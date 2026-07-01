"""Stage 4: LLM deep-trace pass over pending trace_queue items.
See prompts/trace_v1.txt. Only ever shown the context Stage 3's graph walk
assembled (CLAUDE.md: "must only reason over the context explicitly
assembled and provided by the Stage 3 graph walk").
"""

import json
import re
from pathlib import Path

from pipeline.config import DEFAULT_NUM_CTX
from pipeline.llm.ollama_client import LLMRunner

PROMPT_VERSION = "trace_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / f"{PROMPT_VERSION}.txt"

_VALID_VERDICTS = {"exploitable_path", "safe_path", "insufficient_context", "inconclusive"}
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _load_system_prompt():
    return _PROMPT_PATH.read_text()


def _extract_json_object(text):
    cleaned = _CODE_FENCE_RE.sub("", text).strip()
    data, _end = json.JSONDecoder().raw_decode(cleaned)
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        return data[0]
    raise ValueError(f"unexpected JSON shape from trace response: {type(data)}")


def _slice_lines(lines, line_start, line_end):
    if line_start is None or line_end is None:
        return ""
    return "\n".join(lines[line_start - 1 : line_end])


def _build_user_prompt(origin_row, context_symbols, source_text, target_variable):
    lines = source_text.split("\n")
    method_blocks = []
    for sym in context_symbols:
        body = _slice_lines(lines, sym["line_start"], sym["line_end"])
        method_blocks.append(
            f"--- symbol_id={sym['symbol_id']} name={sym['name']} ---\n```java\n{body}\n```"
        )
    return (
        f"ORIGIN (flagged by Stage 1 triage): {origin_row['symbol_name_raw']} "
        f"(symbol_id={origin_row['symbol_id']})\n"
        f"Stage 1 sink_type: {origin_row['sink_type']}\n"
        f"Stage 1 validation_desc: {origin_row['validation_desc'] or ''}\n"
        f"target_variable (pipeline-identified cross-method property, empty if direct): "
        f"{target_variable or ''}\n\n"
        f"CONTEXT METHODS (only these symbol_ids are valid for evidence_symbol_ids):\n\n"
        + "\n\n".join(method_blocks)
    )


def trace_item(conn, runner: LLMRunner, queue_row, source_root, log=print):
    """queue_row: sqlite3.Row from trace_queue (must include queue_id,
    origin_triage_result_id, target_symbol_id, target_variable,
    assembled_context_symbol_ids, status).
    Returns {"trace_id": int, "verdict": str, "queue_status": str} or
    {"skipped": reason} for rows with no target_symbol_id (already blocked
    at enqueue time -- nothing for Stage 4 to do).
    """
    if queue_row["target_symbol_id"] is None:
        return {"skipped": "no target_symbol_id (blocked at enqueue)"}

    context_ids = json.loads(queue_row["assembled_context_symbol_ids"] or "[]")
    if not context_ids:
        return {"skipped": "empty assembled_context_symbol_ids"}

    origin_row = conn.execute(
        "SELECT result_id, symbol_id, symbol_name_raw, sink_type, validation_desc "
        "FROM triage_results WHERE result_id = ?",
        (queue_row["origin_triage_result_id"],),
    ).fetchone()

    placeholders = ",".join("?" for _ in context_ids)
    context_symbols = conn.execute(
        f"SELECT symbol_id, name, file_id, line_start, line_end FROM symbols "
        f"WHERE symbol_id IN ({placeholders}) ORDER BY line_start",
        context_ids,
    ).fetchall()
    file_id = context_symbols[0]["file_id"]
    file_row = conn.execute("SELECT path FROM files WHERE file_id = ?", (file_id,)).fetchone()
    source_text = (Path(source_root) / file_row["path"]).read_text(encoding="utf-8", errors="replace")

    user_prompt = _build_user_prompt(origin_row, context_symbols, source_text, queue_row["target_variable"])
    num_predict = max(400, min(2000, 300 * len(context_symbols)))

    run_id, result = runner.run(
        stage="trace",
        prompt_version=PROMPT_VERSION,
        prompt=user_prompt,
        system=_load_system_prompt(),
        file_id=file_id,
        extra_options={
            "format": "json",
            "temperature": 0,
            "num_ctx": DEFAULT_NUM_CTX,
            "num_predict": num_predict,
        },
    )

    try:
        item = _extract_json_object(result.text)
        verdict = item.get("verdict")
        if verdict not in _VALID_VERDICTS:
            verdict = "inconclusive"
        path_narrative = item.get("path_narrative")
        raw_evidence = item.get("evidence_symbol_ids") or []
        # Defensive: evidence_symbol_ids must be a subset of what was shown --
        # never trust the model to have obeyed this on its own.
        valid_ids = {s["symbol_id"] for s in context_symbols}
        evidence_ids = [i for i in raw_evidence if isinstance(i, int) and i in valid_ids]
    except (json.JSONDecodeError, ValueError) as e:
        verdict = "inconclusive"
        path_narrative = f"JSON parse failure: {e}. Raw (truncated): {result.text[:500]}"
        evidence_ids = []
        log(f"  queue_id={queue_row['queue_id']}: FAILED to parse trace JSON ({e})")

    cur = conn.execute(
        "INSERT INTO trace_results (queue_id, run_id, verdict, path_narrative, evidence_symbol_ids) "
        "VALUES (?, ?, ?, ?, ?)",
        (queue_row["queue_id"], run_id, verdict, path_narrative, json.dumps(evidence_ids)),
    )
    trace_id = cur.lastrowid

    # insufficient_context here can only mean "needs data outside intra-file
    # scope" -- Stage 3 already assembled everything intra-file discoverable.
    new_status = "blocked" if verdict == "insufficient_context" else "done"
    conn.execute("UPDATE trace_queue SET status = ? WHERE queue_id = ?", (new_status, queue_row["queue_id"]))
    conn.commit()
    return {"trace_id": trace_id, "verdict": verdict, "queue_status": new_status}


def trace_all_pending(conn, runner: LLMRunner, source_root, log=print):
    rows = conn.execute("SELECT * FROM trace_queue WHERE status = 'pending' ORDER BY queue_id").fetchall()
    stats = {
        "items": 0,
        "skipped": 0,
        "exploitable_path": 0,
        "safe_path": 0,
        "insufficient_context": 0,
        "inconclusive": 0,
    }
    for row in rows:
        result = trace_item(conn, runner, row, source_root, log=log)
        if "skipped" in result:
            stats["skipped"] += 1
            continue
        stats["items"] += 1
        stats[result["verdict"]] += 1
        log(f"queue_id={row['queue_id']}: {result['verdict']} -> trace_queue.status={result['queue_status']}")
    return stats
