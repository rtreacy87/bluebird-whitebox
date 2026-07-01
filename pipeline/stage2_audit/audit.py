"""Stage 2: adversarial audit pass (LLM). See prompts/audit_v1.txt.

Two distinct kinds of checking happen here, deliberately kept separate:

1. Structural existence-matching (matched / hallucinated_row / missing_from_table
   / ambiguous) is computed in plain Python directly from Stage 0's symbols
   table -- this must be exactly correct, and an LLM re-deriving it from
   scratch could itself hallucinate, which would defeat the point.
2. Adversarial semantic review (does triage's claim look consistent with
   Stage 0's deterministic facts?) is a genuinely separate LLM call
   (CLAUDE.md: "must be a separate invocation from triage") that is only ever
   shown already-extracted Stage 0 facts and the triage claim -- never the raw
   file source -- so it compares against ground truth instead of re-deriving
   its own reading of the file (CLAUDE.md: "not against the model's own
   re-derivation of the file's contents").
"""

import json
import re
from collections import defaultdict
from pathlib import Path

from pipeline.config import DEFAULT_NUM_CTX
from pipeline.llm.ollama_client import LLMRunner

PROMPT_VERSION = "audit_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / f"{PROMPT_VERSION}.txt"

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# Keyword heuristic only, to surface possibly-sink-relevant callee names to
# the audit LLM as a Stage 0 "fact" -- not a sink classification itself
# (that judgment call stays with triage/audit's semantic review).
_SINK_KEYWORD_RE = re.compile(
    r"query|update|execute|statement|runtime\.exec|processbuilder|"
    r"\bfile\b|files\.|filewriter|fileoutputstream",
    re.IGNORECASE,
)


def _load_system_prompt():
    return _PROMPT_PATH.read_text()


def _extract_json_array(text):
    cleaned = _CODE_FENCE_RE.sub("", text).strip()
    data, _end = json.JSONDecoder().raw_decode(cleaned)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                return value
        return [data]
    raise ValueError(f"unexpected JSON shape from audit response: {type(data)}")


def _structural_status(triage_row, method_name_counts):
    symbol_id = triage_row["symbol_id"]
    name = triage_row["symbol_name_raw"]
    if symbol_id is not None:
        return "matched"
    if name in method_name_counts and method_name_counts[name] > 1:
        return "ambiguous"
    return "hallucinated_row"


def audit_file(conn, runner: LLMRunner, file_id, triage_run_id, log=print):
    method_symbols = conn.execute(
        "SELECT symbol_id, name, signature, is_entrypoint FROM symbols "
        "WHERE file_id = ? AND kind IN ('method','constructor') ORDER BY line_start",
        (file_id,),
    ).fetchall()
    method_name_counts = defaultdict(int)
    for m in method_symbols:
        method_name_counts[m["name"]] += 1

    input_source_symbol_ids = {
        row["symbol_id"]
        for row in conn.execute(
            "SELECT DISTINCT symbol_id FROM input_sources WHERE symbol_id IN "
            "(SELECT symbol_id FROM symbols WHERE file_id = ?)",
            (file_id,),
        ).fetchall()
    }

    sink_flagged_callees = defaultdict(list)
    for row in conn.execute(
        "SELECT caller_symbol_id, callee_raw_name FROM call_edges WHERE caller_symbol_id IN "
        "(SELECT symbol_id FROM symbols WHERE file_id = ?)",
        (file_id,),
    ).fetchall():
        if _SINK_KEYWORD_RE.search(row["callee_raw_name"] or ""):
            sink_flagged_callees[row["caller_symbol_id"]].append(row["callee_raw_name"])

    triage_rows = conn.execute(
        "SELECT result_id, symbol_id, symbol_name_raw, has_input, sink_type, "
        "validation_desc, needs_trace, confidence FROM triage_results WHERE run_id = ?",
        (triage_run_id,),
    ).fetchall()

    # missing_from_table: Stage 0 methods with zero triage rows resolved to them
    covered_symbol_ids = {r["symbol_id"] for r in triage_rows if r["symbol_id"] is not None}
    missing_symbols = [m for m in method_symbols if m["symbol_id"] not in covered_symbol_ids]

    audit_run_id, matched_concerns = None, {}
    matched_rows = [r for r in triage_rows if r["symbol_id"] is not None]

    if matched_rows:
        facts_lines = []
        for r in matched_rows:
            sid = r["symbol_id"]
            has_input_fact = sid in input_source_symbol_ids
            sink_callees = sink_flagged_callees.get(sid, [])
            facts_lines.append(
                f"- {r['symbol_name_raw']}: STAGE0 FACTS: has_request_input={has_input_fact}, "
                f"sink_flagged_callees={sink_callees or 'none'} | "
                f"TRIAGE CLAIM: has_input={bool(r['has_input'])}, sink_type={r['sink_type']}, "
                f"needs_trace={bool(r['needs_trace'])}, confidence={r['confidence']}, "
                f"validation_desc={r['validation_desc'] or ''!r}"
            )
        user_prompt = "Methods:\n" + "\n".join(facts_lines)

        num_predict = max(200, min(2500, 120 * len(matched_rows)))
        audit_run_id, result = runner.run(
            stage="audit",
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
            items = _extract_json_array(result.text)
            for item in items:
                name = str(item.get("symbol_name", "")).strip()
                if name:
                    matched_concerns[name] = str(item.get("concern", "")).strip()
        except (json.JSONDecodeError, ValueError) as e:
            log(f"  audit JSON parse failure for file_id={file_id}: {e}")

    if audit_run_id is None:
        # Nothing matched to adversarially review, but we still need an
        # llm_runs row so the hallucinated/missing rows below have valid
        # provenance -- record a zero-work audit run rather than skip it.
        audit_run_id, _ = runner.run(
            stage="audit",
            prompt_version=PROMPT_VERSION,
            prompt="No matched triage rows to review for this file.",
            system=_load_system_prompt(),
            file_id=file_id,
            extra_options={"num_predict": 8},
        )

    rows_written = 0
    for r in triage_rows:
        status = _structural_status(r, method_name_counts)
        notes = matched_concerns.get(r["symbol_name_raw"], "") if status == "matched" else (
            "symbol_name_raw does not match any Stage 0 symbol in this file"
            if status == "hallucinated_row"
            else "symbol_name_raw matches multiple same-named Stage 0 symbols (overload); cannot attribute to one"
        )
        conn.execute(
            "INSERT INTO audit_results (run_id, audited_run_id, symbol_id, status, notes) "
            "VALUES (?, ?, ?, ?, ?)",
            (audit_run_id, triage_run_id, r["symbol_id"], status, notes),
        )
        rows_written += 1

    for m in missing_symbols:
        conn.execute(
            "INSERT INTO audit_results (run_id, audited_run_id, symbol_id, status, notes) "
            "VALUES (?, ?, ?, 'missing_from_table', ?)",
            (audit_run_id, triage_run_id, m["symbol_id"], "Stage 0 symbol has no triage_results row referencing it."),
        )
        rows_written += 1

    conn.commit()
    return {"rows_written": rows_written, "concerns_flagged": sum(1 for v in matched_concerns.values() if v and v.lower() != "none")}


def audit_all_files(conn, runner: LLMRunner, log=print):
    # One audit pass per (file, triage run) -- always the most recent triage
    # run for that file, matching how triage_all_files writes one run per file.
    files = conn.execute(
        "SELECT DISTINCT r.file_id, f.path, MAX(r.run_id) AS run_id "
        "FROM llm_runs r JOIN files f ON f.file_id = r.file_id "
        "WHERE r.stage = 'triage' GROUP BY r.file_id ORDER BY f.path"
    ).fetchall()
    total_rows = 0
    total_concerns = 0
    for row in files:
        result = audit_file(conn, runner, row["file_id"], row["run_id"], log=log)
        log(f"{row['path']}: {result['rows_written']} audit rows, {result['concerns_flagged']} concerns flagged")
        total_rows += result["rows_written"]
        total_concerns += result["concerns_flagged"]
    return {"files": len(files), "rows_written": total_rows, "concerns_flagged": total_concerns}
