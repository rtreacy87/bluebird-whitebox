"""Stage 1: per-file triage pass (LLM). See prompts/triage_v1.txt.

Orchestration -- which files to visit, how to chunk them, which rows are
missing -- is deterministic Python. The LLM only ever answers the fixed
checklist for a bounded, pre-assembled chunk of source (CLAUDE.md: "the LLM
never decides what to look at next").
"""

import json
import re
from collections import Counter
from pathlib import Path

from pipeline.config import DEFAULT_NUM_CTX
from pipeline.llm.chunking import build_chunks
from pipeline.llm.ollama_client import LLMRunner

PROMPT_VERSION = "triage_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / f"{PROMPT_VERSION}.txt"

_VALID_SINK_TYPES = {"sql_unsafe", "sql_safe", "file_path", "command_exec", "template", "none"}
_VALID_CONFIDENCE = {"high", "medium", "low"}

_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)


def _load_system_prompt():
    return _PROMPT_PATH.read_text()


def _extract_json_array(text):
    """format="json" constrains Ollama's output to *start* with some valid JSON
    value, but observed behavior is the model can keep rambling prose after
    that value closes (e.g. an explanation in a trailing markdown fence) --
    the grammar constraint isn't a stop condition. raw_decode parses just the
    first JSON value and tells us where it ended, ignoring trailing garbage."""
    cleaned = _CODE_FENCE_RE.sub("", text).strip()
    data, _end_index = json.JSONDecoder().raw_decode(cleaned)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list):
                return value
        return [data]
    raise ValueError(f"unexpected JSON shape from triage response: {type(data)}")


def _build_user_prompt(rel_path, chunk):
    method_list = "\n".join(f"- {name}" for name in chunk.method_names)
    return (
        f"File: {rel_path} (chunk {chunk.chunk_index + 1}/{chunk.chunk_total})\n\n"
        f"Methods to review in this chunk (output exactly one JSON object for each):\n"
        f"{method_list}\n\n"
        f"Source:\n```java\n{chunk.text}\n```"
    )


def _resolve_symbol_id(symbol_name, method_symbols_by_name):
    # Deliberately exact-match only -- see schema.sql / CLAUDE.md: fuzzy-matching
    # a hallucinated name to "the closest" real symbol would destroy the
    # hallucination-detection signal symbol_id NULL provides.
    matches = method_symbols_by_name.get(symbol_name)
    if matches and len(matches) == 1:
        return matches[0]
    return None


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in ("true", "yes", "1")
    return None


def triage_file(conn, runner: LLMRunner, file_row, log=print):
    file_id = file_row["file_id"]
    rel_path = file_row["path"]
    source_root = Path(file_row["source_root"])
    source_text = (source_root / rel_path).read_text(encoding="utf-8", errors="replace")

    class_symbol = conn.execute(
        "SELECT symbol_id, name, line_start, line_end FROM symbols "
        "WHERE file_id = ? AND kind = 'class' ORDER BY line_start LIMIT 1",
        (file_id,),
    ).fetchone()
    if class_symbol is None:
        log(f"skip {rel_path}: no class symbol found")
        return {"rows_written": 0, "methods_missing": []}

    field_symbols = conn.execute(
        "SELECT symbol_id, name, line_start, line_end FROM symbols "
        "WHERE file_id = ? AND kind = 'field' ORDER BY line_start",
        (file_id,),
    ).fetchall()
    method_symbols = conn.execute(
        "SELECT symbol_id, name, line_start, line_end FROM symbols "
        "WHERE file_id = ? AND kind IN ('method','constructor') ORDER BY line_start",
        (file_id,),
    ).fetchall()

    if not method_symbols:
        log(f"skip {rel_path}: no methods to triage")
        return {"rows_written": 0, "methods_missing": []}

    method_symbols_by_name = {}
    for m in method_symbols:
        method_symbols_by_name.setdefault(m["name"], []).append(m["symbol_id"])

    chunks = build_chunks(source_text, class_symbol, field_symbols, method_symbols)
    system_prompt = _load_system_prompt()

    rows_written = 0
    covered_symbol_ids = set()

    for chunk in chunks:
        user_prompt = _build_user_prompt(rel_path, chunk)
        # Bound generation length explicitly -- an uncapped call (num_predict
        # unset = generate until the model stops on its own) was observed to
        # ramble for 10+ minutes on this model even for a two-method file.
        # Budget generously per method (each JSON object has several free-text
        # fields) with a floor/ceiling so tiny and large chunks both work.
        num_predict = max(300, min(3000, 250 * len(chunk.method_names)))
        run_id, result = runner.run(
            stage="triage",
            prompt_version=PROMPT_VERSION,
            prompt=user_prompt,
            system=system_prompt,
            file_id=file_id,
            chunk_index=chunk.chunk_index,
            chunk_total=chunk.chunk_total,
            extra_options={
                "format": "json",
                "temperature": 0,
                "num_ctx": DEFAULT_NUM_CTX,
                "num_predict": num_predict,
            },
        )

        try:
            items = _extract_json_array(result.text)
        except (json.JSONDecodeError, ValueError) as e:
            log(f"  chunk {chunk.chunk_index}: FAILED to parse triage JSON ({e}); raw text logged to notes")
            conn.execute(
                "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, confidence, notes) "
                "VALUES (?, NULL, '<unparseable_response>', 'low', ?)",
                (run_id, f"JSON parse failure: {e}. Raw (truncated): {result.text[:500]}"),
            )
            conn.commit()
            continue

        seen_name_counts = Counter()
        for item in items:
            symbol_name = str(item.get("symbol_name", "")).strip()
            if not symbol_name:
                continue
            seen_name_counts[symbol_name] += 1
            symbol_id = _resolve_symbol_id(symbol_name, method_symbols_by_name)
            if symbol_id is not None:
                covered_symbol_ids.add(symbol_id)

            sink_type = item.get("sink_type")
            if sink_type not in _VALID_SINK_TYPES:
                sink_type = None
            confidence = item.get("confidence")
            if confidence not in _VALID_CONFIDENCE:
                confidence = None

            conn.execute(
                "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, has_input, "
                "sink_type, validation_desc, needs_trace, confidence, missing_context, notes) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    run_id,
                    symbol_id,
                    symbol_name,
                    _coerce_bool(item.get("has_input")),
                    sink_type,
                    item.get("validation_desc"),
                    int(bool(_coerce_bool(item.get("needs_trace")))),
                    confidence,
                    item.get("missing_context"),
                    item.get("notes"),
                ),
            )
            rows_written += 1
        conn.commit()

        # Enforce the "a row for every method reviewed" requirement as a hard
        # pipeline invariant rather than trusting prompt compliance: any
        # method this chunk covered that the model silently dropped gets a
        # synthesized low-confidence row so coverage is never silently short.
        # Counted (not set-based) on purpose: overloaded methods/constructors
        # sharing a name (e.g. User(), User(Long, ...)) are multiple distinct
        # symbols the model can only refer to by the same symbol_name -- a
        # set would collapse them and silently under-cover the second one.
        expected_name_counts = Counter(chunk.method_names)
        missed_names = []
        for name, expected_count in expected_name_counts.items():
            shortfall = expected_count - seen_name_counts.get(name, 0)
            for _ in range(max(0, shortfall)):
                # Ambiguous overloads can't be individually attributed to a
                # specific symbol_id by name alone -- leave symbol_id NULL
                # rather than guessing which overload is the missing one.
                symbol_id = _resolve_symbol_id(name, method_symbols_by_name)
                if symbol_id is not None:
                    covered_symbol_ids.add(symbol_id)
                conn.execute(
                    "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, confidence, notes) "
                    "VALUES (?, ?, ?, 'low', ?)",
                    (run_id, symbol_id, name, "LLM omitted this method from its output; row synthesized by pipeline to enforce complete coverage."),
                )
                rows_written += 1
                missed_names.append(name)
        conn.commit()
        if missed_names:
            log(f"  chunk {chunk.chunk_index}: LLM omitted {sorted(missed_names)}, synthesized placeholder rows")

    all_method_ids = {m["symbol_id"] for m in method_symbols}
    methods_missing = sorted(all_method_ids - covered_symbol_ids)
    log(f"{rel_path}: {rows_written} triage rows written across {len(chunks)} chunk(s)")
    return {"rows_written": rows_written, "methods_missing": methods_missing}


def triage_all_files(conn, runner: LLMRunner, source_root, log=print):
    files = conn.execute("SELECT file_id, path FROM files ORDER BY path").fetchall()
    total_rows = 0
    for f in files:
        row = dict(f)
        row["source_root"] = str(source_root)
        result = triage_file(conn, runner, row, log=log)
        total_rows += result["rows_written"]
    return {"files": len(files), "rows_written": total_rows}
