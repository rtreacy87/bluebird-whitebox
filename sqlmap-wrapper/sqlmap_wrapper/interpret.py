"""Local-LLM interpretation of a completed sqlmap run's raw output --
mirrors bluebird-whitebox's stage4_5_dynamic_verify/interpret.py exactly:
bounded evidence in, defensive JSON parsing, a versioned prompt, full
provenance. This is the ONE place in this tool that touches a model at all
-- the raw sqlmap invocation and its exit code need no model whatsoever;
this only wrangles the resulting log text into clean relational rows (see
CLAUDE.md's "penetration testing as data wrangling" framing).
"""

import json
import re
from pathlib import Path

from sqlmap_wrapper.llm_runner import WrapperLLMRunner

PROMPT_VERSION = "sqlmap_interpret_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent / "prompts" / f"{PROMPT_VERSION}.txt"

_VALID_RESULT_TYPES = {"confirmed", "not_confirmed", "error", "inconclusive"}
_CODE_FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.MULTILINE)

# sqlmap logs can run long; bound how much we ever hand to the model rather
# than the full unbounded verbose log (mirrors this project's "never trust
# an unbounded context" discipline -- see CLAUDE.md's "Local Model Runtime").
_MAX_LOG_CHARS = 6000


def _load_system_prompt():
    return _PROMPT_PATH.read_text()


def _extract_json_object(text):
    cleaned = _CODE_FENCE_RE.sub("", text).strip()
    data, _end = json.JSONDecoder().raw_decode(cleaned)
    if isinstance(data, dict):
        return data
    if isinstance(data, list) and data:
        return data[0]
    raise ValueError(f"unexpected JSON shape from sqlmap_interpret response: {type(data)}")


def _tail(text, max_chars):
    """The most decision-relevant sqlmap output is near the end (the final
    verdict/summary lines), not the beginning -- take the tail, not the head."""
    if text is None:
        return ""
    return text[-max_chars:]


def interpret_run(conn, runner: WrapperLLMRunner, run_row, raw_output_text, log=print):
    """run_row: sqlite3.Row from sqlmap_runs. raw_output_text: the log/output
    read from disk by the caller (this module does no file I/O itself).
    Writes one sqlmap_results row and returns its result_id."""
    user_prompt = f"sqlmap output (tail, {_MAX_LOG_CHARS} chars max):\n{_tail(raw_output_text, _MAX_LOG_CHARS)}"

    run_id, result = runner.run(
        stage="sqlmap_interpret",
        prompt_version=PROMPT_VERSION,
        prompt=user_prompt,
        system=_load_system_prompt(),
        extra_options={"format": "json", "temperature": 0, "num_predict": 300},
    )

    try:
        item = _extract_json_object(result.text)
        result_type = item.get("result_type")
        summary_text = item.get("summary_text", "")
        if result_type not in _VALID_RESULT_TYPES:
            raise ValueError(f"invalid result_type {result_type!r}")
    except (json.JSONDecodeError, ValueError) as e:
        log(f"  run_id={run_row['run_id']}: FAILED to parse sqlmap_interpret response ({e})")
        result_type = "inconclusive"
        summary_text = f"interpretation parse failure: {e}. Raw (truncated): {result.text[:500]}"

    cursor = conn.execute(
        "INSERT INTO sqlmap_results (run_id, result_type, summary_text, raw_output_path, interpreted_by_run_id) "
        "VALUES (?, ?, ?, ?, ?)",
        (run_row["run_id"], result_type, summary_text, run_row["output_dir"], run_id),
    )
    conn.commit()
    return cursor.lastrowid
