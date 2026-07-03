"""Stage 4.5's local-LLM interpretation pass -- only ever invoked for probe
results the deterministic rules in classify.py couldn't confidently label.
See prompts/dynamic_interpret_v1.txt and CLAUDE.md's "Why the interpretation
pass, specifically, must be local-model-only": the raw probe-firing and
classification rules need no model at all; this is the one place in Stage
4.5 that does, and it goes through the same LLMRunner/Ollama path -- and the
same defensive JSON parsing -- every other LLM-derived stage already uses.
"""

import json
import re
from pathlib import Path

from pipeline.config import DEFAULT_NUM_CTX
from pipeline.llm.ollama_client import LLMRunner

PROMPT_VERSION = "dynamic_interpret_v1"
_PROMPT_PATH = Path(__file__).resolve().parent.parent.parent / "prompts" / f"{PROMPT_VERSION}.txt"

_VALID_LABELS = {"error", "passthrough_unmodified", "transformed", "rejected"}
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
    raise ValueError(f"unexpected JSON shape from dynamic_interpret response: {type(data)}")


def _build_user_prompt(probe_row):
    return (
        f"input_value: {probe_row['input_value']!r}\n"
        f"http_status: {probe_row['http_status']}\n"
        f"response_snippet: {(probe_row['response_snippet'] or '')[:1000]!r}\n"
        f"app_log_snippet: {(probe_row['app_log_snippet'] or '')[:2000]!r}\n"
        f"db_row_snippet: {probe_row['db_row_snippet']!r}\n"
    )


def interpret_ambiguous(conn, runner: LLMRunner, probe_row, log=print) -> str:
    """probe_row: sqlite3.Row from dynamic_probe_results, classification
    must be 'ambiguous'. Returns the resulting classification (unchanged if
    the model's response couldn't be parsed into a valid label)."""
    user_prompt = _build_user_prompt(probe_row)

    run_id, result = runner.run(
        stage="dynamic_interpret",
        prompt_version=PROMPT_VERSION,
        prompt=user_prompt,
        system=_load_system_prompt(),
        extra_options={
            "format": "json",
            "temperature": 0,
            "num_ctx": DEFAULT_NUM_CTX,
            "num_predict": 300,
        },
    )

    try:
        item = _extract_json_object(result.text)
        label = item.get("classification")
        reasoning = item.get("reasoning", "")
        if label not in _VALID_LABELS:
            raise ValueError(f"invalid classification {label!r}")
    except (json.JSONDecodeError, ValueError) as e:
        log(f"  probe_id={probe_row['probe_id']}: FAILED to parse dynamic_interpret response ({e})")
        conn.execute(
            "UPDATE dynamic_probe_results SET interpreted_by_run_id = ?, "
            "notes = ? WHERE probe_id = ?",
            (run_id, f"interpretation parse failure: {e}. Raw (truncated): {result.text[:500]}", probe_row["probe_id"]),
        )
        conn.commit()
        return "ambiguous"

    conn.execute(
        "UPDATE dynamic_probe_results SET classification = ?, interpreted_by_run_id = ?, "
        "notes = ? WHERE probe_id = ?",
        (label, run_id, reasoning, probe_row["probe_id"]),
    )
    conn.commit()
    return label
