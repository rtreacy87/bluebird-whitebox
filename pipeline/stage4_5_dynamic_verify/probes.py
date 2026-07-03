"""Stage 4.5's local-only-guarded HTTP probe runner.

Fires the fixed, versioned probe set (never LLM-chosen -- see CLAUDE.md's
Dynamic Verification section) at one candidate request parameter, observes
HTTP status, the target app's own log output, and the resulting database
row, then hands the evidence to classify.classify_probe().
"""

import subprocess
import time
from pathlib import Path

import requests
from requests.exceptions import RequestException

from pipeline.stage4_5_dynamic_verify import guard
from pipeline.stage4_5_dynamic_verify.classify import classify_probe

FIXED_PROBE_SET = ("baseline", "single_quote", "double_quote", "backslash")


def probe_value(nonce: str, probe_name: str) -> str:
    """Deterministic per-probe value -- re-running a batch with the same
    nonce (derived from batch_id) reproduces identical probe values, never
    randomized, so results are reproducible and auditable."""
    if probe_name == "baseline":
        return f"{nonce}_baseline"
    if probe_name == "single_quote":
        return f"{nonce}_sq'x"
    if probe_name == "double_quote":
        return f'{nonce}_dq"x'
    if probe_name == "backslash":
        return f"{nonce}_bs\\x"
    raise ValueError(f"unknown probe_name {probe_name!r}, must be one of {FIXED_PROBE_SET}")


def fire_probe(base_url, endpoint, http_method, target_param, value, fixed_params, timeout=10) -> dict:
    guard.validate_local_target(base_url)
    url = f"{base_url}{endpoint}"
    params = dict(fixed_params)
    params[target_param] = value

    start = time.monotonic()
    try:
        if http_method == "POST":
            resp = requests.post(url, data=params, timeout=timeout)
        else:
            resp = requests.get(url, params=params, timeout=timeout)
        return {
            "http_status": resp.status_code,
            "response_text": resp.text[:2000],
            "elapsed_ms": (time.monotonic() - start) * 1000,
        }
    except RequestException as e:
        return {
            "http_status": None,
            "response_text": f"request failed: {e}",
            "elapsed_ms": (time.monotonic() - start) * 1000,
        }


def _log_line_count(path) -> int:
    if not path or not Path(path).exists():
        return 0
    return len(Path(path).read_text(errors="replace").splitlines())


def _log_lines_since(path, start_line, max_lines=500) -> str:
    """Everything logged strictly after start_line -- capturing "the last N
    lines" instead was tried first and found to truncate real evidence: a
    single Spring Security stack trace routinely runs 60-100+ lines, easily
    longer than a fixed tail window, which silently pushed the actual
    BadSqlGrammarException/PSQLException marker lines out of a 50-line tail
    entirely (confirmed against a real single_quote probe against BlueBird
    -- the exception was in the file, just past where a fixed tail looked).
    Capped at max_lines so a runaway log still returns a bounded snippet."""
    if not path or not Path(path).exists():
        return ""
    lines = Path(path).read_text(errors="replace").splitlines()
    return "\n".join(lines[start_line:start_line + max_lines])


def _pg_escape_literal(value: str) -> str:
    return value.replace("'", "''")


def query_db_row(db_container_name, db_user, db_name, verify_table, verify_column, nonce):
    """Shells out via `podman exec <container> psql` (matching env_setup.py's
    subprocess-based Postgres access, no new native DB-driver dependency).
    verify_table/verify_column are human-supplied via request-templates.json,
    not attacker-controlled -- same trust level as env_setup.apply_schema's
    schema file, so direct interpolation into the query is acceptable here
    (psql -c has no parameter-binding mechanism to use instead). nonce is
    our own generated probe value, escaped defensively regardless."""
    if not verify_table or not verify_column or not db_container_name:
        return None
    escaped_nonce = _pg_escape_literal(nonce)
    sql = (
        f"SELECT {verify_column} FROM {verify_table} "
        f"WHERE {verify_column} LIKE '%{escaped_nonce}%' ORDER BY 1 DESC LIMIT 1;"
    )
    result = subprocess.run(
        ["podman", "exec", db_container_name, "psql", "-U", db_user, "-d", db_name, "-t", "-A", "-c", sql],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    output = result.stdout.strip()
    return output if output else None


def create_batch(conn, source_trace_id, input_source_id, env_id, endpoint,
                  http_method, target_param_name, order_hypothesis,
                  verify_table=None, verify_column=None) -> int:
    """Idempotent: a batch already exists for (source_trace_id,
    target_param_name) returns its existing batch_id rather than inserting
    a duplicate."""
    existing = conn.execute(
        "SELECT batch_id FROM dynamic_probe_batches WHERE source_trace_id = ? AND target_param_name = ?",
        (source_trace_id, target_param_name),
    ).fetchone()
    if existing:
        return existing["batch_id"]

    cur = conn.execute(
        "INSERT INTO dynamic_probe_batches (source_trace_id, input_source_id, target_param_name, "
        "env_id, endpoint, http_method, order_hypothesis, verify_table, verify_column) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (source_trace_id, input_source_id, target_param_name, env_id, endpoint,
         http_method, order_hypothesis, verify_table, verify_column),
    )
    conn.commit()
    return cur.lastrowid


def _resolve_fixed_params(fixed_params, nonce):
    """fixed_params values may contain a "{nonce}" placeholder (e.g.
    request-templates.json declaring "username": "probe_{nonce}") for any
    sibling field the target enforces uniqueness on. Without this, every
    probe in a battery after the first would share the same
    username/email and get short-circuited by the target's own
    already-taken-username check before ever reaching the flagged sink --
    exactly what was observed testing this against real BlueBird: only the
    first (baseline) probe's row was ever inserted, the other three all hit
    signupPOST's duplicate-username branch. Fields with no "{nonce}" in
    them are left as-is (e.g. a constant password is fine to repeat)."""
    return {
        key: (value.format(nonce=nonce) if isinstance(value, str) else value)
        for key, value in fixed_params.items()
    }


def run_battery(conn, env_row, batch_row, fixed_params, app_log_path, log=print) -> list:
    """For each of FIXED_PROBE_SET: fire it, tail the app log, look up the
    resulting DB row, classify, insert into dynamic_probe_results. Returns
    the list of inserted probe_ids. Each probe gets its own nonce (not just
    each batch) specifically so sibling fields templated with "{nonce}"
    don't collide across probes within the same battery."""
    base_url = f"http://{env_row['app_host']}:{env_row['app_port']}"
    probe_ids = []

    for probe_name in FIXED_PROBE_SET:
        nonce = f"b{batch_row['batch_id']}_{probe_name}"
        value = probe_value(nonce, probe_name)
        resolved_fixed_params = _resolve_fixed_params(fixed_params, nonce)
        log_start = _log_line_count(app_log_path)
        result = fire_probe(
            base_url, batch_row["endpoint"], batch_row["http_method"],
            batch_row["target_param_name"], value, resolved_fixed_params,
        )
        app_log_tail = _log_lines_since(app_log_path, log_start)
        db_row_value = query_db_row(
            env_row["db_container_name"], env_row["db_user"], env_row["db_name"],
            batch_row["verify_table"], batch_row["verify_column"], nonce,
        )
        classification = classify_probe(result["http_status"], app_log_tail, db_row_value, value)

        cur = conn.execute(
            "INSERT INTO dynamic_probe_results (batch_id, probe_name, input_value, http_status, "
            "response_snippet, app_log_snippet, db_row_snippet, classification) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (batch_row["batch_id"], probe_name, value, result["http_status"],
             result["response_text"], app_log_tail, db_row_value, classification),
        )
        conn.commit()
        probe_ids.append(cur.lastrowid)
        log(f"  {probe_name}: http_status={result['http_status']} -> {classification}")

    return probe_ids
