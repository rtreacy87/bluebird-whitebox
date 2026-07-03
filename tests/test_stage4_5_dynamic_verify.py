"""Stage 4.5 (dynamic verification) regression gate.

Two tiers:
1. Deterministic tier (no network, no container, no Ollama) -- guard,
   classify, probe_value, create_batch idempotency, and candidates.pending_candidates
   against REAL Stage 0 parse output with synthetic trace_results/trace_queue
   rows mirroring already-verified real Stage 3/4 output for this corpus.
2. RUN_DYNAMIC_TESTS=1 tier -- stands up a real disposable BlueBird replica
   (container + recompiled app) and fires real probes at it, asserting the
   single_quote probe reproduces the real BadSqlGrammarException/
   PSQLException captured in tests/searching_for_strings_live_debug_writeup.md.
"""

import json
import os
import sqlite3
import time
from pathlib import Path

import pytest

from pipeline import db
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage4_5_dynamic_verify import env_setup, guard, orchestrator
from pipeline.stage4_5_dynamic_verify.classify import classify_probe, order_hypothesis_for
from pipeline.stage4_5_dynamic_verify.candidates import pending_candidates
from pipeline.stage4_5_dynamic_verify.interpret import interpret_ambiguous
from pipeline.stage4_5_dynamic_verify.probes import FIXED_PROBE_SET, create_batch, probe_value

CORPUS_ROOT = Path("~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird").expanduser()
SOURCE_ROOT = Path("~/BlueBirdSourceCode").expanduser()

pytestmark = pytest.mark.skipif(not CORPUS_ROOT.exists(), reason=f"BlueBird corpus not found at {CORPUS_ROOT}")


# ---------- Tier 1: deterministic, no network/container/Ollama ----------


def test_guard_rejects_non_local_targets():
    for bad in ("evil.com", "http://8.8.8.8/x", "attacker.example.com", "10.0.0.5"):
        with pytest.raises(guard.RemoteTargetError):
            guard.validate_local_target(bad)


def test_guard_accepts_local_targets():
    for good in ("localhost", "127.0.0.1", "http://localhost:8080", "::1", "http://127.0.0.1:5432"):
        guard.validate_local_target(good)  # must not raise


@pytest.mark.parametrize(
    "http_status,app_log_tail,db_row_value,input_value,expected",
    [
        (500, "Caused by: org.postgresql.util.PSQLException: Unterminated string literal", None, "x'y", "error"),
        (200, "", "nonce_baseline", "nonce_baseline", "passthrough_unmodified"),
        (200, "", "$2a$12$abcxyz", "AnotherPass2", "transformed"),
        (200, "", None, "x", "rejected"),
        (None, "", None, "x", "rejected"),
        (500, "OutOfMemoryError: unrelated crash", None, "x", "ambiguous"),
        # tiebreak: an error marker present alongside a would-be passthrough row -- error wins
        (500, "PSQLException: broke", "has_x'y_in_it", "x'y", "error"),
    ],
)
def test_classify_probe_branches(http_status, app_log_tail, db_row_value, input_value, expected):
    assert classify_probe(http_status, app_log_tail, db_row_value, input_value) == expected


def test_order_hypothesis_for():
    assert order_hypothesis_for(None) == "first_order"
    assert order_hypothesis_for("email") == "second_order"


def test_probe_value_contains_expected_metacharacter():
    values = {name: probe_value("nonce1", name) for name in FIXED_PROBE_SET}
    assert "'" not in values["baseline"]
    assert "'" in values["single_quote"]
    assert '"' in values["double_quote"]
    assert "\\" in values["backslash"]
    assert len(set(values.values())) == 4  # all distinct


# ---------- Tier 1: schema CHECK enforcement ----------


@pytest.fixture()
def empty_conn(tmp_path):
    return db.connect(str(tmp_path / "recon.db"))


def test_dynamic_interpret_is_valid_llm_runs_stage(empty_conn):
    empty_conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('dynamic_interpret', 'm', 'v1')"
    )
    empty_conn.commit()  # must not raise


def test_bad_llm_runs_stage_rejected(empty_conn):
    with pytest.raises(sqlite3.IntegrityError):
        empty_conn.execute(
            "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('bogus_stage', 'm', 'v1')"
        )


def _insert_minimal_trace_chain(conn) -> int:
    """A real, minimal llm_runs -> triage_results -> trace_queue ->
    trace_results chain (symbol_id/target_symbol_id left NULL, both
    columns are nullable) so dynamic_probe_batches' NOT NULL FK to
    trace_results(trace_id) can be satisfied without needing real
    symbols/files rows too. Returns the resulting trace_id."""
    triage_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('triage', 'm', 'v1')"
    ).lastrowid
    trace_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('trace', 'm', 'v1')"
    ).lastrowid
    triage_result_id = conn.execute(
        "INSERT INTO triage_results (run_id, symbol_name_raw, sink_type) VALUES (?, 'x', 'sql_unsafe')",
        (triage_run_id,),
    ).lastrowid
    queue_id = conn.execute(
        "INSERT INTO trace_queue (origin_triage_result_id, status) VALUES (?, 'done')",
        (triage_result_id,),
    ).lastrowid
    trace_id = conn.execute(
        "INSERT INTO trace_results (queue_id, run_id, verdict) VALUES (?, ?, 'exploitable_path')",
        (queue_id, trace_run_id),
    ).lastrowid
    conn.commit()
    return trace_id


def test_bad_probe_name_rejected(empty_conn):
    trace_id = _insert_minimal_trace_chain(empty_conn)
    empty_conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    empty_conn.execute(
        "INSERT INTO dynamic_probe_batches (source_trace_id, target_param_name, env_id, endpoint, http_method, order_hypothesis) "
        "VALUES (?, 'name', 1, '/signup', 'POST', 'first_order')",
        (trace_id,),
    )
    with pytest.raises(sqlite3.IntegrityError):
        empty_conn.execute(
            "INSERT INTO dynamic_probe_results (batch_id, probe_name, input_value) VALUES (1, 'union_probe', 'x')"
        )


def test_bad_http_method_rejected(empty_conn):
    trace_id = _insert_minimal_trace_chain(empty_conn)
    empty_conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    with pytest.raises(sqlite3.IntegrityError):
        empty_conn.execute(
            "INSERT INTO dynamic_probe_batches (source_trace_id, target_param_name, env_id, endpoint, http_method, order_hypothesis) "
            "VALUES (?, 'name', 1, '/signup', 'PUT', 'first_order')",
            (trace_id,),
        )


# ---------- Tier 1: candidates.pending_candidates + create_batch, against real Stage 0 ----------


@pytest.fixture()
def traced_fixture_conn(tmp_path):
    """Real Stage 0 parse of the corpus plus synthetic triage_results/
    trace_queue/trace_results rows mirroring already-verified real Stage 1-4
    output for signupPOST (first-order) and profile (second-order, linked to
    editProfilePOST via target_variable='email') -- see EXPECTED_FINDINGS.md
    and tests/searching_for_strings_stage3_4_writeup.md."""
    conn = db.connect(str(tmp_path / "recon.db"))
    index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)

    def _symbol_id(name):
        return conn.execute("SELECT symbol_id FROM symbols WHERE name = ?", (name,)).fetchone()["symbol_id"]

    triage_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('triage', 'synthetic-fixture', 'triage_v1', NULL)"
    ).lastrowid
    trace_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('trace', 'synthetic-fixture', 'trace_v1', NULL)"
    ).lastrowid

    def _add_exploitable(symbol_name, target_variable, context_names):
        symbol_id = _symbol_id(symbol_name)
        triage_result_id = conn.execute(
            "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, sink_type, needs_trace, confidence) "
            "VALUES (?, ?, ?, 'sql_unsafe', 0, 'high')",
            (triage_run_id, symbol_id, symbol_name),
        ).lastrowid
        context_ids = [_symbol_id(n) for n in context_names]
        queue_id = conn.execute(
            "INSERT INTO trace_queue (origin_triage_result_id, target_symbol_id, target_variable, status, "
            "assembled_context_symbol_ids) VALUES (?, ?, ?, 'done', ?)",
            (triage_result_id, symbol_id, target_variable, json.dumps(context_ids)),
        ).lastrowid
        conn.execute(
            "INSERT INTO trace_results (queue_id, run_id, verdict, path_narrative, evidence_symbol_ids) "
            "VALUES (?, ?, 'exploitable_path', 'synthetic', ?)",
            (queue_id, trace_run_id, json.dumps(context_ids)),
        )
        return symbol_id

    signup_id = _add_exploitable("signupPOST", None, ["signupPOST"])
    _add_exploitable("profile", "email", ["profile", "editProfilePOST"])
    conn.commit()
    return conn, signup_id


def test_pending_candidates_first_order(traced_fixture_conn):
    conn, signup_id = traced_fixture_conn
    candidates = pending_candidates(conn)
    signup_candidates = {c["param_name"] for c in candidates if c["symbol_name"] == "signupPOST"}
    assert signup_candidates == {"name", "username", "email", "password", "repeatPassword"}
    assert all(c["order_hypothesis"] == "first_order" for c in candidates if c["symbol_name"] == "signupPOST")


def test_pending_candidates_second_order(traced_fixture_conn):
    conn, _ = traced_fixture_conn
    candidates = pending_candidates(conn)
    profile_second_order = [
        c for c in candidates if c["symbol_name"] == "profile" and c["order_hypothesis"] == "second_order"
    ]
    assert len(profile_second_order) == 1
    assert profile_second_order[0]["param_name"] == "email"
    assert profile_second_order[0]["input_source_id"] is None


def test_pending_candidates_excludes_already_batched(traced_fixture_conn):
    conn, signup_id = traced_fixture_conn
    trace_id = conn.execute(
        "SELECT trace_id FROM trace_results tr JOIN trace_queue tq ON tq.queue_id = tr.queue_id "
        "WHERE tq.target_symbol_id = ?",
        (signup_id,),
    ).fetchone()["trace_id"]

    conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    conn.commit()
    create_batch(conn, trace_id, None, 1, "/signup", "POST", "name", "first_order")

    candidates = pending_candidates(conn)
    signup_names = {c["param_name"] for c in candidates if c["symbol_name"] == "signupPOST"}
    assert "name" not in signup_names
    assert "username" in signup_names  # not yet batched, still present


def test_create_batch_idempotent(traced_fixture_conn):
    conn, signup_id = traced_fixture_conn
    trace_id = conn.execute(
        "SELECT trace_id FROM trace_results tr JOIN trace_queue tq ON tq.queue_id = tr.queue_id "
        "WHERE tq.target_symbol_id = ?",
        (signup_id,),
    ).fetchone()["trace_id"]
    conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    conn.commit()

    batch_id_1 = create_batch(conn, trace_id, None, 1, "/signup", "POST", "name", "first_order")
    batch_id_2 = create_batch(conn, trace_id, None, 1, "/signup", "POST", "name", "first_order")
    assert batch_id_1 == batch_id_2
    count = conn.execute(
        "SELECT COUNT(*) AS n FROM dynamic_probe_batches WHERE source_trace_id = ? AND target_param_name = 'name'",
        (trace_id,),
    ).fetchone()["n"]
    assert count == 1


# ---------- Tier 1: interpret_ambiguous with a stubbed LLMRunner ----------


class _FakeResult:
    def __init__(self, text):
        self.text = text
        self.prompt_eval_count = 10
        self.eval_count = 5


class _FakeRunner:
    """Stands in for LLMRunner -- returns a canned response instead of
    calling Ollama, so interpret.py's parsing/provenance logic can be
    tested without a live model."""

    def __init__(self, conn, response_text):
        self.conn = conn
        self.response_text = response_text

    def run(self, stage, prompt_version, prompt, system=None, file_id=None,
            chunk_index=0, chunk_total=1, extra_options=None):
        cur = self.conn.execute(
            "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id, chunk_index, chunk_total) "
            "VALUES (?, 'fake-model', ?, ?, ?, ?)",
            (stage, prompt_version, file_id, chunk_index, chunk_total),
        )
        self.conn.commit()
        return cur.lastrowid, _FakeResult(self.response_text)


@pytest.fixture()
def ambiguous_probe_row(empty_conn):
    trace_id = _insert_minimal_trace_chain(empty_conn)
    empty_conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    empty_conn.execute(
        "INSERT INTO dynamic_probe_batches (source_trace_id, target_param_name, env_id, endpoint, http_method, order_hypothesis) "
        "VALUES (?, 'test', 1, '/signup', 'POST', 'first_order')",
        (trace_id,),
    )
    cur = empty_conn.execute(
        "INSERT INTO dynamic_probe_results (batch_id, probe_name, input_value, http_status, "
        "response_snippet, app_log_snippet, db_row_snippet, classification) "
        "VALUES (1, 'baseline', 'x', 500, 'err', 'OutOfMemoryError', NULL, 'ambiguous')"
    )
    empty_conn.commit()
    return empty_conn, cur.lastrowid


def test_interpret_ambiguous_success(ambiguous_probe_row):
    conn, probe_id = ambiguous_probe_row
    runner = _FakeRunner(conn, '{"classification": "error", "reasoning": "OOM is a real fault."}')
    probe_row = conn.execute("SELECT * FROM dynamic_probe_results WHERE probe_id = ?", (probe_id,)).fetchone()

    label = interpret_ambiguous(conn, runner, probe_row)
    assert label == "error"

    updated = conn.execute("SELECT classification, interpreted_by_run_id, notes FROM dynamic_probe_results WHERE probe_id = ?", (probe_id,)).fetchone()
    assert updated["classification"] == "error"
    assert updated["interpreted_by_run_id"] is not None
    assert "OOM" in updated["notes"]


def test_interpret_ambiguous_malformed_json_falls_back(ambiguous_probe_row):
    conn, probe_id = ambiguous_probe_row
    runner = _FakeRunner(conn, "not valid json at all")
    probe_row = conn.execute("SELECT * FROM dynamic_probe_results WHERE probe_id = ?", (probe_id,)).fetchone()

    label = interpret_ambiguous(conn, runner, probe_row)
    assert label == "ambiguous"

    updated = conn.execute("SELECT classification, interpreted_by_run_id, notes FROM dynamic_probe_results WHERE probe_id = ?", (probe_id,)).fetchone()
    assert updated["classification"] == "ambiguous"
    assert updated["interpreted_by_run_id"] is not None  # attempt still recorded
    assert "parse failure" in updated["notes"]


# ---------- Tier 2: RUN_DYNAMIC_TESTS=1, real container, real recompiled BlueBird ----------

dynamic_gate = pytest.mark.skipif(
    os.environ.get("RUN_DYNAMIC_TESTS") != "1",
    reason="stands up a real container + recompiled BlueBird process; set RUN_DYNAMIC_TESTS=1 to run",
)


@dynamic_gate
def test_recompile_source_produces_class(tmp_path):
    build = env_setup.recompile_source(str(SOURCE_ROOT), str(tmp_path / "build"))
    assert build.compiled_ok
    assert Path(build.build_dir, "com/bmdyy/bluebird/BlueBirdApplication.class").exists()


@pytest.fixture()
def live_environment(tmp_path):
    conn = db.connect(str(tmp_path / "recon.db"))
    index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)

    build = env_setup.recompile_source(str(SOURCE_ROOT), str(tmp_path / "build"))
    assert build.compiled_ok

    container_name = "wb-test-dynamic-pg"
    env_setup.start_postgres_container(container_name, "bbuser", "bbpassword", "bluebird", port=15432)
    env_setup.wait_for_db_ready(container_name, "bbuser", "bluebird")

    schema_path = tmp_path / "schema.sql"
    schema_path.write_text(
        "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, "
        "email TEXT, password TEXT, description TEXT);"
    )
    env_setup.apply_schema(container_name, "bbuser", "bluebird", str(schema_path))

    log_path = str(tmp_path / "app.log")
    started = env_setup.start_app(
        build.build_dir, str(SOURCE_ROOT), build.start_class, app_port=18080,
        db_host="localhost", db_port=15432, db_name="bluebird",
        db_user="bbuser", db_password="bbpassword", log_path=log_path,
    )
    env_setup.wait_for_app_ready("localhost", 18080, path="/signup", timeout=60)

    env_id = env_setup.register_environment(
        conn, str(SOURCE_ROOT), build.build_dir, build.start_class, "localhost", 18080,
        started["pid"], started["log_path"], container_name, "localhost", 15432,
        "bbuser", "bluebird",
    )

    yield conn, env_id
    env_setup.teardown_environment(conn, env_id, log=lambda *_: None)


@dynamic_gate
def test_signup_name_single_quote_reproduces_real_error(live_environment):
    conn, env_id = live_environment
    signup_id = conn.execute("SELECT symbol_id FROM symbols WHERE name = 'signupPOST'").fetchone()["symbol_id"]

    triage_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('triage', 'synthetic-fixture', 'triage_v1', NULL)"
    ).lastrowid
    trace_run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('trace', 'synthetic-fixture', 'trace_v1', NULL)"
    ).lastrowid
    triage_result_id = conn.execute(
        "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, sink_type, needs_trace, confidence) "
        "VALUES (?, ?, 'signupPOST', 'sql_unsafe', 0, 'high')",
        (triage_run_id, signup_id),
    ).lastrowid
    queue_id = conn.execute(
        "INSERT INTO trace_queue (origin_triage_result_id, target_symbol_id, status, assembled_context_symbol_ids) "
        "VALUES (?, ?, 'done', ?)",
        (triage_result_id, signup_id, json.dumps([signup_id])),
    ).lastrowid
    conn.execute(
        "INSERT INTO trace_results (queue_id, run_id, verdict, path_narrative, evidence_symbol_ids) "
        "VALUES (?, ?, 'exploitable_path', 'synthetic', ?)",
        (queue_id, trace_run_id, json.dumps([signup_id])),
    )
    conn.commit()

    templates = {
        "signupPOST": {
            "endpoint": "/signup",
            "http_method": "POST",
            "param_defaults": {
                "name": "Probe User",
                "username": "probeuser_{nonce}",
                "email": "probe_{nonce}@test.com",
                "password": "ProbePass123",
                "repeatPassword": "ProbePass123",
            },
            "verify_table": "users",
        }
    }
    stats = orchestrator.run_all_pending(conn, env_id, templates, runner=None, log=lambda *_: None)
    assert stats["error"] >= 1
    assert stats["passthrough_unmodified"] >= 1

    single_quote_row = conn.execute(
        "SELECT classification, app_log_snippet FROM dynamic_probe_results WHERE probe_name = 'single_quote' "
        "AND batch_id IN (SELECT batch_id FROM dynamic_probe_batches WHERE target_param_name = 'name')"
    ).fetchone()
    assert single_quote_row["classification"] == "error"
    assert "PSQLException" in single_quote_row["app_log_snippet"]

    baseline_row = conn.execute(
        "SELECT classification FROM dynamic_probe_results WHERE probe_name = 'baseline' "
        "AND batch_id IN (SELECT batch_id FROM dynamic_probe_batches WHERE target_param_name = 'name')"
    ).fetchone()
    assert baseline_row["classification"] == "passthrough_unmodified"
