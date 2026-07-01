"""Stage 3+4 regression gate against the BlueBird corpus.

Two tiers:
1. Deterministic tier (no LLM) -- verifies Stage 3's builder discovers the
   profile/editProfilePOST same-file name-matching link using REAL Stage 0
   parse output, with synthetic (hand-inserted) triage_results rows that
   mirror already-verified real triage output for this corpus (see
   EXPECTED_FINDINGS.md) -- this avoids an Ollama dependency for testing
   pure deterministic logic.
2. RUN_LLM_TESTS=1 tier -- runs the full pipeline (Stage 0-4) and asserts
   Stage 4 verdicts exploitable_path for the three known vulnerabilities.
"""

import json
import os
from pathlib import Path

import pytest

from pipeline import db
from pipeline.llm.ollama_client import OllamaClient, LLMRunner
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage1_triage.triage import triage_all_files
from pipeline.stage2_audit.audit import audit_all_files
from pipeline.stage3_trace.builder import enqueue_trace_targets
from pipeline.stage4_deep_trace.deep_trace import trace_all_pending

CORPUS_ROOT = Path("~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird").expanduser()
MODEL_NAME = "whiterabbitneo-33b:latest"
KNOWN_VULN_ENDPOINTS = ["findUser", "forgotPOST", "profile"]

pytestmark = pytest.mark.skipif(not CORPUS_ROOT.exists(), reason=f"BlueBird corpus not found at {CORPUS_ROOT}")


# ---------- Tier 1: deterministic, no Ollama ----------


@pytest.fixture()
def indexed_conn(tmp_path):
    """Real Stage 0 parse of the corpus (deterministic, no LLM) plus
    synthetic llm_runs + triage_results rows mirroring real, already-verified
    triage output for profile/editProfilePOST (see EXPECTED_FINDINGS.md)."""
    conn = db.connect(str(tmp_path / "recon.db"))
    index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)

    run_id = conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('triage', 'synthetic-fixture', 'triage_v1', NULL)"
    ).lastrowid

    def _symbol_id(name):
        return conn.execute("SELECT symbol_id FROM symbols WHERE name = ?", (name,)).fetchone()["symbol_id"]

    for name in ("profile", "editProfilePOST"):
        conn.execute(
            "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, sink_type, needs_trace, confidence) "
            "VALUES (?, ?, ?, 'sql_unsafe', 0, 'high')",
            (run_id, _symbol_id(name), name),
        )
    conn.commit()
    return conn


def test_profile_editprofile_link_discovered_by_name_matching(indexed_conn):
    enqueue_trace_targets(indexed_conn)
    row = indexed_conn.execute(
        "SELECT tq.assembled_context_symbol_ids, tq.target_variable FROM trace_queue tq "
        "JOIN triage_results tr ON tr.result_id = tq.origin_triage_result_id "
        "WHERE tr.symbol_name_raw = 'profile'"
    ).fetchone()
    assert row is not None
    context_ids = json.loads(row["assembled_context_symbol_ids"])
    edit_profile_id = indexed_conn.execute(
        "SELECT symbol_id FROM symbols WHERE name = 'editProfilePOST'"
    ).fetchone()["symbol_id"]
    assert edit_profile_id in context_ids, (
        f"editProfilePOST (symbol_id={edit_profile_id}) not discovered in profile's "
        f"assembled_context_symbol_ids={context_ids}"
    )
    assert row["target_variable"] == "email"


def test_null_symbol_triage_row_enqueues_blocked_not_pending(indexed_conn):
    run_id = indexed_conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id) "
        "VALUES ('triage', 'synthetic-fixture', 'triage_v1', NULL)"
    ).lastrowid
    indexed_conn.execute(
        "INSERT INTO triage_results (run_id, symbol_id, symbol_name_raw, sink_type, confidence) "
        "VALUES (?, NULL, 'User', 'sql_unsafe', 'medium')",
        (run_id,),
    )
    indexed_conn.commit()
    enqueue_trace_targets(indexed_conn)
    row = indexed_conn.execute(
        "SELECT tq.status, tq.target_symbol_id FROM trace_queue tq "
        "JOIN triage_results tr ON tr.result_id = tq.origin_triage_result_id "
        "WHERE tr.symbol_name_raw = 'User' AND tr.symbol_id IS NULL"
    ).fetchone()
    assert row is not None
    assert row["status"] == "blocked"
    assert row["target_symbol_id"] is None


def test_enqueue_is_idempotent(indexed_conn):
    enqueue_trace_targets(indexed_conn)
    count_first = indexed_conn.execute("SELECT COUNT(*) AS n FROM trace_queue").fetchone()["n"]
    enqueue_trace_targets(indexed_conn)
    count_second = indexed_conn.execute("SELECT COUNT(*) AS n FROM trace_queue").fetchone()["n"]
    assert count_first == count_second


# ---------- Tier 2: RUN_LLM_TESTS=1, real Ollama, full pipeline ----------

llm_gate = pytest.mark.skipif(
    os.environ.get("RUN_LLM_TESTS") != "1",
    reason="drives real Ollama calls; set RUN_LLM_TESTS=1 to run",
)


@pytest.fixture(scope="module")
def traced_conn(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("stage34") / "recon.db"
    conn = db.connect(str(db_path))
    index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)

    client = OllamaClient(model_name=MODEL_NAME, num_ctx=12288)
    client.verify_model_available()
    runner = LLMRunner(conn, client)

    triage_all_files(conn, runner, CORPUS_ROOT, log=lambda *_: None)
    audit_all_files(conn, runner, log=lambda *_: None)
    enqueue_trace_targets(conn, log=lambda *_: None)
    trace_all_pending(conn, runner, CORPUS_ROOT, log=lambda *_: None)
    return conn


@llm_gate
@pytest.mark.parametrize("method_name", KNOWN_VULN_ENDPOINTS)
def test_known_vuln_traced_as_exploitable(traced_conn, method_name):
    rows = traced_conn.execute(
        "SELECT tr2.verdict FROM trace_results tr2 "
        "JOIN trace_queue tq ON tq.queue_id = tr2.queue_id "
        "JOIN triage_results tr1 ON tr1.result_id = tq.origin_triage_result_id "
        "WHERE tr1.symbol_name_raw = ?",
        (method_name,),
    ).fetchall()
    assert rows, f"no trace_results row at all for {method_name}"
    assert any(r["verdict"] == "exploitable_path" for r in rows), (
        f"{method_name} was not traced as exploitable_path: {[dict(r) for r in rows]}"
    )


@llm_gate
def test_no_pending_or_in_progress_left_after_full_pass(traced_conn):
    stuck = traced_conn.execute(
        "SELECT COUNT(*) AS n FROM trace_queue WHERE status IN ('pending', 'in_progress')"
    ).fetchone()["n"]
    assert stuck == 0
