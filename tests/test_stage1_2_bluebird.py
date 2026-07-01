"""Stage 1+2 regression gate against the BlueBird corpus (CLAUDE.md build order
step 2): "all three known BlueBird vulnerabilities (/find-user, /forgot,
/profile/{id}) must be surfaced by the pipeline before other work proceeds."

This drives real Ollama calls against whiterabbitneo-33b and takes on the
order of 15 minutes end to end, so it's opt-in via RUN_LLM_TESTS=1 rather than
running on every `pytest` invocation -- but it must be run (and pass) before
any Stage 3+ work per CLAUDE.md, and after any Stage 0-2 change.
"""

import os
from pathlib import Path

import pytest

from pipeline import db
from pipeline.llm.ollama_client import OllamaClient, LLMRunner
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage1_triage.triage import triage_all_files
from pipeline.stage2_audit.audit import audit_all_files

CORPUS_ROOT = Path("~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird").expanduser()
MODEL_NAME = "whiterabbitneo-33b:latest"

pytestmark = [
    pytest.mark.skipif(not CORPUS_ROOT.exists(), reason=f"BlueBird corpus not found at {CORPUS_ROOT}"),
    pytest.mark.skipif(
        os.environ.get("RUN_LLM_TESTS") != "1",
        reason="drives real Ollama calls (~15 min); set RUN_LLM_TESTS=1 to run",
    ),
]

KNOWN_VULN_ENDPOINTS = ["findUser", "forgotPOST", "profile"]


@pytest.fixture(scope="module")
def pipeline_conn(tmp_path_factory):
    db_path = tmp_path_factory.mktemp("stage12") / "recon.db"
    conn = db.connect(str(db_path))
    index_source_tree(conn, CORPUS_ROOT, log=lambda *_: None)

    client = OllamaClient(model_name=MODEL_NAME, num_ctx=12288)
    client.verify_model_available()
    runner = LLMRunner(conn, client)

    triage_all_files(conn, runner, CORPUS_ROOT, log=lambda *_: None)
    audit_all_files(conn, runner, log=lambda *_: None)
    return conn


@pytest.mark.parametrize("method_name", KNOWN_VULN_ENDPOINTS)
def test_known_vuln_surfaced_as_unsafe_sink(pipeline_conn, method_name):
    rows = pipeline_conn.execute(
        "SELECT sink_type, confidence FROM triage_results WHERE symbol_name_raw = ?",
        (method_name,),
    ).fetchall()
    assert rows, f"no triage row at all for {method_name}"
    assert any(r["sink_type"] == "sql_unsafe" for r in rows), (
        f"{method_name} was not flagged sql_unsafe by any triage row: {[dict(r) for r in rows]}"
    )


def test_every_stage0_method_has_a_triage_row_or_documented_ambiguity(pipeline_conn):
    """Structural completeness per CLAUDE.md Testing section: a deterministic
    parser-based method count compared against triage coverage, not a manual read."""
    uncovered = pipeline_conn.execute(
        "SELECT s.symbol_id, s.name FROM symbols s "
        "JOIN files f ON f.file_id = s.file_id "
        "LEFT JOIN triage_results tr ON tr.symbol_id = s.symbol_id "
        "WHERE s.kind IN ('method','constructor') AND tr.result_id IS NULL"
    ).fetchall()
    # The only acceptable uncovered symbols are overloaded methods/constructors
    # sharing a name with another symbol in the same file (ambiguous by name,
    # see pipeline/stage1_triage/triage.py) -- anything else is a real gap.
    for row in uncovered:
        count = pipeline_conn.execute(
            "SELECT COUNT(*) AS n FROM symbols WHERE name = ? AND symbol_id IN "
            "(SELECT symbol_id FROM symbols s2 JOIN files f2 ON f2.file_id = s2.file_id "
            "WHERE f2.file_id = (SELECT file_id FROM symbols WHERE symbol_id = ?))",
            (row["name"], row["symbol_id"]),
        ).fetchone()["n"]
        assert count > 1, f"{row['name']} (symbol_id={row['symbol_id']}) has no triage row and isn't an overload"


def test_audit_covers_every_triage_run(pipeline_conn):
    triage_runs = {r["run_id"] for r in pipeline_conn.execute("SELECT run_id FROM llm_runs WHERE stage='triage'")}
    audited_runs = {r["audited_run_id"] for r in pipeline_conn.execute("SELECT DISTINCT audited_run_id FROM audit_results")}
    assert triage_runs == audited_runs


def test_no_hallucinated_rows_among_known_vuln_endpoints(pipeline_conn):
    for method_name in KNOWN_VULN_ENDPOINTS:
        rows = pipeline_conn.execute(
            "SELECT ar.status FROM audit_results ar "
            "JOIN symbols s ON s.symbol_id = ar.symbol_id "
            "WHERE s.name = ?",
            (method_name,),
        ).fetchall()
        assert rows and all(r["status"] == "matched" for r in rows)
