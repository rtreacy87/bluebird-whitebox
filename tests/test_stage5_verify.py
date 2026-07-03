"""Stage 5 write-side tests: pipeline.stage5_verify.logger.log_finding.

No LLM, no BlueBird corpus dependency -- log_finding only ever writes to an
already-initialized schema, so these run against a fresh empty DB.
"""

import sqlite3

import pytest

from pipeline import db
from pipeline.stage5_verify.logger import InvalidFindingError, log_finding


@pytest.fixture()
def conn(tmp_path):
    return db.connect(str(tmp_path / "recon.db"))


def test_log_finding_writes_expected_row(conn):
    finding_id = log_finding(
        conn,
        endpoint="/signup",
        vuln_class="sql_injection",
        verification_method="live_debug",
        status="confirmed",
        severity="medium",
        notes="name/username/email pass through unescaped; passwordHash is BCrypt output.",
    )
    row = conn.execute("SELECT * FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    assert row["endpoint"] == "/signup"
    assert row["verification_method"] == "live_debug"
    assert row["status"] == "confirmed"
    assert row["verified_by_human"] == 1
    assert row["reviewed_at"] is not None


def test_verified_by_human_defaults_true(conn):
    finding_id = log_finding(conn, verification_method="query_log", status="needs_review")
    row = conn.execute("SELECT verified_by_human FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    assert row["verified_by_human"] == 1


def test_not_verified_flag_honored(conn):
    finding_id = log_finding(
        conn, verification_method="manual_payload", status="needs_review", verified_by_human=False
    )
    row = conn.execute("SELECT verified_by_human FROM findings WHERE finding_id = ?", (finding_id,)).fetchone()
    assert row["verified_by_human"] == 0


def test_invalid_verification_method_rejected_before_insert(conn):
    with pytest.raises(InvalidFindingError):
        log_finding(conn, verification_method="just_looked_at_it")
    assert conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 0


def test_invalid_status_rejected_before_insert(conn):
    with pytest.raises(InvalidFindingError):
        log_finding(conn, verification_method="live_debug", status="probably_fine")
    assert conn.execute("SELECT COUNT(*) AS n FROM findings").fetchone()["n"] == 0


def test_source_trace_id_must_exist(conn):
    with pytest.raises(InvalidFindingError):
        log_finding(conn, verification_method="live_debug", source_trace_id=999)


def test_schema_check_itself_rejects_bad_verification_method(conn):
    """Regression test for a real bug: CHECK(col IN ('a','b', NULL)) doesn't
    actually reject bad non-null values in SQLite -- a NULL literal inside
    an IN(...) list makes the whole expression evaluate to NULL/unknown
    (not FALSE) for any value that isn't 'a' or 'b', and a CHECK constraint
    treats NULL as satisfied. log_finding()'s own Python-level validation
    happens to catch this before ever reaching the DB (see the test above),
    which is exactly why this went unnoticed -- but the schema's own CHECK
    must be correct independently, since it's the last line of defense
    against anything else that might someday write to `findings` directly.
    The fix is `CHECK(col IS NULL OR col IN (...))`, not a NULL literal
    inside the IN(...) list."""
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO findings (verification_method, status) VALUES ('bogus_method', 'confirmed')"
        )


def test_source_triage_result_id_must_exist(conn):
    with pytest.raises(InvalidFindingError):
        log_finding(conn, verification_method="live_debug", source_triage_result_id=999)
