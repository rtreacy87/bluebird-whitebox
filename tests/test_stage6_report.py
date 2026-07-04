"""Stage 6 (findings report export) tests. Tier 1 only: no LLM, no
container, no network -- this stage only ever reads an already-populated DB.
"""

import json
import shutil
from pathlib import Path

import pytest

from pipeline import db
from pipeline.stage6_report.dbms_hints import guess_dbms
from pipeline.stage6_report.exporter import export_report
from pipeline.stage6_report.query import assemble_finding_records
from pipeline.stage6_report.render_markdown import render as render_markdown
from pipeline.stage6_report.render_sqlmap_json import render as render_sqlmap_json

REAL_DB = Path(__file__).resolve().parent.parent / "data" / "recon.db"
pytestmark = pytest.mark.skipif(not REAL_DB.exists(), reason="data/recon.db not present")


@pytest.fixture()
def real_conn(tmp_path):
    """A throwaway copy of the real, already-seeded recon.db -- reflects the
    genuine signupPOST finding/trace/dynamic-probe shape produced by earlier
    stages this session, without ever writing back to the shared DB file."""
    copy_path = tmp_path / "recon.db"
    shutil.copy(REAL_DB, copy_path)
    return db.connect(str(copy_path))


@pytest.fixture()
def empty_conn(tmp_path):
    return db.connect(str(tmp_path / "recon.db"))


# ---------- assemble_finding_records against real seeded data ----------


def test_assemble_finding_records_real_signup_finding(real_conn):
    # data/recon.db currently has three real, human-verified findings:
    # finding_id=1 (/signup, live_debug), finding_id=2 (/find-user,
    # manual_payload -- tests/common_character_bypass_writeup.md), and
    # finding_id=3 (/forgot, manual_payload -- tests/error_based_sqli_writeup.md).
    records = assemble_finding_records(real_conn)
    assert len(records) == 3
    record = next(r for r in records if r["endpoint"] == "/signup")
    assert record["vuln_class"] == "sql_injection"
    assert record["triage"]["symbol_name_raw"] == "signupPOST"
    assert record["trace"]["verdict"] == "exploitable_path"
    assert {p["target_param_name"] for p in record["parameters"]} == {
        "name", "username", "email", "password", "repeatPassword",
    }


def test_only_confirmed_verified_findings_are_included(real_conn):
    real_conn.execute(
        "INSERT INTO findings (endpoint, vuln_class, verified_by_human, status) "
        "VALUES ('/other', 'sql_injection', 1, 'needs_review')"
    )
    real_conn.execute(
        "INSERT INTO findings (endpoint, vuln_class, verified_by_human, status) "
        "VALUES ('/other2', 'sql_injection', 0, 'confirmed')"
    )
    real_conn.commit()
    records = assemble_finding_records(real_conn)
    # The three seeded real findings (/signup, /find-user, /forgot) -- the
    # needs_review and unverified-confirmed rows just inserted must not appear.
    assert {r["endpoint"] for r in records} == {"/signup", "/find-user", "/forgot"}


# ---------- dbms_hints ----------


def test_guess_dbms_resolves_postgresql_for_reactive_params(real_conn):
    records = assemble_finding_records(real_conn)
    reactive = {p["target_param_name"]: p for p in records[0]["parameters"] if p["target_param_name"] in ("name", "username", "email")}
    for param in reactive.values():
        assert guess_dbms(param["sample_log_snippet"]) == "postgresql"


def test_guess_dbms_none_for_no_snippet():
    assert guess_dbms(None) is None
    assert guess_dbms("") is None
    assert guess_dbms("nothing interesting here") is None


# ---------- render_sqlmap_json filtering ----------


def test_sqlmap_json_filters_to_reactive_params_only(real_conn):
    records = assemble_finding_records(real_conn)
    payload = render_sqlmap_json(records, "2026-01-01T00:00:00+00:00")
    assert payload["schema_version"] == "sqlmap_candidate_v1"

    signup_candidates = [c for c in payload["candidates"] if c["finding_id"] == 1]
    param_names = {c["target_param_name"] for c in signup_candidates}
    assert param_names == {"name", "username", "email"}
    for candidate in signup_candidates:
        assert candidate["dbms_hint"] == "postgresql"
        assert candidate["note"] is None
        assert "single_quote" in candidate["evidence"]["probe_classifications"]

    # finding_id=2 (/find-user) has only uniformly-`rejected` Stage 4.5
    # evidence (an auth-gap artifact, see common_character_bypass_writeup.md)
    # -- Stage 6 must not fabricate a target_param_name/dbms_hint for it.
    find_user_candidates = [c for c in payload["candidates"] if c["finding_id"] == 2]
    assert len(find_user_candidates) == 1
    assert find_user_candidates[0]["target_param_name"] is None
    assert find_user_candidates[0]["note"] is not None


def test_sqlmap_json_includes_param_defaults_when_request_templates_given(real_conn):
    request_templates = {
        "signupPOST": {
            "endpoint": "/signup",
            "http_method": "POST",
            "param_defaults": {"name": "Probe User", "username": "probeuser_{nonce}"},
        }
    }
    records = assemble_finding_records(real_conn)
    payload = render_sqlmap_json(records, "2026-01-01T00:00:00+00:00", request_templates=request_templates)
    signup_candidates = [c for c in payload["candidates"] if c["finding_id"] == 1]
    assert signup_candidates
    for candidate in signup_candidates:
        assert candidate["param_defaults"] == {"name": "Probe User", "username": "probeuser_{nonce}"}

    # /find-user's triaged method is 'findUser', not in request_templates above --
    # its candidate must not silently inherit signupPOST's param_defaults.
    find_user_candidates = [c for c in payload["candidates"] if c["finding_id"] == 2]
    assert find_user_candidates
    for candidate in find_user_candidates:
        assert candidate["param_defaults"] is None


def test_sqlmap_json_param_defaults_null_without_request_templates(real_conn):
    records = assemble_finding_records(real_conn)
    payload = render_sqlmap_json(records, "2026-01-01T00:00:00+00:00")
    for candidate in payload["candidates"]:
        assert candidate["param_defaults"] is None


def test_sqlmap_json_null_fallback_when_no_dynamic_evidence(empty_conn):
    empty_conn.execute(
        "INSERT INTO findings (endpoint, vuln_class, verified_by_human, status, verification_method) "
        "VALUES ('/manual', 'blind_sqli', 1, 'confirmed', 'manual_payload')"
    )
    empty_conn.commit()
    records = assemble_finding_records(empty_conn)
    payload = render_sqlmap_json(records, "2026-01-01T00:00:00+00:00")
    assert len(payload["candidates"]) == 1
    candidate = payload["candidates"][0]
    assert candidate["target_param_name"] is None
    assert candidate["note"] is not None
    assert "manually" in candidate["note"]


def test_sqlmap_json_null_fallback_when_all_params_non_reactive(empty_conn):
    """Real dynamic-probe evidence exists, but nothing reacted -- should
    still surface a candidate (with a distinct note), not vanish silently."""
    run_id = empty_conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('trace', 'm', 'v1')"
    ).lastrowid
    triage_run_id = empty_conn.execute(
        "INSERT INTO llm_runs (stage, model_name, prompt_version) VALUES ('triage', 'm', 'v1')"
    ).lastrowid
    triage_result_id = empty_conn.execute(
        "INSERT INTO triage_results (run_id, symbol_name_raw, sink_type) VALUES (?, 'x', 'sql_unsafe')",
        (triage_run_id,),
    ).lastrowid
    queue_id = empty_conn.execute(
        "INSERT INTO trace_queue (origin_triage_result_id, status) VALUES (?, 'done')", (triage_result_id,)
    ).lastrowid
    trace_id = empty_conn.execute(
        "INSERT INTO trace_results (queue_id, run_id, verdict) VALUES (?, ?, 'exploitable_path')",
        (queue_id, run_id),
    ).lastrowid
    empty_conn.execute(
        "INSERT INTO target_environments (source_root, build_dir, start_class, app_port, app_log_path) "
        "VALUES ('/x', '/y', 'com.Foo', 8080, '/x/app.log')"
    )
    batch_id = empty_conn.execute(
        "INSERT INTO dynamic_probe_batches (source_trace_id, target_param_name, env_id, endpoint, http_method, order_hypothesis) "
        "VALUES (?, 'safeparam', 1, '/x', 'POST', 'first_order')",
        (trace_id,),
    ).lastrowid
    for probe in ("baseline", "single_quote", "double_quote", "backslash"):
        empty_conn.execute(
            "INSERT INTO dynamic_probe_results (batch_id, probe_name, input_value, classification) "
            "VALUES (?, ?, 'v', 'passthrough_unmodified')",
            (batch_id, probe),
        )
    empty_conn.execute(
        "INSERT INTO findings (source_trace_id, endpoint, vuln_class, verified_by_human, status) "
        "VALUES (?, '/x', 'sql_injection', 1, 'confirmed')",
        (trace_id,),
    )
    empty_conn.commit()

    records = assemble_finding_records(empty_conn)
    payload = render_sqlmap_json(records, "2026-01-01T00:00:00+00:00")
    assert len(payload["candidates"]) == 1
    candidate = payload["candidates"][0]
    assert candidate["target_param_name"] is None
    assert "no parameter showed a reactive" in candidate["note"]


# ---------- render_markdown ----------


def test_markdown_report_contains_expected_sections(real_conn):
    records = assemble_finding_records(real_conn)
    text = render_markdown(records)
    assert "/signup" in text
    assert "sql_injection" in text
    assert "| name | passthrough_unmodified | error |" in text
    assert "| password | rejected | rejected | rejected | rejected |" in text


def test_markdown_report_empty_findings():
    assert "No confirmed" in render_markdown([])


# ---------- exporter (writes to disk + report_exports provenance row) ----------


def test_export_report_writes_file_and_provenance_row(real_conn, tmp_path):
    out_path = tmp_path / "report.md"
    export_id, finding_count = export_report(real_conn, "markdown", str(out_path))
    assert out_path.exists()
    assert finding_count == 3
    row = real_conn.execute("SELECT * FROM report_exports WHERE export_id = ?", (export_id,)).fetchone()
    assert row["format"] == "markdown"
    assert row["finding_count"] == 3


def test_export_report_sqlmap_json_is_valid_json(real_conn, tmp_path):
    out_path = tmp_path / "candidates.json"
    export_report(real_conn, "sqlmap-json", str(out_path))
    payload = json.loads(out_path.read_text())
    assert payload["schema_version"] == "sqlmap_candidate_v1"
    # 3 reactive signupPOST candidates (name/username/email) + 1 null-fallback
    # candidate for /find-user + 1 null-fallback candidate for /forgot
    # (see test_sqlmap_json_filters_to_reactive_params_only).
    assert len(payload["candidates"]) == 5


def test_export_report_bad_format_raises(real_conn, tmp_path):
    with pytest.raises(ValueError):
        export_report(real_conn, "yaml", str(tmp_path / "out.yaml"))
