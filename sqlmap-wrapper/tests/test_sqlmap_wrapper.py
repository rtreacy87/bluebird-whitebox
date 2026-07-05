"""sqlmap-wrapper tests. Two tiers, mirroring the parent repo's convention
(test_stage4_5_dynamic_verify.py): Tier 1 is deterministic, no network, no
subprocess. Tier 2 (RUN_SQLMAP_TESTS=1) stands up a real disposable BlueBird
replica and runs real `sqlmap` against it.

Run from the bluebird-whitebox repo root:
    PYTHONPATH=sqlmap-wrapper .venv/bin/python -m pytest sqlmap-wrapper/tests/ -v
    RUN_SQLMAP_TESTS=1 PYTHONPATH=sqlmap-wrapper .venv/bin/python -m pytest sqlmap-wrapper/tests/ -v
"""

import json
import os
import shutil
import sqlite3
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from sqlmap_wrapper import cli, db, guard, runner, targets
from sqlmap_wrapper.flags import DangerousFlagError, MissingRequestBodyError, build_args, check_extra_args
from sqlmap_wrapper.import_candidates import InvalidCandidateExportError, import_candidates, validate_candidate, validate_export

REAL_RECON_DB = REPO_ROOT / "data" / "recon.db"

# ---------- fixtures ----------


@pytest.fixture()
def conn(tmp_path):
    return db.connect(str(tmp_path / "wrapper.db"))


def _valid_candidate(**overrides):
    base = {
        "finding_id": 1,
        "endpoint": "/signup",
        "http_method": "POST",
        "vuln_class": "sql_injection",
        "severity": "medium",
        "order_hypothesis": "first_order",
        "target_param_name": "name",
        "param_defaults": {"name": "Probe User", "username": "probeuser_{nonce}"},
        "dbms_hint": "postgresql",
        "evidence": {"path_narrative": "x", "probe_classifications": {"single_quote": "error"}, "sample_log_snippet": "PSQLException"},
        "note": None,
    }
    base.update(overrides)
    return base


def _valid_export(candidates=None):
    return {
        "schema_version": "sqlmap_candidate_v1",
        "generated_at": "2026-01-01T00:00:00+00:00",
        "candidates": candidates if candidates is not None else [_valid_candidate()],
    }


# ---------- guard / targets ----------


def test_guard_rejects_unregistered_target(conn):
    with pytest.raises(guard.UnauthorizedTargetError):
        guard.require_authorized(conn, "10.10.11.5", 80)


def test_guard_rejects_unauthorized_target(conn):
    targets.register_target(conn, "10.10.11.5", 80, authorized=False)
    with pytest.raises(guard.UnauthorizedTargetError):
        guard.require_authorized(conn, "10.10.11.5", 80)


def test_guard_accepts_authorized_target(conn):
    targets.register_target(conn, "10.10.11.5", 80, authorized=True)
    row = guard.require_authorized(conn, "10.10.11.5", 80)
    assert row["host"] == "10.10.11.5"


def test_register_target_duplicate_rejected(conn):
    targets.register_target(conn, "10.10.11.5", 80)
    with pytest.raises(targets.TargetAlreadyRegisteredError):
        targets.register_target(conn, "10.10.11.5", 80)


# ---------- CLI-level regression tests (real bugs found while using the CLI directly) ----------


def test_cli_register_target_duplicate_shows_clean_error_not_traceback(tmp_path, capsys):
    wrapper_db = str(tmp_path / "wrapper.db")
    parser = cli.build_parser()

    args = parser.parse_args(["register-target", "--host", "10.10.11.5", "--port", "80", "--wrapper-db", wrapper_db])
    cli.cmd_register_target(args)

    args = parser.parse_args(["register-target", "--host", "10.10.11.5", "--port", "80", "--wrapper-db", wrapper_db])
    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_register_target(args)
    assert exc_info.value.code == 1
    captured = capsys.readouterr()
    assert "already registered as target_id=1" in captured.err


def test_cli_update_authorization_changes_flag(tmp_path):
    wrapper_db = str(tmp_path / "wrapper.db")
    parser = cli.build_parser()

    cli.cmd_register_target(parser.parse_args(
        ["register-target", "--host", "10.10.11.5", "--port", "80", "--wrapper-db", wrapper_db]
    ))
    cli.cmd_update_authorization(parser.parse_args(
        ["update-authorization", "--host", "10.10.11.5", "--port", "80", "--authorized", "1", "--wrapper-db", wrapper_db]
    ))

    conn = db.connect(wrapper_db)
    row = targets.lookup_target(conn, "10.10.11.5", 80)
    assert row["authorized"] == 1


def test_cli_update_authorization_unregistered_host_fails_cleanly(tmp_path, capsys):
    wrapper_db = str(tmp_path / "wrapper.db")
    parser = cli.build_parser()

    args = parser.parse_args(
        ["update-authorization", "--host", "1.2.3.4", "--port", "80", "--authorized", "1", "--wrapper-db", wrapper_db]
    )
    with pytest.raises(SystemExit) as exc_info:
        cli.cmd_update_authorization(args)
    assert exc_info.value.code == 1
    assert "not registered" in capsys.readouterr().err


def test_update_authorization(conn):
    targets.register_target(conn, "10.10.11.5", 80, authorized=False)
    targets.update_authorization(conn, "10.10.11.5", 80, True)
    row = guard.require_authorized(conn, "10.10.11.5", 80)
    assert row["authorized"] == 1


# ---------- import_candidates validation ----------


def test_validate_candidate_accepts_well_formed():
    assert validate_candidate(_valid_candidate()) == []


def test_validate_candidate_rejects_missing_keys():
    obj = _valid_candidate()
    del obj["dbms_hint"]
    errors = validate_candidate(obj)
    assert any("missing keys" in e for e in errors)


def test_validate_candidate_rejects_bad_http_method():
    errors = validate_candidate(_valid_candidate(http_method="PUT"))
    assert any("http_method" in e for e in errors)


def test_validate_candidate_rejects_bad_order_hypothesis():
    errors = validate_candidate(_valid_candidate(order_hypothesis="third_order"))
    assert any("order_hypothesis" in e for e in errors)


def test_validate_candidate_requires_note_when_param_null():
    errors = validate_candidate(_valid_candidate(target_param_name=None, note=None))
    assert any("note" in e for e in errors)


def test_validate_export_rejects_wrong_schema_version():
    errors = validate_export(_valid_export() | {"schema_version": "sqlmap_candidate_v99"})
    assert any("schema_version" in e for e in errors)


def test_import_candidates_writes_rows(conn, tmp_path):
    export_path = tmp_path / "candidates.json"
    export_path.write_text(json.dumps(_valid_export([_valid_candidate(), _valid_candidate(target_param_name="username")])))

    import_id, count = import_candidates(conn, str(export_path))
    assert count == 2
    rows = conn.execute("SELECT target_param_name, param_defaults_json FROM candidates").fetchall()
    assert {r["target_param_name"] for r in rows} == {"name", "username"}
    assert json.loads(rows[0]["param_defaults_json"])["name"] == "Probe User"


def test_import_candidates_refuses_invalid_export_without_writing(conn, tmp_path):
    export_path = tmp_path / "bad.json"
    export_path.write_text(json.dumps(_valid_export([_valid_candidate(http_method="PUT")])))

    with pytest.raises(InvalidCandidateExportError):
        import_candidates(conn, str(export_path))
    assert conn.execute("SELECT COUNT(*) AS n FROM import_batches").fetchone()["n"] == 0
    assert conn.execute("SELECT COUNT(*) AS n FROM candidates").fetchone()["n"] == 0


# ---------- flags ----------


def test_check_extra_args_rejects_denylisted_flag():
    with pytest.raises(DangerousFlagError):
        check_extra_args(["--os-shell"])


def test_check_extra_args_accepts_safe_flags():
    check_extra_args(["--tamper=space2comment"])  # must not raise


def test_build_args_post_resolves_nonce_and_data(conn):
    targets.register_target(conn, "10.10.11.5", 80, authorized=True)
    target_row = conn.execute("SELECT * FROM targets").fetchone()
    export_path = "n/a"
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES (?, ?, 1)",
        (export_path, "sqlmap_candidate_v1"),
    ).lastrowid
    candidate_id = conn.execute(
        "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, target_param_name, "
        "param_defaults_json, dbms_hint, evidence_json) VALUES (?, 1, '/signup', 'POST', 'name', ?, 'postgresql', '{}')",
        (import_id, json.dumps({"name": "Probe User", "username": "probeuser_{nonce}"})),
    ).lastrowid
    candidate_row = conn.execute("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()

    argv = build_args(candidate_row, target_row, "/tmp/out", nonce="abc123")
    assert "sqlmap" in argv
    assert "-u" in argv and "http://10.10.11.5:80/signup" in argv
    assert "--dbms=postgresql" in argv
    data_arg = argv[argv.index("--data") + 1]
    assert "probeuser_abc123" in data_arg
    assert "{nonce}" not in data_arg


def test_build_args_post_without_param_defaults_raises(conn):
    targets.register_target(conn, "10.10.11.5", 80, authorized=True)
    target_row = conn.execute("SELECT * FROM targets").fetchone()
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    candidate_id = conn.execute(
        "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, target_param_name, evidence_json) "
        "VALUES (?, 1, '/signup', 'POST', 'name', '{}')",
        (import_id,),
    ).lastrowid
    candidate_row = conn.execute("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()

    with pytest.raises(MissingRequestBodyError):
        build_args(candidate_row, target_row, "/tmp/out")


# ---------- runner (dry-run never touches subprocess) ----------


def test_runner_dry_run_never_invokes_subprocess(conn, tmp_path, monkeypatch):
    targets.register_target(conn, "10.10.11.5", 80, authorized=True)
    target_row = conn.execute("SELECT * FROM targets").fetchone()
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    candidate_id = conn.execute(
        "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, target_param_name, "
        "param_defaults_json, dbms_hint, target_id, evidence_json) "
        "VALUES (?, 1, '/signup', 'POST', 'name', ?, 'postgresql', ?, '{}')",
        (import_id, json.dumps({"name": "x"}), target_row["target_id"]),
    ).lastrowid

    def _fail_if_called(*a, **kw):
        raise AssertionError("subprocess.run must not be called for a dry run")

    monkeypatch.setattr(subprocess, "run", _fail_if_called)
    run_id = runner.run(conn, candidate_id, str(tmp_path / "out"), execute=False)
    row = conn.execute("SELECT * FROM sqlmap_runs WHERE run_id = ?", (run_id,)).fetchone()
    assert row["dry_run"] == 1
    assert row["exit_code"] is None


def test_runner_execute_requires_authorized_target(conn, tmp_path):
    targets.register_target(conn, "10.10.11.5", 80, authorized=False)
    target_row = conn.execute("SELECT * FROM targets").fetchone()
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    candidate_id = conn.execute(
        "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, target_param_name, "
        "param_defaults_json, dbms_hint, target_id, evidence_json) "
        "VALUES (?, 1, '/signup', 'POST', 'name', ?, 'postgresql', ?, '{}')",
        (import_id, json.dumps({"name": "x"}), target_row["target_id"]),
    ).lastrowid

    with pytest.raises(guard.UnauthorizedTargetError):
        runner.run(conn, candidate_id, str(tmp_path / "out"), execute=True)


# ---------- schema CHECK enforcement ----------


def test_bad_http_method_rejected(conn):
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, evidence_json) "
            "VALUES (?, 1, '/x', 'PUT', '{}')",
            (import_id,),
        )


def test_bad_order_hypothesis_rejected(conn):
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO candidates (import_id, finding_id_source, endpoint, order_hypothesis, evidence_json) "
            "VALUES (?, 1, '/x', 'third_order', '{}')",
            (import_id,),
        )


def test_bad_wrapper_llm_runs_stage_rejected(conn):
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO wrapper_llm_runs (stage, model_name, prompt_version) VALUES ('bogus_stage', 'm', 'v1')"
        )


def test_bad_sqlmap_result_type_rejected(conn):
    target_row_id = targets.register_target(conn, "10.10.11.5", 80, authorized=True)
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES ('n/a', 'sqlmap_candidate_v1', 1)"
    ).lastrowid
    candidate_id = conn.execute(
        "INSERT INTO candidates (import_id, finding_id_source, endpoint, evidence_json) VALUES (?, 1, '/x', '{}')",
        (import_id,),
    ).lastrowid
    run_id = conn.execute(
        "INSERT INTO sqlmap_runs (candidate_id, target_id, argv_json, output_dir, dry_run) VALUES (?, ?, '[]', '/tmp', 1)",
        (candidate_id, target_row_id),
    ).lastrowid
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute(
            "INSERT INTO sqlmap_results (run_id, result_type) VALUES (?, 'maybe')",
            (run_id,),
        )


# ---------- Tier 2: RUN_SQLMAP_TESTS=1, real container, real recompiled BlueBird, real sqlmap ----------

sqlmap_gate = pytest.mark.skipif(
    os.environ.get("RUN_SQLMAP_TESTS") != "1",
    reason="stands up a real container + recompiled BlueBird + real sqlmap subprocess; set RUN_SQLMAP_TESTS=1 to run",
)


@pytest.fixture()
def real_bluebird_environment(tmp_path):
    """Reuses the parent pipeline's own env_setup strictly as a test
    fixture (never a production dependency of this tool) -- exactly the
    boundary CLAUDE.md documents."""
    from pipeline import db as pipeline_db
    from pipeline.stage4_5_dynamic_verify import env_setup

    source_root = Path("~/BlueBirdSourceCode").expanduser()
    if not source_root.exists():
        pytest.skip(f"BlueBird corpus not found at {source_root}")

    recon_copy = tmp_path / "recon.db"
    shutil.copy(REAL_RECON_DB, recon_copy)
    conn = pipeline_db.connect(str(recon_copy))

    build = env_setup.recompile_source(str(source_root), str(tmp_path / "build"))
    assert build.compiled_ok

    container_name = "sqlmap-wrapper-test-pg"
    env_setup.start_postgres_container(container_name, "bbuser", "bbpassword", "bluebird", port=15442)
    env_setup.wait_for_db_ready(container_name, "bbuser", "bluebird")

    schema_path = tmp_path / "schema.sql"
    schema_path.write_text(
        "CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT, username TEXT UNIQUE, "
        "email TEXT, password TEXT, description TEXT);"
    )
    env_setup.apply_schema(container_name, "bbuser", "bluebird", str(schema_path))

    log_path = str(tmp_path / "app.log")
    started = env_setup.start_app(
        build.build_dir, str(source_root), build.start_class, app_port=18091,
        db_host="localhost", db_port=15442, db_name="bluebird",
        db_user="bbuser", db_password="bbpassword", log_path=log_path,
    )
    env_setup.wait_for_app_ready("localhost", 18091, path="/signup", timeout=60)
    env_id = env_setup.register_environment(
        conn, str(source_root), build.build_dir, build.start_class, "localhost", 18091,
        started["pid"], started["log_path"], container_name, "localhost", 15442,
        "bbuser", "bluebird",
    )

    yield conn, "localhost", 18091
    env_setup.teardown_environment(conn, env_id, log=lambda *_: None)


@sqlmap_gate
def test_real_sqlmap_run_against_known_vulnerable_signup(real_bluebird_environment, tmp_path):
    """Real end-to-end: Stage 6 export -> import -> register+authorize ->
    assign -> real `sqlmap` execution -> real local-LLM interpretation.

    Asserts the run completes and produces a parseable result -- NOT that
    result_type is "confirmed". A real run during development against this
    exact known-vulnerable candidate produced "not_confirmed": sqlmap's
    black-box HTTP-only view can't see the server-log evidence Stage 4.5
    had (see CLAUDE.md's "A real, discovered limitation"). Asserting
    "confirmed" here would be asserting something this tool has already
    demonstrated, for real, not to be reliably true for this sink shape.
    """
    from pipeline.llm.ollama_client import OllamaClient
    from pipeline.stage6_report.exporter import export_report

    recon_conn, host, port = real_bluebird_environment

    export_path = tmp_path / "candidates.json"
    request_templates = {
        "signupPOST": {
            "endpoint": "/signup",
            "http_method": "POST",
            "param_defaults": {
                "name": "Probe User", "username": "probeuser_{nonce}",
                "email": "probe_{nonce}@test.com", "password": "ProbePass123",
                "repeatPassword": "ProbePass123",
            },
        }
    }
    export_report(recon_conn, "sqlmap-json", str(export_path), request_templates=request_templates)

    wrapper_conn = db.connect(str(tmp_path / "wrapper.db"))
    targets.register_target(wrapper_conn, host, port, label="test-fixture", authorized=True)
    import_id, count = import_candidates(wrapper_conn, str(export_path))
    assert count >= 1

    name_candidate = wrapper_conn.execute(
        "SELECT * FROM candidates WHERE target_param_name = 'name'"
    ).fetchone()
    assert name_candidate is not None

    target_row = wrapper_conn.execute("SELECT * FROM targets WHERE host = ? AND port = ?", (host, port)).fetchone()
    runner.assign_target(wrapper_conn, name_candidate["candidate_id"], target_row["target_id"])

    run_id = runner.run(
        wrapper_conn, name_candidate["candidate_id"], str(tmp_path / "sqlmap-out"), execute=True,
    )
    run_row = wrapper_conn.execute("SELECT * FROM sqlmap_runs WHERE run_id = ?", (run_id,)).fetchone()
    assert run_row["dry_run"] == 0
    assert run_row["exit_code"] is not None

    client = OllamaClient(model_name="whiterabbitneo-33b:latest", num_ctx=4096)
    client.verify_model_available()
    from sqlmap_wrapper.interpret import interpret_run
    from sqlmap_wrapper.llm_runner import WrapperLLMRunner

    llm_runner = WrapperLLMRunner(wrapper_conn, client)
    output_text = runner.read_run_output(run_row)
    result_id = interpret_run(wrapper_conn, llm_runner, run_row, output_text)
    result_row = wrapper_conn.execute("SELECT * FROM sqlmap_results WHERE result_id = ?", (result_id,)).fetchone()
    assert result_row["result_type"] in {"confirmed", "not_confirmed", "error", "inconclusive"}
    assert result_row["summary_text"]
