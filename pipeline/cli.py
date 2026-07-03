"""CLI entrypoint for the white-box recon pipeline.

Usage:
    python -m pipeline.cli index         --source <dir> --db data/recon.db
    python -m pipeline.cli triage        --source <dir> --db data/recon.db [--model NAME]
    python -m pipeline.cli audit         --db data/recon.db [--model NAME]
    python -m pipeline.cli enqueue-trace --db data/recon.db
    python -m pipeline.cli trace         --source <dir> --db data/recon.db [--model NAME]
    python -m pipeline.cli log-finding   --db data/recon.db --verification-method live_debug --status confirmed ...
    python -m pipeline.cli setup-target-env    --source <dir> --schema-sql <file> --db-user U --db-password P --db-name N --db data/recon.db
    python -m pipeline.cli dynamic-probe       --env-id <N> --request-templates <file> --db data/recon.db
    python -m pipeline.cli teardown-target-env --env-id <N> --db data/recon.db
    python -m pipeline.cli export-report --db data/recon.db --format markdown --out report.md
    python -m pipeline.cli export-report --db data/recon.db --format sqlmap-json --out candidates.json
    python -m pipeline.cli coverage      --db data/recon.db

`log-finding` is Stage 5's write-side only -- a human records what they
already verified; nothing here decides anything.
`setup-target-env`/`dynamic-probe`/`teardown-target-env` are Stage 4.5
(dynamic verification) -- see CLAUDE.md's "Dynamic Verification (Stage 4.5)"
section for the hard local-only guardrail and probe-set scope boundary.
`export-report` is Stage 6: reads only `findings` rows with
`verified_by_human=1 AND status='confirmed'` and renders them as either a
human-readable Markdown report or a versioned `sqlmap_candidate_v1` JSON
file consumed by the separately-governed `sqlmap-wrapper/` tool -- see
CLAUDE.md's "Reporting (Stage 6)" section.
"""

import argparse
import json
import sys
from pathlib import Path

from pipeline import config, db
from pipeline.llm.ollama_client import LLMRunner, ModelNotAvailableError, OllamaClient
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage1_triage.triage import triage_all_files
from pipeline.stage2_audit.audit import audit_all_files
from pipeline.stage3_trace.builder import enqueue_trace_targets
from pipeline.stage4_deep_trace.deep_trace import trace_all_pending
from pipeline.stage4_5_dynamic_verify import env_setup, orchestrator
from pipeline.stage5_verify.logger import InvalidFindingError, log_finding
from pipeline.stage6_report.exporter import export_report

DEFAULT_MODEL = "whiterabbitneo-33b:latest"


def cmd_index(args):
    conn = db.connect(args.db)
    stats = index_source_tree(conn, args.source)
    print(stats)


def cmd_triage(args):
    conn = db.connect(args.db)
    client = OllamaClient(model_name=args.model, num_ctx=args.num_ctx, host=args.host)
    try:
        client.verify_model_available()
    except ModelNotAvailableError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    runner = LLMRunner(conn, client)
    stats = triage_all_files(conn, runner, args.source)
    print(stats)


def cmd_audit(args):
    conn = db.connect(args.db)
    client = OllamaClient(model_name=args.model, num_ctx=args.num_ctx, host=args.host)
    try:
        client.verify_model_available()
    except ModelNotAvailableError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    runner = LLMRunner(conn, client)
    stats = audit_all_files(conn, runner)
    print(stats)


def cmd_enqueue_trace(args):
    conn = db.connect(args.db)
    stats = enqueue_trace_targets(conn)
    print(stats)


def cmd_trace(args):
    conn = db.connect(args.db)
    client = OllamaClient(model_name=args.model, num_ctx=args.num_ctx, host=args.host)
    try:
        client.verify_model_available()
    except ModelNotAvailableError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    runner = LLMRunner(conn, client)
    stats = trace_all_pending(conn, runner, args.source)
    print(stats)


def cmd_log_finding(args):
    conn = db.connect(args.db)
    try:
        finding_id = log_finding(
            conn,
            endpoint=args.endpoint,
            vuln_class=args.vuln_class,
            verification_method=args.verification_method,
            status=args.status,
            verified_by_human=not args.not_verified,
            severity=args.severity,
            notes=args.notes,
            source_trace_id=args.source_trace_id,
            source_triage_result_id=args.source_triage_result_id,
        )
    except InvalidFindingError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"logged finding_id={finding_id}")


def cmd_setup_target_env(args):
    conn = db.connect(args.db)
    build_dir = args.build_dir or str(Path(args.source).parent / f"{Path(args.source).name}-build")

    build = env_setup.recompile_source(args.source, build_dir, release=args.java_release)
    if not build.compiled_ok:
        print(f"error: recompile failed:\n{build.stderr_tail}", file=sys.stderr)
        sys.exit(1)

    env_setup.start_postgres_container(
        args.db_container_name, args.db_user, args.db_password, args.db_name,
        port=args.db_port, image=args.db_image,
    )
    env_setup.wait_for_db_ready(args.db_container_name, args.db_user, args.db_name)
    env_setup.apply_schema(args.db_container_name, args.db_user, args.db_name, args.schema_sql)

    started = env_setup.start_app(
        build.build_dir, args.source, build.start_class, app_port=args.app_port,
        db_host="localhost", db_port=args.db_port, db_name=args.db_name,
        db_user=args.db_user, db_password=args.db_password,
    )
    env_setup.wait_for_app_ready("localhost", args.app_port)

    env_id = env_setup.register_environment(
        conn, source_root=args.source, build_dir=build.build_dir, start_class=build.start_class,
        app_host="localhost", app_port=args.app_port, app_pid=started["pid"],
        app_log_path=started["log_path"], db_container_name=args.db_container_name,
        db_host="localhost", db_port=args.db_port, db_user=args.db_user, db_name=args.db_name,
    )
    print(f"env_id={env_id}")


def cmd_teardown_target_env(args):
    conn = db.connect(args.db)
    env_setup.teardown_environment(conn, args.env_id)
    print(f"env_id={args.env_id} torn down")


def cmd_dynamic_probe(args):
    conn = db.connect(args.db)
    request_templates = json.loads(Path(args.request_templates).read_text())
    runner = None
    if not args.no_llm_interpret:
        client = OllamaClient(model_name=args.model, num_ctx=args.num_ctx, host=args.host)
        try:
            client.verify_model_available()
        except ModelNotAvailableError as e:
            print(f"error: {e}", file=sys.stderr)
            sys.exit(1)
        runner = LLMRunner(conn, client)
    stats = orchestrator.run_all_pending(conn, args.env_id, request_templates, runner=runner)
    print(stats)


def cmd_export_report(args):
    conn = db.connect(args.db)
    request_templates = None
    if args.request_templates:
        request_templates = json.loads(Path(args.request_templates).read_text())
    export_id, finding_count = export_report(conn, args.format, args.out, request_templates=request_templates)
    print(f"export_id={export_id} findings={finding_count} -> {args.out}")


def cmd_coverage(args):
    conn = db.connect(args.db)
    total = conn.execute("SELECT COUNT(*) AS n FROM symbols WHERE kind IN ('method','constructor')").fetchone()["n"]
    covered = conn.execute(
        "SELECT COUNT(DISTINCT symbol_id) AS n FROM triage_results WHERE symbol_id IS NOT NULL"
    ).fetchone()["n"]
    uncovered = conn.execute(
        "SELECT f.path, s.name FROM symbols s "
        "JOIN files f ON f.file_id = s.file_id "
        "LEFT JOIN triage_results tr ON tr.symbol_id = s.symbol_id "
        "WHERE s.kind IN ('method','constructor') AND tr.result_id IS NULL "
        "ORDER BY f.path, s.line_start"
    ).fetchall()
    hallucinated = conn.execute(
        "SELECT COUNT(*) AS n FROM audit_results WHERE status = 'hallucinated_row'"
    ).fetchone()["n"]

    print(f"methods triaged (resolved to a symbol): {covered}/{total}")
    print(f"hallucinated_row rows (per Stage 2 audit): {hallucinated}")
    if uncovered:
        print(f"symbols with no resolved triage row ({len(uncovered)}):")
        for row in uncovered:
            print(f"  {row['path']}: {row['name']}")


def build_parser():
    parser = argparse.ArgumentParser(prog="pipeline.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p_index = sub.add_parser("index", help="Stage 0: build the deterministic static index")
    p_index.add_argument("--source", required=True, help="root directory of decompiled Java source")
    p_index.add_argument("--db", default="data/recon.db")
    p_index.set_defaults(func=cmd_index)

    p_triage = sub.add_parser("triage", help="Stage 1: per-file LLM triage pass")
    p_triage.add_argument("--source", required=True, help="same source root used for `index`")
    p_triage.add_argument("--db", default="data/recon.db")
    p_triage.add_argument("--model", default=DEFAULT_MODEL)
    p_triage.add_argument("--host", default="http://localhost:11434")
    p_triage.add_argument("--num-ctx", dest="num_ctx", type=int, default=config.DEFAULT_NUM_CTX)
    p_triage.set_defaults(func=cmd_triage)

    p_audit = sub.add_parser("audit", help="Stage 2: adversarial audit pass against Stage 0 facts")
    p_audit.add_argument("--db", default="data/recon.db")
    p_audit.add_argument("--model", default=DEFAULT_MODEL)
    p_audit.add_argument("--host", default="http://localhost:11434")
    p_audit.add_argument("--num-ctx", dest="num_ctx", type=int, default=config.DEFAULT_NUM_CTX)
    p_audit.set_defaults(func=cmd_audit)

    p_enqueue_trace = sub.add_parser(
        "enqueue-trace",
        help="Stage 3: deterministic trace-queue builder (call-graph + same-file name-matching graph walk)",
    )
    p_enqueue_trace.add_argument("--db", default="data/recon.db")
    p_enqueue_trace.set_defaults(func=cmd_enqueue_trace)

    p_trace = sub.add_parser("trace", help="Stage 4: LLM deep-trace pass over pending trace_queue items")
    p_trace.add_argument("--source", required=True, help="same source root used for `index`")
    p_trace.add_argument("--db", default="data/recon.db")
    p_trace.add_argument("--model", default=DEFAULT_MODEL)
    p_trace.add_argument("--host", default="http://localhost:11434")
    p_trace.add_argument("--num-ctx", dest="num_ctx", type=int, default=config.DEFAULT_NUM_CTX)
    p_trace.set_defaults(func=cmd_trace)

    p_log_finding = sub.add_parser(
        "log-finding",
        help="Stage 5 (write-side): record a finding you've already manually verified",
    )
    p_log_finding.add_argument("--db", default="data/recon.db")
    p_log_finding.add_argument("--endpoint", help="e.g. /signup")
    p_log_finding.add_argument("--vuln-class", dest="vuln_class", help="e.g. blind_sqli, error_based, second_order")
    p_log_finding.add_argument(
        "--verification-method",
        dest="verification_method",
        choices=["live_debug", "query_log", "manual_payload"],
        required=True,
    )
    p_log_finding.add_argument(
        "--status", choices=["confirmed", "rejected", "needs_review"], default="needs_review"
    )
    p_log_finding.add_argument("--severity", help="free text, e.g. high/medium/low")
    p_log_finding.add_argument("--notes", help="what you observed and why")
    p_log_finding.add_argument(
        "--source-trace-id", dest="source_trace_id", type=int, help="trace_results.trace_id this finding originated from"
    )
    p_log_finding.add_argument(
        "--source-triage-result-id",
        dest="source_triage_result_id",
        type=int,
        help="triage_results.result_id this finding originated from, if no trace exists",
    )
    p_log_finding.add_argument(
        "--not-verified",
        dest="not_verified",
        action="store_true",
        help="record this WITHOUT marking verified_by_human=1 (rare -- this command exists specifically to record verification, so verified_by_human defaults to true)",
    )
    p_log_finding.set_defaults(func=cmd_log_finding)

    p_setup_env = sub.add_parser(
        "setup-target-env",
        help="Stage 4.5: recompile decompiled source + stand up a disposable local DB + start the target app",
    )
    p_setup_env.add_argument("--source", required=True, help="decompiled source root (e.g. ~/BlueBirdSourceCode)")
    p_setup_env.add_argument("--build-dir", default=None, help="default: <source>-build alongside --source")
    p_setup_env.add_argument("--schema-sql", required=True, help="human-authored minimal DB schema for the target")
    p_setup_env.add_argument("--db-container-name", default="wb-dynamic-pg")
    p_setup_env.add_argument("--db-image", default="docker.io/library/postgres:15")
    p_setup_env.add_argument("--db-user", required=True)
    p_setup_env.add_argument("--db-password", required=True)
    p_setup_env.add_argument("--db-name", required=True)
    p_setup_env.add_argument("--db-port", type=int, default=5432)
    p_setup_env.add_argument("--app-port", type=int, default=8080)
    p_setup_env.add_argument("--java-release", default="17")
    p_setup_env.add_argument("--db", default="data/recon.db")
    p_setup_env.set_defaults(func=cmd_setup_target_env)

    p_teardown_env = sub.add_parser("teardown-target-env", help="stop+remove a Stage 4.5 disposable environment")
    p_teardown_env.add_argument("--env-id", type=int, required=True)
    p_teardown_env.add_argument("--db", default="data/recon.db")
    p_teardown_env.set_defaults(func=cmd_teardown_target_env)

    p_dynamic_probe = sub.add_parser(
        "dynamic-probe",
        help="Stage 4.5: fire the fixed non-destructive probe battery at each exploitable_path candidate",
    )
    p_dynamic_probe.add_argument("--db", default="data/recon.db")
    p_dynamic_probe.add_argument("--env-id", type=int, required=True)
    p_dynamic_probe.add_argument(
        "--request-templates", required=True,
        help="JSON file: symbol_name -> {endpoint, http_method, param_defaults, verify_table, column_map?}",
    )
    p_dynamic_probe.add_argument("--model", default=DEFAULT_MODEL, help="local model, used only to interpret ambiguous results")
    p_dynamic_probe.add_argument("--host", default="http://localhost:11434")
    p_dynamic_probe.add_argument("--num-ctx", dest="num_ctx", type=int, default=config.DEFAULT_NUM_CTX)
    p_dynamic_probe.add_argument(
        "--no-llm-interpret", action="store_true",
        help="skip local-LLM interpretation; leave ambiguous results as 'ambiguous' for manual review",
    )
    p_dynamic_probe.set_defaults(func=cmd_dynamic_probe)

    p_export_report = sub.add_parser(
        "export-report",
        help="Stage 6: render confirmed+verified findings as a report or an sqlmap-wrapper candidate export",
    )
    p_export_report.add_argument("--db", default="data/recon.db")
    p_export_report.add_argument("--format", required=True, choices=["markdown", "sqlmap-json"])
    p_export_report.add_argument("--out", required=True, help="output file path")
    p_export_report.add_argument(
        "--request-templates",
        dest="request_templates",
        help="sqlmap-json only: same request-templates.json Stage 4.5 uses, to carry sibling "
        "request-body values (param_defaults) into the export",
    )
    p_export_report.set_defaults(func=cmd_export_report)

    p_coverage = sub.add_parser("coverage", help="print Stage 0 -> Stage 1 coverage as a query, not a stored field")
    p_coverage.add_argument("--db", default="data/recon.db")
    p_coverage.set_defaults(func=cmd_coverage)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
