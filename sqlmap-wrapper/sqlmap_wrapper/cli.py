"""CLI entrypoint for sqlmap-wrapper.

Usage (run from the bluebird-whitebox repo root so `pipeline.*` stays
importable -- see llm_runner.py's module docstring):
    python -m sqlmap_wrapper.cli register-target --host <H> --port <P> [--label L] [--authorize] --wrapper-db <path>
    python -m sqlmap_wrapper.cli import-candidates --file <stage6-export.json> --wrapper-db <path>
    python -m sqlmap_wrapper.cli assign-target --candidate-id <N> --target-id <N> --wrapper-db <path>
    python -m sqlmap_wrapper.cli run-sqlmap --candidate-id <N> --output-dir <dir> [--execute] [--extra-args ...] --wrapper-db <path>
    python -m sqlmap_wrapper.cli interpret-run --run-id <N> [--model NAME] --wrapper-db <path>

register-target/import-candidates/assign-target/run-sqlmap (dry-run) never
touch a network or subprocess. run-sqlmap --execute and interpret-run are the
only two commands that do (a real sqlmap subprocess, and a real local Ollama
call, respectively) -- see CLAUDE.md.
"""

import argparse
import sys

from sqlmap_wrapper import db, guard, runner, targets
from sqlmap_wrapper.flags import DangerousFlagError, MissingRequestBodyError
from sqlmap_wrapper.import_candidates import InvalidCandidateExportError, import_candidates
from sqlmap_wrapper.interpret import interpret_run
from sqlmap_wrapper.llm_runner import WrapperLLMRunner

DEFAULT_MODEL = "whiterabbitneo-33b:latest"


def cmd_register_target(args):
    conn = db.connect(args.wrapper_db)
    target_id = targets.register_target(conn, args.host, args.port, label=args.label, authorized=args.authorize)
    print(f"target_id={target_id} authorized={args.authorize}")


def cmd_import_candidates(args):
    conn = db.connect(args.wrapper_db)
    try:
        import_id, count = import_candidates(conn, args.file)
    except InvalidCandidateExportError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"import_id={import_id} candidates={count}")


def cmd_assign_target(args):
    conn = db.connect(args.wrapper_db)
    runner.assign_target(conn, args.candidate_id, args.target_id)
    print(f"candidate_id={args.candidate_id} -> target_id={args.target_id}")


def cmd_run_sqlmap(args):
    conn = db.connect(args.wrapper_db)
    try:
        run_id = runner.run(
            conn, args.candidate_id, args.output_dir,
            execute=args.execute, extra_args=args.extra_args, nonce=args.nonce,
        )
    except (ValueError, guard.UnauthorizedTargetError, DangerousFlagError, MissingRequestBodyError) as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)
    print(f"run_id={run_id} dry_run={not args.execute}")


def cmd_interpret_run(args):
    conn = db.connect(args.wrapper_db)
    run_row = conn.execute("SELECT * FROM sqlmap_runs WHERE run_id = ?", (args.run_id,)).fetchone()
    if run_row is None:
        print(f"error: no sqlmap_runs row with run_id={args.run_id}", file=sys.stderr)
        sys.exit(1)
    if run_row["dry_run"]:
        print("error: run_id refers to a dry-run -- nothing was actually executed to interpret", file=sys.stderr)
        sys.exit(1)

    from pipeline.llm.ollama_client import ModelNotAvailableError, OllamaClient

    client = OllamaClient(model_name=args.model, num_ctx=args.num_ctx)
    try:
        client.verify_model_available()
    except ModelNotAvailableError as e:
        print(f"error: {e}", file=sys.stderr)
        sys.exit(1)

    llm_runner = WrapperLLMRunner(conn, client)
    output_text = runner.read_run_output(run_row)
    result_id = interpret_run(conn, llm_runner, run_row, output_text)
    print(f"result_id={result_id}")


def build_parser():
    parser = argparse.ArgumentParser(prog="sqlmap_wrapper.cli")
    sub = parser.add_subparsers(dest="command", required=True)

    p_register = sub.add_parser("register-target", help="declare a host:port in scope")
    p_register.add_argument("--host", required=True)
    p_register.add_argument("--port", type=int, required=True)
    p_register.add_argument("--label", default=None)
    p_register.add_argument("--authorize", action="store_true", help="mark authorized=1 immediately")
    p_register.add_argument("--wrapper-db", default="sqlmap-wrapper/data/wrapper.db")
    p_register.set_defaults(func=cmd_register_target)

    p_import = sub.add_parser("import-candidates", help="import a bluebird-whitebox Stage 6 sqlmap-candidate export")
    p_import.add_argument("--file", required=True, help="path to the Stage 6 JSON export")
    p_import.add_argument("--wrapper-db", default="sqlmap-wrapper/data/wrapper.db")
    p_import.set_defaults(func=cmd_import_candidates)

    p_assign = sub.add_parser("assign-target", help="associate an imported candidate with a registered target")
    p_assign.add_argument("--candidate-id", type=int, required=True)
    p_assign.add_argument("--target-id", type=int, required=True)
    p_assign.add_argument("--wrapper-db", default="sqlmap-wrapper/data/wrapper.db")
    p_assign.set_defaults(func=cmd_assign_target)

    p_run = sub.add_parser("run-sqlmap", help="build (and optionally execute) a real sqlmap invocation for a candidate")
    p_run.add_argument("--candidate-id", type=int, required=True)
    p_run.add_argument("--output-dir", required=True)
    p_run.add_argument("--execute", action="store_true", help="actually run sqlmap (default: dry-run/print only)")
    p_run.add_argument("--extra-args", nargs="*", default=None, help="extra sqlmap flags, checked against the denylist")
    p_run.add_argument("--nonce", default=None, help="override the default per-run nonce used to resolve {nonce} in param_defaults")
    p_run.add_argument("--wrapper-db", default="sqlmap-wrapper/data/wrapper.db")
    p_run.set_defaults(func=cmd_run_sqlmap)

    p_interpret = sub.add_parser("interpret-run", help="local-LLM interpretation of a completed sqlmap run's output")
    p_interpret.add_argument("--run-id", type=int, required=True)
    p_interpret.add_argument("--model", default=DEFAULT_MODEL)
    p_interpret.add_argument("--num-ctx", dest="num_ctx", type=int, default=4096)
    p_interpret.add_argument("--wrapper-db", default="sqlmap-wrapper/data/wrapper.db")
    p_interpret.set_defaults(func=cmd_interpret_run)

    return parser


def main():
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
