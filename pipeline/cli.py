"""CLI entrypoint for the white-box recon pipeline.

Usage:
    python -m pipeline.cli index         --source <dir> --db data/recon.db
    python -m pipeline.cli triage        --source <dir> --db data/recon.db [--model NAME]
    python -m pipeline.cli audit         --db data/recon.db [--model NAME]
    python -m pipeline.cli enqueue-trace --db data/recon.db
    python -m pipeline.cli trace         --source <dir> --db data/recon.db [--model NAME]
    python -m pipeline.cli coverage      --db data/recon.db

Stage 5+ (human verification / findings export) is deliberately not
implemented yet per CLAUDE.md's build order.
"""

import argparse
import sys

from pipeline import config, db
from pipeline.llm.ollama_client import LLMRunner, ModelNotAvailableError, OllamaClient
from pipeline.stage0_index.indexer import index_source_tree
from pipeline.stage1_triage.triage import triage_all_files
from pipeline.stage2_audit.audit import audit_all_files
from pipeline.stage3_trace.builder import enqueue_trace_targets
from pipeline.stage4_deep_trace.deep_trace import trace_all_pending

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
