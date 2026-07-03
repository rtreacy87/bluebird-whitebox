"""Builds and (optionally) executes a real sqlmap invocation for one
imported candidate. Dry-run by default -- `execute=False` only ever builds
and prints the argv plus records a `dry_run=1` row, no subprocess call at
all. `execute=True` is the one path in this whole tool that actually fires
something at a real target, and it is gated behind guard.require_authorized()
immediately before doing so.
"""

import json
import subprocess
from pathlib import Path

from sqlmap_wrapper import flags, guard


def _candidate_and_target(conn, candidate_id):
    candidate_row = conn.execute("SELECT * FROM candidates WHERE candidate_id = ?", (candidate_id,)).fetchone()
    if candidate_row is None:
        raise ValueError(f"no candidate with candidate_id={candidate_id}")
    if candidate_row["target_id"] is None:
        raise ValueError(f"candidate {candidate_id} has no assigned target -- run assign-target first")
    target_row = conn.execute(
        "SELECT * FROM targets WHERE target_id = ?", (candidate_row["target_id"],)
    ).fetchone()
    return candidate_row, target_row


def assign_target(conn, candidate_id, target_id):
    conn.execute("UPDATE candidates SET target_id = ? WHERE candidate_id = ?", (target_id, candidate_id))
    conn.commit()


def run(conn, candidate_id, output_dir, execute=False, extra_args=None, nonce=None, log=print):
    """Returns the resulting sqlmap_runs.run_id."""
    candidate_row, target_row = _candidate_and_target(conn, candidate_id)
    nonce = nonce or f"run{candidate_id}"
    argv = flags.build_args(candidate_row, target_row, output_dir, nonce=nonce, extra_args=extra_args)

    if not execute:
        log("dry-run (pass --execute to actually run this):")
        log(" ".join(argv))
        run_id = conn.execute(
            "INSERT INTO sqlmap_runs (candidate_id, target_id, argv_json, output_dir, dry_run) "
            "VALUES (?, ?, ?, ?, 1)",
            (candidate_id, target_row["target_id"], json.dumps(argv), output_dir),
        ).lastrowid
        conn.commit()
        return run_id

    guard.require_authorized(conn, target_row["host"], target_row["port"])

    Path(output_dir).mkdir(parents=True, exist_ok=True)
    run_id = conn.execute(
        "INSERT INTO sqlmap_runs (candidate_id, target_id, argv_json, output_dir, dry_run) "
        "VALUES (?, ?, ?, ?, 0)",
        (candidate_id, target_row["target_id"], json.dumps(argv), output_dir),
    ).lastrowid
    conn.commit()

    log("executing: " + " ".join(argv))
    proc = subprocess.run(argv, capture_output=True, text=True)

    Path(output_dir, "wrapper_stdout.log").write_text(proc.stdout or "")
    Path(output_dir, "wrapper_stderr.log").write_text(proc.stderr or "")

    conn.execute(
        "UPDATE sqlmap_runs SET exit_code = ?, finished_at = CURRENT_TIMESTAMP WHERE run_id = ?",
        (proc.returncode, run_id),
    )
    conn.commit()
    return run_id


def read_run_output(run_row):
    """Reads back the captured sqlmap stdout for a completed (execute=True)
    run -- what interpret.py hands to the local model."""
    stdout_path = Path(run_row["output_dir"], "wrapper_stdout.log")
    return stdout_path.read_text() if stdout_path.exists() else ""
