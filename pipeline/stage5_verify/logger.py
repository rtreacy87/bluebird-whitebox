"""Stage 5: human verification gate -- the write-side only.

No LLM, no automation: this module exists so a human who just finished
manually verifying a finding (via live debugging, query-log inspection, or
authorized manual testing -- see CLAUDE.md's Stage 5) can record that
verdict into `findings` as they go, instead of writing it up after the fact.
Nothing here decides whether a finding is real; it only persists what a
human already decided.
"""

_VALID_VERIFICATION_METHODS = {"live_debug", "query_log", "manual_payload", None}
_VALID_STATUSES = {"confirmed", "rejected", "needs_review"}


class InvalidFindingError(ValueError):
    pass


def log_finding(
    conn,
    endpoint=None,
    vuln_class=None,
    verification_method=None,
    status="needs_review",
    verified_by_human=True,
    severity=None,
    notes=None,
    source_trace_id=None,
    source_triage_result_id=None,
):
    """Write one row to `findings` and return its finding_id.

    Raises InvalidFindingError before touching the DB if verification_method
    or status don't match schema.sql's CHECK constraints -- a human typo in
    a CLI flag should fail loudly and immediately, not become an opaque
    sqlite3.IntegrityError or a silently coerced value.
    """
    if verification_method not in _VALID_VERIFICATION_METHODS:
        raise InvalidFindingError(
            f"verification_method must be one of {sorted(m for m in _VALID_VERIFICATION_METHODS if m)} "
            f"or omitted, got {verification_method!r}"
        )
    if status not in _VALID_STATUSES:
        raise InvalidFindingError(f"status must be one of {sorted(_VALID_STATUSES)}, got {status!r}")

    if source_trace_id is not None:
        row = conn.execute(
            "SELECT trace_id FROM trace_results WHERE trace_id = ?", (source_trace_id,)
        ).fetchone()
        if row is None:
            raise InvalidFindingError(f"no trace_results row with trace_id={source_trace_id}")
    if source_triage_result_id is not None:
        row = conn.execute(
            "SELECT result_id FROM triage_results WHERE result_id = ?", (source_triage_result_id,)
        ).fetchone()
        if row is None:
            raise InvalidFindingError(f"no triage_results row with result_id={source_triage_result_id}")

    cur = conn.execute(
        "INSERT INTO findings (source_trace_id, source_triage_result_id, endpoint, vuln_class, "
        "verified_by_human, verification_method, verification_notes, severity, status, reviewed_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
        (
            source_trace_id,
            source_triage_result_id,
            endpoint,
            vuln_class,
            int(bool(verified_by_human)),
            verification_method,
            notes,
            severity,
            status,
        ),
    )
    conn.commit()
    return cur.lastrowid
