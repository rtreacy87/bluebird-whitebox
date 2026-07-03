"""Stage 6 canonical query: the one place that reads `findings` and
assembles everything both the markdown report and the sqlmap-candidate
export need. Both renderers consume this same function's output so there is
only one export filter to get right (per CLAUDE.md: only rows with
verified_by_human=1 AND status='confirmed' may ever leave the DB).
"""

_FINDINGS_QUERY = """
    SELECT finding_id, source_trace_id, source_triage_result_id, endpoint,
           vuln_class, severity, verification_method, verification_notes, status
    FROM findings
    WHERE verified_by_human = 1 AND status = 'confirmed'
    ORDER BY finding_id
"""

_TRIAGE_BY_RESULT_ID = """
    SELECT symbol_name_raw, sink_type, validation_desc, confidence
    FROM triage_results WHERE result_id = ?
"""

_TRACE_BY_ID = """
    SELECT queue_id, verdict, path_narrative FROM trace_results WHERE trace_id = ?
"""

_ORIGIN_TRIAGE_RESULT_ID_FOR_QUEUE = """
    SELECT origin_triage_result_id FROM trace_queue WHERE queue_id = ?
"""

_BATCHES_FOR_TRACE = """
    SELECT batch_id, target_param_name, http_method, endpoint, order_hypothesis,
           verify_table, verify_column
    FROM dynamic_probe_batches
    WHERE source_trace_id = ?
    ORDER BY batch_id
"""

_RESULTS_FOR_BATCH = """
    SELECT probe_name, classification, app_log_snippet
    FROM dynamic_probe_results
    WHERE batch_id = ?
    ORDER BY probe_id
"""


def _resolve_triage_context(conn, source_trace_id, source_triage_result_id):
    """A finding can reference triage context directly, or indirectly via its
    trace -> trace_queue link. Returns a dict of triage fields, or None if
    neither path resolves (e.g. a human-entered finding with no upstream row)."""
    result_id = source_triage_result_id
    if result_id is None and source_trace_id is not None:
        trace_row = conn.execute(_TRACE_BY_ID, (source_trace_id,)).fetchone()
        if trace_row is not None:
            origin_row = conn.execute(_ORIGIN_TRIAGE_RESULT_ID_FOR_QUEUE, (trace_row["queue_id"],)).fetchone()
            if origin_row is not None:
                result_id = origin_row["origin_triage_result_id"]

    if result_id is None:
        return None

    row = conn.execute(_TRIAGE_BY_RESULT_ID, (result_id,)).fetchone()
    return dict(row) if row is not None else None


def _trace_narrative(conn, source_trace_id):
    if source_trace_id is None:
        return None
    row = conn.execute(_TRACE_BY_ID, (source_trace_id,)).fetchone()
    return dict(row) if row is not None else None


def _sample_log_snippet(probe_results):
    """Prefer an `error`-classified probe's log (the strongest signal), then
    any non-baseline probe, then baseline -- never leave this empty if any
    probe recorded a snippet at all."""
    for row in probe_results:
        if row["classification"] == "error" and row["app_log_snippet"]:
            return row["app_log_snippet"]
    for row in probe_results:
        if row["probe_name"] != "baseline" and row["app_log_snippet"]:
            return row["app_log_snippet"]
    for row in probe_results:
        if row["app_log_snippet"]:
            return row["app_log_snippet"]
    return None


def _parameters_for_finding(conn, source_trace_id):
    if source_trace_id is None:
        return []

    parameters = []
    for batch in conn.execute(_BATCHES_FOR_TRACE, (source_trace_id,)).fetchall():
        probe_results = conn.execute(_RESULTS_FOR_BATCH, (batch["batch_id"],)).fetchall()
        classifications = {row["probe_name"]: row["classification"] for row in probe_results}
        parameters.append(
            {
                "target_param_name": batch["target_param_name"],
                "http_method": batch["http_method"],
                "endpoint": batch["endpoint"],
                "order_hypothesis": batch["order_hypothesis"],
                "verify_table": batch["verify_table"],
                "verify_column": batch["verify_column"],
                "classifications": classifications,
                "sample_log_snippet": _sample_log_snippet(probe_results),
            }
        )
    return parameters


def assemble_finding_records(conn):
    """Returns list[dict], one entry per confirmed+verified finding:
    {finding_id, endpoint, vuln_class, severity, verification_method,
     verification_notes, status, triage (dict|None), trace (dict|None),
     parameters (list[dict])}.
    """
    records = []
    for finding in conn.execute(_FINDINGS_QUERY).fetchall():
        triage = _resolve_triage_context(conn, finding["source_trace_id"], finding["source_triage_result_id"])
        trace = _trace_narrative(conn, finding["source_trace_id"])
        parameters = _parameters_for_finding(conn, finding["source_trace_id"])
        records.append(
            {
                "finding_id": finding["finding_id"],
                "endpoint": finding["endpoint"],
                "vuln_class": finding["vuln_class"],
                "severity": finding["severity"],
                "verification_method": finding["verification_method"],
                "verification_notes": finding["verification_notes"],
                "status": finding["status"],
                "triage": triage,
                "trace": trace,
                "parameters": parameters,
            }
        )
    return records
