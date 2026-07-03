"""Deterministic classification of one Stage 4.5 probe's observed outcome.

Pure functions, no I/O -- the raw evidence (HTTP status, app log tail, DB
row, the exact input sent) is gathered elsewhere (probes.py). This module
only ever decides which of the fixed classification labels the evidence
supports; it never fires a request or touches the network/DB itself.
"""

_ERROR_MARKERS = ("BadSqlGrammarException", "PSQLException", "SQLException", "Exception")


def classify_probe(http_status, app_log_tail, db_row_value, input_value) -> str:
    """Checked in this exact priority order -- a 500 with a logged exception
    is a stronger, more specific signal that the value broke the query than
    merely finding the raw value in a row that may not even have been
    written by this probe, so 'error' is checked first.

    1. http_status >= 500 and an error marker appears in the app's own log
       -> 'error' (the value broke the query outright).
    2. the resulting DB row contains input_value verbatim
       -> 'passthrough_unmodified' (reached storage completely unescaped).
    3. a DB row exists but differs from input_value
       -> 'transformed' (something changed it -- e.g. hashed, encoded).
    4. no DB row, and a clean non-5xx response with no error marker
       -> 'rejected' (validation stopped it before it reached the sink).
    5. anything else -> 'ambiguous' (needs the local-LLM interpretation pass).
    """
    app_log_tail = app_log_tail or ""

    has_error_marker = any(marker in app_log_tail for marker in _ERROR_MARKERS)

    if http_status is not None and http_status >= 500 and has_error_marker:
        return "error"

    if db_row_value is not None and input_value in db_row_value:
        return "passthrough_unmodified"

    if db_row_value is not None and db_row_value != input_value:
        return "transformed"

    if db_row_value is None and (http_status is None or http_status < 500) and not has_error_marker:
        return "rejected"

    return "ambiguous"


def order_hypothesis_for(target_variable) -> str:
    """target_variable is trace_queue.target_variable. Non-NULL means Stage
    3's same-file getter-name-matching heuristic fired (e.g. "email" for
    profile/editProfilePOST) -- a second-order candidate. NULL means the
    flagged value came straight from this method's own request parameters
    (e.g. signupPOST's "name") -- a first-order candidate."""
    return "second_order" if target_variable is not None else "first_order"
