"""Versioned JSON export consumed by sqlmap-wrapper/. This is the one shared
contract between the two tools -- bump SCHEMA_VERSION and add a new
schemas/sqlmap_candidate_v1.schema.json sibling file (never overwrite the
old one in place) if the shape ever needs to change, matching this repo's
prompt-versioning convention.
"""

SCHEMA_VERSION = "sqlmap_candidate_v1"

_REACTIVE_CLASSIFICATIONS = {"error", "transformed"}


def _is_reactive(param):
    return any(c in _REACTIVE_CLASSIFICATIONS for c in param["classifications"].values())


def _evidence_for(record, param=None):
    evidence = {
        "path_narrative": record["trace"]["path_narrative"] if record["trace"] else None,
    }
    if param is not None:
        evidence["probe_classifications"] = param["classifications"]
        evidence["sample_log_snippet"] = param["sample_log_snippet"]
    return evidence


def _param_defaults_for(record, request_templates):
    """Sibling request-body values (e.g. signupPOST's username/email/password
    alongside whichever field is the injection point) come from the same
    human-supplied request_templates.json Stage 4.5 already requires --
    never inferred, since Stage 0 has no route/sibling-parameter tracking
    (see CLAUDE.md's Stage 4.5 section). Looked up by the finding's triaged
    method name, the same key Stage 4.5's orchestrator already indexes on.
    None if no template was supplied or none matches -- the wrapper must
    then ask a human before it can build a POST body for this candidate."""
    if not request_templates or not record["triage"]:
        return None
    template = request_templates.get(record["triage"]["symbol_name_raw"])
    if template is None:
        return None
    return template.get("param_defaults")


def _candidates_for_record(record, request_templates):
    from pipeline.stage6_report.dbms_hints import guess_dbms

    param_defaults = _param_defaults_for(record, request_templates)
    reactive_params = [p for p in record["parameters"] if _is_reactive(p)]

    if not reactive_params:
        note = (
            "No dynamic-probe evidence available for this finding -- injection point "
            "must be determined manually."
            if not record["parameters"]
            else "Stage 4.5 evidence exists but no parameter showed a reactive "
            "(error/transformed) classification -- injection point must be determined "
            "manually; do not assume this finding is unexploitable."
        )
        return [
            {
                "finding_id": record["finding_id"],
                "endpoint": record["endpoint"],
                "http_method": None,
                "vuln_class": record["vuln_class"],
                "severity": record["severity"],
                "order_hypothesis": None,
                "target_param_name": None,
                "param_defaults": param_defaults,
                "dbms_hint": None,
                "evidence": _evidence_for(record),
                "note": note,
            }
        ]

    candidates = []
    for param in reactive_params:
        candidates.append(
            {
                "finding_id": record["finding_id"],
                "endpoint": param["endpoint"] or record["endpoint"],
                "http_method": param["http_method"],
                "vuln_class": record["vuln_class"],
                "severity": record["severity"],
                "order_hypothesis": param["order_hypothesis"],
                "target_param_name": param["target_param_name"],
                "param_defaults": param_defaults,
                "dbms_hint": guess_dbms(param["sample_log_snippet"]),
                "evidence": _evidence_for(record, param),
                "note": None,
            }
        )
    return candidates


def render(records, generated_at, request_templates=None):
    candidates = []
    for record in records:
        candidates.extend(_candidates_for_record(record, request_templates))
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_at": generated_at,
        "candidates": candidates,
    }
