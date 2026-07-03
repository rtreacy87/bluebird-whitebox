"""Imports a bluebird-whitebox Stage 6 sqlmap-candidate export
(schema_version "sqlmap_candidate_v1") into this tool's own `candidates`
table.

validate_candidate() is a hand-rolled shape/enum check, not a JSON Schema
library dependency -- matches this project's established minimal-dependency
preference (see bluebird-whitebox's schemas/sqlmap_candidate_v1.schema.json,
which documents this same shape but is never imported or executed by
either side). Both this function and that JSON Schema file must be kept in
sync by hand if the shape ever changes -- bump SCHEMA_VERSION on both sides
together, never silently.
"""

import json

SCHEMA_VERSION = "sqlmap_candidate_v1"

_REQUIRED_CANDIDATE_KEYS = {
    "finding_id", "endpoint", "http_method", "vuln_class", "severity",
    "order_hypothesis", "target_param_name", "param_defaults", "dbms_hint",
    "evidence", "note",
}
_VALID_HTTP_METHODS = {"GET", "POST", None}
_VALID_ORDER_HYPOTHESES = {"first_order", "second_order", None}
_VALID_DBMS_HINTS = {"postgresql", "mysql", "mssql", None}


class InvalidCandidateExportError(Exception):
    """Raised when an imported file doesn't match the expected
    sqlmap_candidate_v1 shape -- refuse the import rather than guess at a
    partial/malformed structure."""


def validate_candidate(obj):
    """Returns a list of human-readable error strings; empty list = valid."""
    errors = []

    missing = _REQUIRED_CANDIDATE_KEYS - obj.keys()
    if missing:
        errors.append(f"missing keys: {sorted(missing)}")
        return errors  # further checks would just KeyError

    if not isinstance(obj["finding_id"], int):
        errors.append("finding_id must be an int")
    if not isinstance(obj["endpoint"], str):
        errors.append("endpoint must be a str")
    if obj["http_method"] not in _VALID_HTTP_METHODS:
        errors.append(f"http_method must be one of {sorted(m for m in _VALID_HTTP_METHODS if m)} or null")
    if obj["order_hypothesis"] not in _VALID_ORDER_HYPOTHESES:
        errors.append(f"order_hypothesis must be one of {sorted(o for o in _VALID_ORDER_HYPOTHESES if o)} or null")
    if obj["target_param_name"] is not None and not isinstance(obj["target_param_name"], str):
        errors.append("target_param_name must be a str or null")
    if obj["dbms_hint"] not in _VALID_DBMS_HINTS:
        errors.append(f"dbms_hint must be one of {sorted(d for d in _VALID_DBMS_HINTS if d)} or null")
    if not isinstance(obj["evidence"], dict):
        errors.append("evidence must be an object")
    if obj["target_param_name"] is None and not obj["note"]:
        errors.append("note is required when target_param_name is null")

    return errors


def validate_export(payload):
    """Validates the top-level export shape. Returns a list of errors
    (empty = valid) covering the schema_version and every candidate."""
    errors = []
    if payload.get("schema_version") != SCHEMA_VERSION:
        errors.append(f"schema_version must be {SCHEMA_VERSION!r}, got {payload.get('schema_version')!r}")
        return errors  # a version mismatch makes per-candidate checks meaningless

    candidates = payload.get("candidates")
    if not isinstance(candidates, list):
        errors.append("candidates must be a list")
        return errors

    for i, candidate in enumerate(candidates):
        for err in validate_candidate(candidate):
            errors.append(f"candidate[{i}]: {err}")

    return errors


def import_candidates(conn, source_file):
    """Reads and validates a Stage 6 export, writes one import_batches row
    plus one candidates row per entry. Raises InvalidCandidateExportError
    (without writing anything) if validation fails."""
    payload = json.loads(open(source_file).read())
    errors = validate_export(payload)
    if errors:
        raise InvalidCandidateExportError(f"{source_file}: " + "; ".join(errors))

    candidates = payload["candidates"]
    import_id = conn.execute(
        "INSERT INTO import_batches (source_file, schema_version, candidate_count) VALUES (?, ?, ?)",
        (str(source_file), payload["schema_version"], len(candidates)),
    ).lastrowid

    for candidate in candidates:
        param_defaults = candidate["param_defaults"]
        conn.execute(
            "INSERT INTO candidates (import_id, finding_id_source, endpoint, http_method, "
            "vuln_class, severity, order_hypothesis, target_param_name, param_defaults_json, "
            "dbms_hint, evidence_json) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                import_id,
                candidate["finding_id"],
                candidate["endpoint"],
                candidate["http_method"],
                candidate["vuln_class"],
                candidate["severity"],
                candidate["order_hypothesis"],
                candidate["target_param_name"],
                json.dumps(param_defaults) if param_defaults is not None else None,
                candidate["dbms_hint"],
                json.dumps(candidate["evidence"]),
            ),
        )
    conn.commit()
    return import_id, len(candidates)
