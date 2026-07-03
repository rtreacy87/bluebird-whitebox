"""Deterministic DBMS-guessing heuristic for the sqlmap-candidate export.

Separate from classify.py's _ERROR_MARKERS on purpose: that constant detects
the *presence* of any exception (deliberately broad); this needs *which*
DBMS, a different and more specific job, so it gets its own small,
purpose-specific marker table -- same pattern as classify_probe()/
order_hypothesis_for() being small standalone pure functions rather than
reused/repurposed private internals from another stage.

Values are passed straight through to sqlmap's own --dbms flag verbatim
(confirmed against a real `sqlmap` install: it accepts "postgresql"/"mysql"/
"mssql" directly, no translation needed).
"""

_DBMS_MARKERS = {
    "PSQLException": "postgresql",
    "org.postgresql": "postgresql",
    "MySQLSyntaxErrorException": "mysql",
    "com.mysql": "mysql",
    "SQLServerException": "mssql",
    "com.microsoft.sqlserver": "mssql",
}


def guess_dbms(log_snippet):
    """Returns a sqlmap --dbms value ("postgresql"/"mysql"/"mssql"), or None
    if no known marker appears in the given log text."""
    if not log_snippet:
        return None
    for marker, dbms in _DBMS_MARKERS.items():
        if marker in log_snippet:
            return dbms
    return None
