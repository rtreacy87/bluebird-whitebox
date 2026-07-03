"""Explicit target registration -- the human-in-the-loop step
guard.require_authorized() checks against. Registering a target is a
deliberate act of declaring scope, not incidental to importing candidates
or running sqlmap.
"""


class TargetAlreadyRegisteredError(Exception):
    """Raised on a duplicate (host, port) registration attempt -- use
    update_authorization() to change an existing target's authorized flag
    instead of re-registering."""


def register_target(conn, host, port, label=None, authorized=False):
    try:
        cursor = conn.execute(
            "INSERT INTO targets (host, port, label, authorized) VALUES (?, ?, ?, ?)",
            (host, port, label, authorized),
        )
    except Exception as e:
        if "UNIQUE constraint failed" in str(e):
            raise TargetAlreadyRegisteredError(
                f"{host}:{port} is already registered -- use update_authorization() instead"
            ) from e
        raise
    conn.commit()
    return cursor.lastrowid


def update_authorization(conn, host, port, authorized):
    cursor = conn.execute(
        "UPDATE targets SET authorized = ? WHERE host = ? AND port = ?",
        (authorized, host, port),
    )
    conn.commit()
    return cursor.rowcount


def list_targets(conn):
    return conn.execute("SELECT * FROM targets ORDER BY target_id").fetchall()


def lookup_target(conn, host, port):
    return conn.execute("SELECT * FROM targets WHERE host = ? AND port = ?", (host, port)).fetchone()
