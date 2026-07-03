"""SQLite connection helper -- mirrors bluebird-whitebox's pipeline/db.py
exactly. schema.sql at this subtree's root is the source of truth (see
CLAUDE.md); this module only ever reads that file to initialize a fresh
database, never defines schema inline.
"""

import sqlite3
from pathlib import Path

WRAPPER_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = WRAPPER_ROOT / "schema.sql"


def connect(db_path):
    """Open (creating + initializing if needed) the wrapper's SQLite DB at db_path."""
    db_path = Path(db_path)
    is_new = not db_path.exists()
    db_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")

    if is_new:
        conn.executescript(SCHEMA_PATH.read_text())
        conn.commit()

    return conn
