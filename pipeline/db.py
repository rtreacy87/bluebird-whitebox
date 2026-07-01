"""SQLite connection helper.

schema.sql at the repo root is the source of truth for table structure
(see CLAUDE.md). This module only ever reads that file to initialize a
fresh database -- it never defines schema inline.
"""

import sqlite3
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
SCHEMA_PATH = REPO_ROOT / "schema.sql"


def connect(db_path):
    """Open (creating + initializing if needed) the recon SQLite DB at db_path."""
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
