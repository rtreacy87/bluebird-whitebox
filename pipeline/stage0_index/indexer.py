"""Stage 0 orchestration: walk a source tree, parse each .java file
intra-file only, and write files/symbols/call_edges/field_access/input_sources.

Deterministic, no LLM involvement (see CLAUDE.md). Cross-file call resolution
is explicitly out of scope here -- an unresolved call_edges row is a normal,
expected outcome, not an error.
"""

import hashlib
import sys
from pathlib import Path

from pipeline.stage0_index.parser import JavaParseError, parse_source
from pipeline.stage0_index.tokenizer import estimate_token_count


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def index_source_tree(conn, source_root, log=print):
    """Parse every .java file under source_root and populate Stage 0 tables.

    Existing rows for files whose sha256 hasn't changed are left untouched
    (re-run is idempotent); files whose content changed are re-parsed and
    replaced (old symbols/call_edges/field_access/input_sources cascade-delete
    via foreign keys).
    """
    source_root = Path(source_root)
    java_files = sorted(source_root.rglob("*.java"))
    if not java_files:
        log(f"warning: no .java files found under {source_root}")

    stats = {"files_indexed": 0, "files_unchanged": 0, "files_failed": 0, "symbols": 0}

    for path in java_files:
        source = path.read_text(encoding="utf-8", errors="replace")
        sha = _sha256(source)
        rel_path = str(path.relative_to(source_root))

        existing = conn.execute(
            "SELECT file_id, sha256 FROM files WHERE path = ?", (rel_path,)
        ).fetchone()
        if existing and existing["sha256"] == sha:
            stats["files_unchanged"] += 1
            continue

        try:
            parsed = parse_source(str(path), source)
        except JavaParseError as e:
            stats["files_failed"] += 1
            log(f"PARSE FAILED: {e}")
            continue

        loc = source.count("\n") + 1
        token_count = estimate_token_count(source)

        if existing:
            file_id = existing["file_id"]
            conn.execute(
                "UPDATE files SET sha256 = ?, loc = ?, token_count = ?, "
                "indexed_at = CURRENT_TIMESTAMP WHERE file_id = ?",
                (sha, loc, token_count, file_id),
            )
        else:
            cur = conn.execute(
                "INSERT INTO files (path, sha256, loc, token_count) VALUES (?, ?, ?, ?)",
                (rel_path, sha, loc, token_count),
            )
            file_id = cur.lastrowid

        _write_parsed_file(conn, file_id, parsed)
        stats["files_indexed"] += 1
        stats["symbols"] += len(parsed.symbols)
        log(f"indexed {rel_path}: {len(parsed.symbols)} symbols")

    conn.commit()
    return stats


def _write_parsed_file(conn, file_id, parsed):
    # Wipe this file's previously derived rows (cascades from symbols via FK).
    conn.execute("DELETE FROM symbols WHERE file_id = ?", (file_id,))

    local_to_db_id = {}
    for sym in parsed.symbols:
        parent_db_id = local_to_db_id.get(sym.parent_local_id) if sym.parent_local_id is not None else None
        cur = conn.execute(
            "INSERT INTO symbols (file_id, kind, name, signature, parent_symbol_id, "
            "line_start, line_end, is_entrypoint) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                file_id,
                sym.kind,
                sym.name,
                sym.signature,
                parent_db_id,
                sym.line_start,
                sym.line_end,
                int(sym.is_entrypoint),
            ),
        )
        local_to_db_id[sym.local_id] = cur.lastrowid

    for edge in parsed.call_edges:
        caller_db_id = local_to_db_id[edge.caller_local_id]
        callee_db_id = local_to_db_id.get(edge.callee_local_id) if edge.callee_local_id is not None else None
        conn.execute(
            "INSERT INTO call_edges (caller_symbol_id, callee_symbol_id, callee_raw_name, "
            "resolved, line_no) VALUES (?, ?, ?, ?, ?)",
            (caller_db_id, callee_db_id, edge.callee_raw_name, int(edge.resolved), edge.line_no),
        )

    for fa in parsed.field_access:
        conn.execute(
            "INSERT INTO field_access (symbol_id, field_name, owning_class, access_type, line_no) "
            "VALUES (?, ?, ?, ?, ?)",
            (local_to_db_id[fa.symbol_local_id], fa.field_name, fa.owning_class, fa.access_type, fa.line_no),
        )

    for src in parsed.input_sources:
        conn.execute(
            "INSERT INTO input_sources (symbol_id, kind, param_name, line_no) VALUES (?, ?, ?, ?)",
            (local_to_db_id[src.symbol_local_id], src.kind, src.param_name, src.line_no),
        )


if __name__ == "__main__":
    from pipeline import db

    if len(sys.argv) != 3:
        print("usage: python -m pipeline.stage0_index.indexer <source_root> <db_path>")
        sys.exit(1)

    conn = db.connect(sys.argv[2])
    stats = index_source_tree(conn, sys.argv[1])
    print(stats)
