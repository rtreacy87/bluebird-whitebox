"""Stage 3: deterministic trace-queue builder (call-graph + same-file
name-matching graph walk). See CLAUDE.md build order step 3: built on top of
intra-file call_edges and field_access data only -- no cross-file resolution.

No LLM involvement. The LLM never decides what to look at next (CLAUDE.md);
this module IS "what to look at next" for Stage 4, computed in plain Python.
"""

import json
import re

# Matches a getter-style callee name, with or without a receiver prefix:
# "user.getEmail" -> "email", "getAuthentication" -> "authentication".
# Anchored at end of string since call_edges.callee_raw_name never includes
# call-argument parens (confirmed against data/recon.db).
_GETTER_RE = re.compile(r"(?:^|\.)get([A-Z]\w*)$")


def _extract_getter_property(callee_raw_name):
    if not callee_raw_name:
        return None
    m = _GETTER_RE.search(callee_raw_name)
    return m.group(1).lower() if m else None


def _resolved_callee_ids(conn, target_symbol_id):
    rows = conn.execute(
        "SELECT DISTINCT callee_symbol_id FROM call_edges "
        "WHERE caller_symbol_id = ? AND resolved = 1 AND callee_symbol_id IS NOT NULL",
        (target_symbol_id,),
    ).fetchall()
    return [r["callee_symbol_id"] for r in rows]


def _corroborated_property_writers(conn, file_id, exclude_symbol_id, property_name):
    rows = conn.execute(
        "SELECT DISTINCT s.symbol_id FROM input_sources i "
        "JOIN symbols s ON s.symbol_id = i.symbol_id "
        "JOIN triage_results tr ON tr.symbol_id = s.symbol_id "
        "WHERE s.file_id = ? AND s.symbol_id != ? "
        "AND tr.sink_type = 'sql_unsafe' AND LOWER(i.param_name) = ?",
        (file_id, exclude_symbol_id, property_name),
    ).fetchall()
    return [r["symbol_id"] for r in rows]


def assemble_context(conn, target_symbol_id):
    """Deterministic graph walk for one target method's symbol_id.

    Returns (context_symbol_ids: list[int], target_variable: str|None).
    context_symbol_ids always starts with target_symbol_id, is deduplicated,
    and preserves discovery order (target, then resolved callees, then
    name-matched same-file candidates) so the ordering is stable/testable.
    target_variable is the first getter-derived property name that produced
    a corroborated same-file hit, or None if the walk never used the
    name-matching heuristic (i.e. this is a direct-parameter case).
    """
    file_row = conn.execute(
        "SELECT file_id FROM symbols WHERE symbol_id = ?", (target_symbol_id,)
    ).fetchone()
    file_id = file_row["file_id"] if file_row else None

    context_ids = [target_symbol_id]
    seen = {target_symbol_id}
    target_variable = None

    for callee_id in _resolved_callee_ids(conn, target_symbol_id):
        if callee_id not in seen:
            seen.add(callee_id)
            context_ids.append(callee_id)

    if file_id is not None:
        raw_names = conn.execute(
            "SELECT callee_raw_name FROM call_edges WHERE caller_symbol_id = ? "
            "AND callee_raw_name IS NOT NULL",
            (target_symbol_id,),
        ).fetchall()
        for row in raw_names:
            prop = _extract_getter_property(row["callee_raw_name"])
            if prop is None:
                continue
            for writer_id in _corroborated_property_writers(conn, file_id, target_symbol_id, prop):
                if writer_id not in seen:
                    seen.add(writer_id)
                    context_ids.append(writer_id)
                    if target_variable is None:
                        target_variable = prop

    return context_ids, target_variable


def enqueue_trace_targets(conn, log=print):
    """Stage 3 entry point: enqueue every triage_results row flagged
    sink_type='sql_unsafe', regardless of needs_trace (needs_trace is
    demonstrated-unreliable as a queueing gate -- see profile's needs_trace=0
    despite being the /profile/{id} regression case). Idempotent: skips
    result_ids already enqueued.
    """
    pending_rows = conn.execute(
        "SELECT result_id, symbol_id FROM triage_results "
        "WHERE sink_type = 'sql_unsafe' "
        "AND result_id NOT IN (SELECT origin_triage_result_id FROM trace_queue) "
        "ORDER BY result_id"
    ).fetchall()

    stats = {"queued_pending": 0, "queued_blocked_no_symbol": 0}
    for row in pending_rows:
        result_id = row["result_id"]
        symbol_id = row["symbol_id"]

        if symbol_id is None:
            # Triage referenced a name that never resolved to a real Stage 0
            # symbol (hallucinated_row per Stage 2 audit) -- nothing to walk.
            # Still record the queue row for auditability, but there is no
            # deterministic work Stage 4 could do with it, so mark blocked
            # immediately rather than sending an empty-context prompt.
            conn.execute(
                "INSERT INTO trace_queue (origin_triage_result_id, target_symbol_id, "
                "target_variable, status, assembled_context_symbol_ids) "
                "VALUES (?, NULL, NULL, 'blocked', '[]')",
                (result_id,),
            )
            stats["queued_blocked_no_symbol"] += 1
            continue

        context_ids, target_variable = assemble_context(conn, symbol_id)
        conn.execute(
            "INSERT INTO trace_queue (origin_triage_result_id, target_symbol_id, "
            "target_variable, status, assembled_context_symbol_ids) "
            "VALUES (?, ?, ?, 'pending', ?)",
            (result_id, symbol_id, target_variable, json.dumps(context_ids)),
        )
        stats["queued_pending"] += 1

    conn.commit()
    log(
        f"trace queue: {stats['queued_pending']} pending, "
        f"{stats['queued_blocked_no_symbol']} blocked (no resolvable symbol)"
    )
    return stats


if __name__ == "__main__":
    import sys

    from pipeline import db

    if len(sys.argv) != 2:
        print("usage: python -m pipeline.stage3_trace.builder <db_path>")
        sys.exit(1)

    conn = db.connect(sys.argv[1])
    stats = enqueue_trace_targets(conn)
    print(stats)
