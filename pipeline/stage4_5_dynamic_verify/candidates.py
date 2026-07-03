"""Stage 4.5 candidate selection: deterministic, no LLM involvement.

Turns Stage 4's exploitable_path hypotheses into a worklist of (trace
result, request parameter) pairs to probe. Two distinct shapes of candidate,
combined:

1. Direct request parameters -- every input_sources row belonging to the
   flagged method, always first_order (the value comes straight from this
   method's own request parameters).
2. Second-order candidates -- when Stage 3's same-file getter-name-matching
   heuristic set trace_queue.target_variable (e.g. "email" for
   profile/editProfilePOST), that variable itself is a candidate even though
   it has no input_sources row of its own (it's a stored value read back
   unsafely, not a request param on this method).

Already-batched (trace_id, param_name) pairs are excluded via SQL, mirroring
enqueue_trace_targets()'s existing idempotent-skip pattern in stage3_trace/builder.py.
"""

from pipeline.stage4_5_dynamic_verify.classify import order_hypothesis_for

_DIRECT_PARAM_QUERY = """
    SELECT tr.trace_id, tq.queue_id, tq.target_symbol_id, s.name AS symbol_name,
           i.source_id AS input_source_id, i.param_name AS param_name
    FROM trace_results tr
    JOIN trace_queue tq ON tq.queue_id = tr.queue_id
    JOIN symbols s ON s.symbol_id = tq.target_symbol_id
    JOIN input_sources i ON i.symbol_id = tq.target_symbol_id
    WHERE tr.verdict = 'exploitable_path'
      AND NOT EXISTS (
          SELECT 1 FROM dynamic_probe_batches b
          WHERE b.source_trace_id = tr.trace_id AND b.target_param_name = i.param_name
      )
"""

_SECOND_ORDER_QUERY = """
    SELECT tr.trace_id, tq.queue_id, tq.target_symbol_id, s.name AS symbol_name,
           NULL AS input_source_id, tq.target_variable AS param_name
    FROM trace_results tr
    JOIN trace_queue tq ON tq.queue_id = tr.queue_id
    JOIN symbols s ON s.symbol_id = tq.target_symbol_id
    WHERE tr.verdict = 'exploitable_path'
      AND tq.target_variable IS NOT NULL
      AND NOT EXISTS (
          SELECT 1 FROM dynamic_probe_batches b
          WHERE b.source_trace_id = tr.trace_id AND b.target_param_name = tq.target_variable
      )
"""


def pending_candidates(conn):
    """Returns list[dict]: {trace_id, queue_id, target_symbol_id, symbol_name,
    input_source_id, param_name, order_hypothesis}."""
    candidates = []

    for row in conn.execute(_DIRECT_PARAM_QUERY).fetchall():
        candidates.append(
            {
                "trace_id": row["trace_id"],
                "queue_id": row["queue_id"],
                "target_symbol_id": row["target_symbol_id"],
                "symbol_name": row["symbol_name"],
                "input_source_id": row["input_source_id"],
                "param_name": row["param_name"],
                "order_hypothesis": order_hypothesis_for(None),
            }
        )

    for row in conn.execute(_SECOND_ORDER_QUERY).fetchall():
        candidates.append(
            {
                "trace_id": row["trace_id"],
                "queue_id": row["queue_id"],
                "target_symbol_id": row["target_symbol_id"],
                "symbol_name": row["symbol_name"],
                "input_source_id": row["input_source_id"],
                "param_name": row["param_name"],
                "order_hypothesis": order_hypothesis_for(row["param_name"]),
            }
        )

    return candidates
