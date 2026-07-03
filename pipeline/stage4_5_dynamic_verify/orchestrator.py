"""Stage 4.5 CLI-facing orchestration: ties candidates + probes + classify +
interpret together into one `dynamic-probe` run.
"""

from pipeline.stage4_5_dynamic_verify.candidates import pending_candidates
from pipeline.stage4_5_dynamic_verify.probes import create_batch, run_battery


def run_all_pending(conn, env_id, request_templates: dict, runner=None, log=print) -> dict:
    """request_templates: symbol_name -> {endpoint, http_method,
    param_defaults: dict, verify_table, column_map: dict (optional,
    param_name -> db column, defaults to param_name itself)}.

    Never guesses a request shape: a candidate whose symbol_name has no
    entry in request_templates is skipped and counted, not fabricated.
    """
    env_row = conn.execute("SELECT * FROM target_environments WHERE env_id = ?", (env_id,)).fetchone()
    if env_row is None:
        raise ValueError(f"no target_environments row with env_id={env_id}")

    stats = {
        "batches": 0,
        "probes": 0,
        "error": 0,
        "passthrough_unmodified": 0,
        "transformed": 0,
        "rejected": 0,
        "ambiguous": 0,
        "skipped_no_template": 0,
    }

    for candidate in pending_candidates(conn):
        template = request_templates.get(candidate["symbol_name"])
        if template is None:
            log(f"skip {candidate['symbol_name']}/{candidate['param_name']}: no request-template entry")
            stats["skipped_no_template"] += 1
            continue

        param_defaults = template.get("param_defaults", {})
        fixed_params = {k: v for k, v in param_defaults.items() if k != candidate["param_name"]}
        column_map = template.get("column_map", {})
        verify_column = column_map.get(candidate["param_name"], candidate["param_name"])

        batch_id = create_batch(
            conn,
            source_trace_id=candidate["trace_id"],
            input_source_id=candidate["input_source_id"],
            env_id=env_id,
            endpoint=template["endpoint"],
            http_method=template["http_method"],
            target_param_name=candidate["param_name"],
            order_hypothesis=candidate["order_hypothesis"],
            verify_table=template.get("verify_table"),
            verify_column=verify_column,
        )
        batch_row = conn.execute("SELECT * FROM dynamic_probe_batches WHERE batch_id = ?", (batch_id,)).fetchone()
        stats["batches"] += 1

        log(f"battery: {candidate['symbol_name']}/{candidate['param_name']} ({candidate['order_hypothesis']})")
        probe_ids = run_battery(conn, env_row, batch_row, fixed_params, env_row["app_log_path"], log=log)
        stats["probes"] += len(probe_ids)

        for probe_id in probe_ids:
            probe_row = conn.execute("SELECT * FROM dynamic_probe_results WHERE probe_id = ?", (probe_id,)).fetchone()
            classification = probe_row["classification"]
            if classification == "ambiguous" and runner is not None:
                from pipeline.stage4_5_dynamic_verify.interpret import interpret_ambiguous

                classification = interpret_ambiguous(conn, runner, probe_row, log=log)
            stats[classification] = stats.get(classification, 0) + 1

    return stats
