"""Stage 6 orchestration: query.py -> a renderer -> write the file ->
record a report_exports row. The Stage 6 analog of Stage 4.5's
orchestrator.py.
"""

import datetime
import json
from pathlib import Path

from pipeline.stage6_report import render_markdown, render_sqlmap_json
from pipeline.stage6_report.query import assemble_finding_records

_INSERT_EXPORT = """
    INSERT INTO report_exports (format, output_path, finding_count)
    VALUES (?, ?, ?)
"""


def export_report(conn, fmt, out_path, request_templates=None):
    """fmt: 'markdown' or 'sqlmap-json'. request_templates: the same
    request-templates.json dict Stage 4.5 uses (symbol_name -> {endpoint,
    http_method, param_defaults, ...}) -- only consulted for 'sqlmap-json',
    to carry sibling request-body values into the export (see
    render_sqlmap_json._param_defaults_for's docstring). Returns
    (export_id, finding_count)."""
    records = assemble_finding_records(conn)
    out_path = Path(out_path)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if fmt == "markdown":
        out_path.write_text(render_markdown.render(records))
        db_format = "markdown"
    elif fmt == "sqlmap-json":
        generated_at = datetime.datetime.now(datetime.timezone.utc).isoformat()
        payload = render_sqlmap_json.render(records, generated_at, request_templates=request_templates)
        out_path.write_text(json.dumps(payload, indent=2))
        db_format = "sqlmap_json"
    else:
        raise ValueError(f"unknown export format: {fmt!r}")

    cursor = conn.execute(_INSERT_EXPORT, (db_format, str(out_path), len(records)))
    conn.commit()
    return cursor.lastrowid, len(records)
