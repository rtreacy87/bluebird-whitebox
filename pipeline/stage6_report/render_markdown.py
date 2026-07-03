"""Human-readable Stage 6 report renderer. Consumes query.py's canonical
finding records -- never queries the DB itself."""

_PROBE_ORDER = ("baseline", "single_quote", "double_quote", "backslash")


def _finding_section(record):
    lines = [
        f"## Finding {record['finding_id']}: {record['endpoint']} ({record['vuln_class']})",
        "",
        f"- **Severity:** {record['severity'] or 'unspecified'}",
        f"- **Verification method:** {record['verification_method'] or 'unspecified'}",
    ]
    if record["verification_notes"]:
        lines.append(f"- **Verification notes:** {record['verification_notes']}")

    if record["triage"]:
        lines += [
            "",
            "### Triage summary",
            "",
            f"`{record['triage']['symbol_name_raw']}` (confidence: {record['triage']['confidence']}): "
            f"{record['triage']['validation_desc']}",
        ]

    if record["trace"]:
        lines += [
            "",
            "### Trace narrative",
            "",
            f"Verdict: `{record['trace']['verdict']}`",
            "",
            record["trace"]["path_narrative"] or "(no narrative recorded)",
        ]

    if record["parameters"]:
        lines += [
            "",
            "### Dynamic verification evidence (Stage 4.5)",
            "",
            "| parameter | " + " | ".join(_PROBE_ORDER) + " |",
            "|---|" + "---|" * len(_PROBE_ORDER),
        ]
        for param in record["parameters"]:
            row = [param["target_param_name"] or "(unknown)"]
            row += [param["classifications"].get(probe, "-") for probe in _PROBE_ORDER]
            lines.append("| " + " | ".join(row) + " |")

    lines.append("")
    return "\n".join(lines)


def render(records):
    if not records:
        return "# Findings Report\n\nNo confirmed, human-verified findings yet.\n"

    header = f"# Findings Report\n\n{len(records)} confirmed, human-verified finding(s).\n\n"
    return header + "\n".join(_finding_section(r) for r in records)
