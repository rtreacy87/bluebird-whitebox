# Data Dictionary — sqlmap-wrapper

What each table is for and why it's shaped the way it is. Companion to
`CLAUDE.md` (the rules) and `../DATA_DICTIONARY.md` (the parent pipeline's
own dictionary, for `findings`/`dynamic_probe_results`/etc.). Schema source
of truth is `schema.sql` — this file explains it, never redefines it.

## Known boundaries (up front, not buried)

- **`candidates.finding_id_source` is not a real foreign key.** It's the
  parent `bluebird-whitebox` repo's `findings.finding_id`, living in a
  genuinely separate SQLite file (`../data/recon.db` vs. this tool's own
  `data/wrapper.db`) — SQLite has no cross-database FK enforcement. This is
  a deliberate consequence of keeping the two tools' data stores separate
  (see `CLAUDE.md`'s "why this tool is governed separately"), not an
  oversight. If you need to trace a candidate back to its original finding,
  join by value (`finding_id_source = recon.db's findings.finding_id`) by
  hand, or via the same `source_file` recorded on `import_batches`.
- **`targets.authorized` never expires or re-verifies.** Once a target is
  marked `authorized = 1`, it stays that way until someone runs
  `update_authorization(..., authorized=False)` explicitly. There is no
  "this authorization is 30 days old, confirm it's still in scope" prompt.
- **`candidates.dbms_hint` is exactly whatever Stage 6 computed** (a simple
  string-match heuristic against a probe's log snippet, see
  `../pipeline/stage6_report/dbms_hints.py`) — this tool never re-derives
  or second-guesses it.

## `targets`

The explicit, human-authorized scope declaration this tool's guard checks
against.

**Why an explicit registration table, not a hardcoded allowlist:** the
parent pipeline's Stage 4.5 guard is a fixed
`{"localhost","127.0.0.1","::1"}` set, because it only ever talks to a
disposable replica it stood up itself. This tool's whole purpose is
firing at a *real* target (an HTB lab box, eventually a real engagement
host) — by definition not localhost — so there is no fixed set that could
ever be correct. The guard here instead requires a deliberate, auditable
act: a human runs `register-target`, and only rows with `authorized = 1`
ever pass `guard.require_authorized()`.

| Column | Type | Description |
|---|---|---|
| `target_id` | INTEGER (PK) | Unique identifier. |
| `host` / `port` | TEXT / INTEGER | The real target. |
| `label` | TEXT | Free text, e.g. `'HTB-BlueBird-10.10.11.x'`. |
| `authorized` | BOOLEAN | Must be `1` before `require_authorized()` will allow a real `sqlmap` invocation against this host:port. |
| `registered_at` | TIMESTAMP | When this row was created. |

## `import_batches`

One row per Stage 6 export ingested via `import-candidates`.

**Why:** Provenance of *which* export a given set of candidates came from —
matches this whole project's habit of recording "what happened, when, with
what" (`llm_runs`, `target_environments`, `report_exports` in the parent
repo). `schema_version` is recorded per-import (not just checked and
discarded) so a stale import can be identified later if the shared JSON
contract ever changes.

| Column | Type | Description |
|---|---|---|
| `import_id` | INTEGER (PK) | Unique identifier. |
| `source_file` | TEXT | Path to the Stage 6 JSON export file. |
| `schema_version` | TEXT | The export's `schema_version` field, e.g. `'sqlmap_candidate_v1'`. |
| `imported_at` | TIMESTAMP | When this import ran. |
| `candidate_count` | INTEGER | How many candidates this import produced. |

## `candidates`

One row per imported candidate — the actual unit `run-sqlmap` operates on.

**Why `target_id` is nullable and set separately from import:** a Stage 6
export never carries a real host (see the parent repo's
`render_sqlmap_json.py` docstring — it's endpoint PATH and PARAM STRUCTURE
only). Importing a candidate is a data-ingestion step; deciding *which*
registered target it should run against is a distinct, deliberate human
decision (`assign-target`), so the two are separate operations rather than
one import step trying to guess a target.

**Why `param_defaults_json` is a separate column from `evidence_json`:**
they answer different questions. `evidence_json` is *why* this candidate
was flagged (the trace narrative, probe classifications, a log sample) —
informational, read by a human or fed to `interpret.py`. `param_defaults`
is *what request body to send* — structural, read by `flags.build_args()`
to construct a working `sqlmap --data` string. Folding them into one blob
would make `build_args()` need to parse evidence text to find the one part
it actually needs.

| Column | Type | Description |
|---|---|---|
| `candidate_id` | INTEGER (PK) | Unique identifier. |
| `import_id` | INTEGER (FK → `import_batches`) | Which import this came from. Cascades on delete. |
| `target_id` | INTEGER (FK → `targets`, nullable) | Set via `assign-target`, not at import time. |
| `finding_id_source` | INTEGER | The parent repo's `findings.finding_id` — see "Known boundaries" above. |
| `endpoint` | TEXT | Route path, e.g. `/signup`. |
| `http_method` | TEXT | `GET`/`POST`/null. |
| `vuln_class` / `severity` | TEXT | Carried through from the parent `findings` row. |
| `order_hypothesis` | TEXT | `first_order`/`second_order`/null — see the second-order gap in `CLAUDE.md`. |
| `target_param_name` | TEXT | The parameter to test; null means Stage 6 had no reactive dynamic-probe evidence for this finding (see the parent repo's null-fallback candidate design). |
| `param_defaults_json` | TEXT | Sibling request-body values, from the same human-supplied `request-templates.json` Stage 4.5 uses. Null if none was supplied at export time. |
| `dbms_hint` | TEXT | Passed to `sqlmap --dbms` verbatim. |
| `evidence_json` | TEXT | The full evidence object (trace narrative, probe classifications, log sample), preserved verbatim from the export. |

## `sqlmap_runs`

One row per `run-sqlmap` invocation — dry-run or real.

**Why `argv_json` records the exact argv, not just "which candidate ran":**
mirrors `llm_runs` recording the exact model/prompt_version that produced a
result — if a run's outcome looks surprising later, you need to know
*exactly* what command produced it, not just that "candidate 3 was run."
This is what let the real discovered sqlmap-vs-Stage-4.5 evidence gap (see
`CLAUDE.md`) be reconstructed precisely: the recorded argv shows exactly
which flags were and weren't used.

**Why `dry_run` defaults to `1`:** matches `runner.run()`'s
dry-run-by-default behavior — the row itself makes it unambiguous, from a
query alone, whether a given "run" actually touched the network or was
just a preview.

| Column | Type | Description |
|---|---|---|
| `run_id` | INTEGER (PK) | Unique identifier. |
| `candidate_id` | INTEGER (FK → `candidates`) | Which candidate this ran. |
| `target_id` | INTEGER (FK → `targets`) | Which target this ran against. |
| `argv_json` | TEXT | The exact argv list, executed or previewed. |
| `output_dir` | TEXT | Where sqlmap's own output (and this tool's captured stdout/stderr) was written. |
| `dry_run` | BOOLEAN | `1` = preview only, no subprocess call was made. |
| `exit_code` | INTEGER | sqlmap's process exit code, null for dry runs. |
| `started_at` / `finished_at` | TIMESTAMP | When this run began/ended. `finished_at` is null for dry runs. |

## `wrapper_llm_runs`

This tool's own `llm_runs`-equivalent — the one provenance table for the
one stage that touches a model (`sqlmap_interpret`).

**Why a separate table from the parent repo's `llm_runs`, not a shared
one:** the parent's `llm_runs.stage` `CHECK` constraint doesn't include
`'sqlmap_interpret'`, and the two tools have entirely separate databases by
design (see `CLAUDE.md`). Extending the parent's `CHECK` to accommodate this
tool's stage would blur a boundary that's supposed to stay firm — a
separately-governed tool gets its own provenance table, not a shared one
with a widened enum.

| Column | Type | Description |
|---|---|---|
| `run_id` | INTEGER (PK) | Unique identifier. |
| `stage` | TEXT | Always `'sqlmap_interpret'` currently — a `CHECK` constraint, not a free string, exactly like the parent's `llm_runs.stage`. |
| `model_name` | TEXT | The exact Ollama tag used. |
| `prompt_version` | TEXT | e.g. `'sqlmap_interpret_v1'` — versioned exactly like the parent repo's prompts, never overwritten in place. |
| `started_at` | TIMESTAMP | When this call was made. |

## `sqlmap_results`

One row per interpreted sqlmap run — the actual, queryable outcome.

**Why `raw_output_path` is a pointer, not an embedded blob:** matches the
parent repo's `dynamic_probe_results.app_log_snippet` being a trimmed
sample rather than a full log dump — sqlmap's own output/log files can be
large; the DB stores where to find them, not a copy of them.

**Why `result_type` has exactly these four values, and why
`'not_confirmed'` is a first-class outcome, not treated as a failure:** see
`CLAUDE.md`'s discovered-limitation section — a real, known-vulnerable
candidate genuinely produced `not_confirmed` here, because sqlmap's
black-box HTTP-only view couldn't see the server-log evidence Stage 4.5
had. Collapsing `not_confirmed` into "the wrapper failed" or silently
retrying would hide a real, useful signal (sqlmap's default techniques
don't fit this sink shape) behind a manufactured "success."

| Column | Type | Description |
|---|---|---|
| `result_id` | INTEGER (PK) | Unique identifier. |
| `run_id` | INTEGER (FK → `sqlmap_runs`) | Which run this interprets. Cascades on delete. |
| `result_type` | TEXT | `confirmed` / `not_confirmed` / `error` / `inconclusive`. |
| `summary_text` | TEXT | The model's short plain-English summary — advisory, not authoritative, same caveat this whole project applies to every LLM-derived text field. |
| `raw_output_path` | TEXT | Where the actual sqlmap output/log lives on disk. |
| `interpreted_by_run_id` | INTEGER (FK → `wrapper_llm_runs`) | Which model call produced this row. |
