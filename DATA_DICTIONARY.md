# Data Dictionary

Reference for every table in `schema.sql`. `schema.sql` is the source of
truth for structure (see `CLAUDE.md`) — if this document and the SQL ever
disagree, the SQL wins and this file needs updating.

Tables are grouped and ordered the same way as `schema.sql`.

## Stage 0 — Deterministic structural index (ground truth)

Nothing derived from an LLM call may write to these tables.

### `files`

One row per source file indexed by Stage 0.

| Column | Type | Description |
|---|---|---|
| `file_id` | INTEGER (PK) | Unique identifier for the file. |
| `path` | TEXT | File path, unique. |
| `sha256` | TEXT | Content hash, used to detect whether source changed between pipeline runs. |
| `loc` | INTEGER | Lines of code. |
| `token_count` | INTEGER | Token count, used for context-budget/chunking decisions. |
| `indexed_at` | TIMESTAMP | When this file was indexed (defaults to now). |

### `symbols`

One row per class, method, field, or constructor found in a file.

| Column | Type | Description |
|---|---|---|
| `symbol_id` | INTEGER (PK) | Unique identifier for the symbol. |
| `file_id` | INTEGER (FK → `files`) | File the symbol belongs to. Cascades on delete. |
| `kind` | TEXT | What kind of symbol this is. See factors below. |
| `name` | TEXT | Symbol name. |
| `signature` | TEXT | Full method signature, if applicable. |
| `parent_symbol_id` | INTEGER (FK → `symbols`) | Enclosing symbol, e.g. a method's parent class. |
| `line_start` | INTEGER | Starting line number. |
| `line_end` | INTEGER | Ending line number. |
| `is_entrypoint` | BOOLEAN | Whether this symbol is a web entry point (e.g. annotated `@GetMapping`/`@PostMapping`). Default `0`. |

**`kind` factors:**
- `class` — a class declaration.
- `method` — a method declaration.
- `field` — a field declaration.
- `constructor` — a constructor declaration.

### `call_edges`

One row per call site, linking a caller symbol to a callee. Cross-file calls
are always recorded here — never dropped — even when the callee can't yet
be resolved.

| Column | Type | Description |
|---|---|---|
| `edge_id` | INTEGER (PK) | Unique identifier for the call edge. |
| `caller_symbol_id` | INTEGER (FK → `symbols`) | Symbol making the call. Cascades on delete. |
| `callee_symbol_id` | INTEGER (FK → `symbols`, nullable) | Symbol being called, if resolved. NULL when unresolved. |
| `callee_raw_name` | TEXT | Raw callee name as written in source; fallback when the callee can't be resolved to a `symbol_id`. |
| `resolved` | BOOLEAN | Whether `callee_symbol_id` was successfully resolved. Default `1`. |
| `line_no` | INTEGER | Line number of the call site. |

**`resolved` factors:**
- `1` (true) — the callee was resolved to a known symbol (intra-file resolution succeeded).
- `0` (false) — best-effort/unresolved (e.g. cross-file call not yet resolved, reflection). This state must remain visible and queryable — it is never silently treated as "no issue."

### `field_access`

One row per field read or write performed by a method, used for
second-order/data-flow tracing.

| Column | Type | Description |
|---|---|---|
| `access_id` | INTEGER (PK) | Unique identifier for the access. |
| `symbol_id` | INTEGER (FK → `symbols`) | The method performing the access. Cascades on delete. |
| `field_name` | TEXT | Name of the field being accessed. |
| `owning_class` | TEXT | Class that owns the field. |
| `access_type` | TEXT | Whether the access is a read or write. See factors below. |
| `line_no` | INTEGER | Line number of the access. |

**`access_type` factors:**
- `read` — the method reads the field's value.
- `write` — the method assigns/mutates the field's value.

### `input_sources`

One row per untrusted-input entry point associated with a method (e.g.
Spring MVC parameter bindings).

| Column | Type | Description |
|---|---|---|
| `source_id` | INTEGER (PK) | Unique identifier for the input source. |
| `symbol_id` | INTEGER (FK → `symbols`) | Method that receives this input. Cascades on delete. |
| `kind` | TEXT | Type of input binding. See factors below. |
| `param_name` | TEXT | Name of the parameter. |
| `line_no` | INTEGER | Line number where the input is declared/bound. |

**`kind` factors:**
- `RequestParam` — a query/form parameter (`@RequestParam`).
- `PathVariable` — a URL path segment (`@PathVariable`).
- `RequestBody` — a deserialized request body (`@RequestBody`).
- `Header` — an HTTP header value.
- `Cookie` — a cookie value.
- `SessionAttribute` — a value pulled from the HTTP session.

## Stage 1-4 — LLM-derived analysis (never ground truth)

Every row here must be traceable to an `llm_runs` row for provenance (model,
prompt version, chunking).

### `llm_runs`

One row per invocation of the local LLM, recording exactly which model and
prompt version produced downstream results.

| Column | Type | Description |
|---|---|---|
| `run_id` | INTEGER (PK) | Unique identifier for the run. |
| `stage` | TEXT | Which pipeline stage this run belongs to. See factors below. |
| `model_name` | TEXT | Exact Ollama tag used (e.g. `whiterabbitneo:latest`), confirmed against `ollama list` — never assumed. |
| `prompt_version` | TEXT | Prompt template version used (e.g. `triage_v1`). |
| `file_id` | INTEGER (FK → `files`) | File this run analyzed. |
| `started_at` | TIMESTAMP | When the run started (defaults to now). |
| `input_token_count` | INTEGER | Token count of the input sent to the model. |
| `num_ctx` | INTEGER | Ollama context length (`num_ctx`) used for this call — must match the value validated in the context-window benchmark. |
| `chunk_index` | INTEGER | Index of this chunk if the file was split (0-based). Default `0`. |
| `chunk_total` | INTEGER | Total number of chunks the file was split into. Default `1`. |

**`stage` factors:**
- `triage` — Stage 1, first-pass per-file review.
- `audit` — Stage 2, adversarial check of a triage run against Stage 0 ground truth.
- `trace` — Stage 4, deep-trace of a specific queued item.

### `triage_results`

One row per method reviewed during Stage 1 triage — every reviewed method
gets a row, including "clean" ones; silence is not an acceptable output
shape.

| Column | Type | Description |
|---|---|---|
| `result_id` | INTEGER (PK) | Unique identifier for the result row. |
| `run_id` | INTEGER (FK → `llm_runs`) | The triage run that produced this row. Cascades on delete. |
| `symbol_id` | INTEGER (FK → `symbols`, nullable) | Matched symbol, if the model's referenced method exists in `symbols`. |
| `symbol_name_raw` | TEXT | The method name/identifier as the model actually stated it. Populated even when `symbol_id` is NULL — this is intentional, and is what makes hallucination detection possible via a join against `symbols`. Do not "fix" by forcing a match. |
| `has_input` | BOOLEAN | Checklist item C1: whether the method has an identified input source. |
| `sink_type` | TEXT | Checklist item C2: what kind of sink the input reaches, if any. See factors below. |
| `validation_desc` | TEXT | Checklist item C3: free-text description of any validation/sanitization observed. |
| `needs_trace` | BOOLEAN | Checklist item C4: whether this result should be queued for Stage 3/4 deep trace. Default `0`. |
| `confidence` | TEXT | Checklist item C5: model's confidence in this assessment. See factors below. |
| `missing_context` | TEXT | What file/class the model needed but wasn't shown. |
| `notes` | TEXT | Free-text notes. |

**`sink_type` factors:**
- `sql_unsafe` — input reaches a SQL sink in a way that is not safely parameterized.
- `sql_safe` — input reaches a SQL sink, but via a safe parameterized query (first-class "safe" category, not just an absence of a finding).
- `file_path` — input reaches a file path/filesystem operation.
- `command_exec` — input reaches command execution.
- `template` — input reaches a template-rendering sink.
- `none` — no sink was identified for this method.

**`confidence` factors:**
- `high` — model is highly confident in the assessment.
- `medium` — moderate confidence.
- `low` — low confidence, e.g. due to missing context.

### `audit_results`

One row per symbol checked during Stage 2 audit, comparing a triage run
against Stage 0's ground-truth symbol list (never against the model's own
re-derivation of the file).

| Column | Type | Description |
|---|---|---|
| `audit_id` | INTEGER (PK) | Unique identifier for the audit row. |
| `run_id` | INTEGER (FK → `llm_runs`) | The audit run itself. |
| `audited_run_id` | INTEGER (FK → `llm_runs`) | The triage run being checked. |
| `symbol_id` | INTEGER (FK → `symbols`, nullable) | Symbol under audit. |
| `status` | TEXT | Outcome of the audit check for this symbol. See factors below. |
| `notes` | TEXT | Free-text notes. |

**`status` factors:**
- `matched` — the symbol was correctly covered by the triage run.
- `missing_from_table` — a real symbol has no corresponding triage row (coverage gap).
- `hallucinated_row` — the triage run produced a row referencing a symbol that doesn't exist.
- `ambiguous` — the audit couldn't cleanly classify the symbol's coverage.

## Stage 3 — Deterministic trace queue (sub-agent substitute)

### `trace_queue`

One row per candidate to deep-trace, generated deterministically from
`triage_results` where `needs_trace = 1`. Represents scripted work
assignment — not an LLM decision.

| Column | Type | Description |
|---|---|---|
| `queue_id` | INTEGER (PK) | Unique identifier for the queue entry. |
| `origin_triage_result_id` | INTEGER (FK → `triage_results`) | Triage row that generated this queue entry. |
| `target_symbol_id` | INTEGER (FK → `symbols`, nullable) | Symbol to trace. |
| `target_variable` | TEXT | Specific variable/parameter being traced. |
| `status` | TEXT | Current processing status of this queue entry. See factors below. |
| `assembled_context_symbol_ids` | TEXT | JSON array of `symbol_id`s assembled by the Stage 3 graph walk, to be handed to the model as bounded context. |
| `created_at` | TIMESTAMP | When this entry was queued (defaults to now). |

**`status` factors:**
- `pending` — not yet picked up for tracing. Default.
- `in_progress` — currently being traced.
- `done` — tracing completed.
- `blocked` — tracing cannot proceed (e.g. missing context).

### `trace_results`

One row per completed Stage 4 deep-trace, reasoning only over the context
explicitly assembled by the Stage 3 graph walk.

| Column | Type | Description |
|---|---|---|
| `trace_id` | INTEGER (PK) | Unique identifier for the trace result. |
| `queue_id` | INTEGER (FK → `trace_queue`) | Queue entry this result answers. Cascades on delete. |
| `run_id` | INTEGER (FK → `llm_runs`) | The trace run that produced this row. |
| `verdict` | TEXT | Outcome of the deep trace. See factors below. |
| `path_narrative` | TEXT | Step-by-step chain the model described from source to sink. |
| `evidence_symbol_ids` | TEXT | JSON array of the actual `symbol_id`s forming the cited path. |

**`verdict` factors:**
- `exploitable_path` — a complete path from input source to unsafe sink was traced.
- `safe_path` — a path was traced but is not exploitable (e.g. properly sanitized/parameterized).
- `insufficient_context` — the assembled context wasn't enough to reach a verdict.
- `inconclusive` — the model could not determine a verdict for another reason.

## Stage 5-6 — Human verification + final findings

Only findings with `verified_by_human = 1 AND status = 'confirmed'` should
ever leave the internal DB in an exported report.

### `findings`

The only table a report generator should read from. One row per candidate
finding, pending or after human review.

| Column | Type | Description |
|---|---|---|
| `finding_id` | INTEGER (PK) | Unique identifier for the finding. |
| `source_trace_id` | INTEGER (FK → `trace_results`, nullable) | Originating trace result, if any. Nullable because a finding may originate from triage alone. |
| `source_triage_result_id` | INTEGER (FK → `triage_results`, nullable) | Originating triage result. |
| `endpoint` | TEXT | Affected endpoint, e.g. `/find-user`. |
| `vuln_class` | TEXT | Vulnerability class, e.g. `blind_sqli`, `error_based`, `second_order`. |
| `verified_by_human` | BOOLEAN | Whether a human has verified this finding against a live system. Default `0`. |
| `verification_method` | TEXT | How the finding was verified. See factors below. |
| `verification_notes` | TEXT | Free-text notes from the human verifier. |
| `severity` | TEXT | Severity assessment. |
| `status` | TEXT | Review/export status. See factors below. Default `needs_review`. |
| `reviewed_at` | TIMESTAMP | When the finding was reviewed. |

**`verification_method` factors:**
- `live_debug` — verified via live debugger inspection.
- `query_log` — verified via database/query logs.
- `manual_payload` — verified via a manually crafted, human-driven request (not tool-automated).
- `NULL` — not yet verified.

**`status` factors:**
- `needs_review` — awaiting human review. Default.
- `confirmed` — human has confirmed this is a real finding. Combined with `verified_by_human = 1`, this is the only state eligible for export.
- `rejected` — human has determined this is not a real finding.

## Indexes

Indexes support the coverage/hallucination queries and call-graph/trace
lookups described in `CLAUDE.md`. See the `-- Indexes` block at the bottom
of `schema.sql` for the full, commented list rather than duplicating it here.
