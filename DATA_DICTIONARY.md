# Data Dictionary

Reference for every table in `schema.sql`. `schema.sql` is the source of
truth for structure (see `CLAUDE.md`) — if this document and the SQL ever
disagree, the SQL wins and this file needs updating.

Tables are grouped and ordered the same way as `schema.sql`.

## Stage 0 — Deterministic structural index (ground truth)

Nothing derived from an LLM call may write to these tables.

### `files`

One row per source file indexed by Stage 0.

**Why:** Stage 0 has no LLM access, so decisions about how a file must be
handled downstream have to be made offline, from structural facts alone.
`token_count`/`loc` are what let the pipeline decide, before any model call,
whether a file is small enough for single-shot Stage 1 triage or must be
forced into method-boundary multi-chunk review (see
`pipeline/llm/chunking.py`'s `build_chunks()`, gated by
`SAFE_CONTEXT_TOKENS_HEURISTIC` in `pipeline/config.py`). `sha256` makes
re-indexing idempotent: `pipeline/stage0_index/indexer.py` skips files whose
hash hasn't changed, and for files that did change, deletes and rebuilds
their `symbols`/`call_edges`/`field_access`/`input_sources` rows (via
cascade) rather than leaving stale derived data next to updated source.

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

**Why:** This table is the parser-verified ground truth that everything
downstream is chunked and checked against. `line_start`/`line_end` aren't
just metadata — they're the literal chunk boundaries `build_chunks()` slices
on ("chunk by parser-verified method boundary only, never split a file by
raw token count," per `CLAUDE.md`), including the overlap of the previous
chunk's last method into the next chunk so boundary-adjacent logic is never
reviewed half-truncated. `is_entrypoint` marks where untrusted input can
first enter the app (e.g. `@GetMapping`/`@PostMapping`), which is what
anchors the whole vulnerability-tracing effort to reachable code. Because
`symbols` is ground truth, Stage 2 audit compares triage's claims against
this table directly rather than letting an LLM re-derive it (an LLM
re-deriving the symbol list could hallucinate the same way triage might).

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

**Why:** Stage 0 only resolves intra-file calls deterministically
(`pipeline/stage0_index/parser.py`); a cross-file callee is a real, common
case (this pipeline's build order deliberately defers cross-file resolution
until Stage 0-2 are validated — see `CLAUDE.md`), not an error. The table
exists so that gap is never silently invisible: a SQL-injection path that
only becomes exploitable through a call into another file must show up as
"unresolved," not disappear into a false "no issue" result. That's why
`resolved` has its own indexed column (`idx_call_edges_resolved`) rather than
being inferred from `callee_symbol_id IS NULL` — the state needs to be
directly queryable to drive future cross-file-resolution work and audit
checks against it.

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

**Why:** A call graph alone can't see data that gets written to a field in
one method and read back unsafely in a completely different, uncalled-from
method — a classic second-order injection shape. `field_access` exists to
make that write/read pairing queryable independent of the call graph, which
is why `findings.vuln_class` has `second_order` as a first-class category
and why the table is indexed on `field_name` (`idx_field_access_name`) —
that's the join key for "where else does this field get touched."

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

**Why:** This is captured deterministically by the Stage 0 parser rather
than left for the LLM to notice on its own, because it becomes an
independent ground-truth fact Stage 2 audit checks the model's work against.
`pipeline/stage2_audit/audit.py` computes `has_request_input` straight from
this table and puts it side-by-side with triage's self-reported `has_input`
claim in the same adversarial prompt — a mismatch is exactly the kind of
thing the audit pass exists to catch, and it only works because
`input_sources` isn't itself LLM-derived.

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

## Stage 1-2 — LLM-derived analysis (never ground truth)

Every row here must be traceable to an `llm_runs` row for provenance (model,
prompt version, chunking). (`trace_results`, Stage 4's LLM output, is also
`llm_runs`-backed the same way — see the "Stage 3-4" section below, grouped
there with `trace_queue` since the two tables are Stage 3/4's paired
input/output.)

### `llm_runs`

One row per invocation of the local LLM, recording exactly which model and
prompt version produced downstream results.

**Why:** Every field here exists for reproducibility of a specific,
re-runnable configuration, not just record-keeping. `model_name` must be the
exact Ollama tag (confirmed via `ollama list`, since a custom Modelfile
import can give it a non-obvious tag) because results are only meaningful if
you can point at the exact model build that produced them. `num_ctx` exists
because Ollama's default context window is much smaller than a model's
marketed max, and this value must match what `bench/context_benchmark.py`
empirically validated (`DEFAULT_NUM_CTX` in `pipeline/config.py`) — a
mismatch here would silently reintroduce truncated-context review without
anyone noticing. `chunk_index`/`chunk_total` exist so any downstream result
row can be traced back to exactly which slice of a (possibly chunked) file
produced it, which matters once a file is split across multiple LLM calls.

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
- `dynamic_interpret` — Stage 4.5, the one place in that stage that touches a model at all: interpreting an ambiguous dynamic-probe result. The raw probe-firing and classification rules are pure deterministic Python and never appear here.

### `triage_results`

One row per method reviewed during Stage 1 triage — every reviewed method
gets a row, including "clean" ones; silence is not an acceptable output
shape.

**Why:** Coverage has to be provable, not trusted from prompt compliance.
`pipeline/stage1_triage/triage.py` actively enforces this as a pipeline
invariant: if the LLM's JSON output silently omits a method the chunk
covered, the pipeline itself synthesizes a low-confidence placeholder row
for it, so a coverage query (`LEFT JOIN symbols` against this table) can
never be fooled into thinking a method was reviewed when it wasn't.
`symbol_id` being nullable with `symbol_name_raw` populated instead is the
other half of that same reliability concern, but pointed the other
direction: `_resolve_symbol_id()` deliberately does exact-name matching only
— it will *not* fuzzy-match a name the model invented to the closest real
symbol, because doing so would destroy the signal that lets a
`symbol_id IS NULL` row mean "the model referenced something that doesn't
exist" (a hallucination) rather than a routine data-entry gap.

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
- `sql_safe` — input reaches a SQL sink, but via a safe parameterized query. This is deliberately a first-class category rather than just an absence of a finding: it's the difference between "this method was reviewed and found clean" and "this method was never looked at," which is exactly the coverage guarantee `triage_results` exists to provide.
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

**Why:** Two distinct kinds of checking happen here, deliberately kept
apart. Structural status (`matched`/`hallucinated_row`/`missing_from_table`/
`ambiguous`) is computed in plain Python directly from `symbols`
(`pipeline/stage2_audit/audit.py:_structural_status`), never by asking an
LLM to re-derive it — an LLM doing that re-derivation could hallucinate the
same way triage might, which would defeat the point of an independent check.
The semantic review *is* a genuinely separate LLM call from triage
(`CLAUDE.md`: "must be a separate invocation from triage"), and it's only
ever shown pre-extracted Stage 0 facts (`has_request_input` from
`input_sources`, sink-keyword-flagged callees from `call_edges`) plus
triage's claim — never the raw file source — so it's checking triage's
claim against ground truth instead of forming its own independent (and
possibly equally wrong) reading of the file. `run_id` (the audit call) and
`audited_run_id` (the triage call being checked) are kept as separate
columns specifically so this two-run relationship is queryable.

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

## Stage 3-4 — Trace queue (deterministic) and deep-trace (LLM)

### `trace_queue`

One row per candidate to deep-trace. Populated by
`pipeline/stage3_trace/builder.py`'s `enqueue_trace_targets()`, which
selects every `triage_results` row with `sink_type = 'sql_unsafe'` — not
gated on `needs_trace` (see below). Represents scripted work assignment —
not an LLM decision.

**Why:** WhiteRabbitNeo is deliberately never given an open-ended "explore
this codebase" instruction — it's "not a highly agentic model" (per
`CLAUDE.md`), so all traversal/queueing decisions are scripted in Python
instead of left to the model. `trace_queue` is that scripted decision made
concrete: `assembled_context_symbol_ids` is the bounded, pre-assembled
context a deterministic graph walk decided the model needs, handed to it as
a fixed task rather than letting it wander the call graph itself. `status`
lets the queue be processed incrementally and resumably (pending → in
progress → done/blocked) without the LLM tracking its own state.

**Why `sink_type = 'sql_unsafe'`, not `needs_trace = 1`, is the enqueue
predicate:** `needs_trace` turned out to be empirically unreliable as a
queueing gate. Against the real BlueBird corpus, `ProfileController.profile`
— one of the three required regression vulnerabilities (`/profile/{id}`,
second-order SQLi) — was correctly flagged `sink_type='sql_unsafe'` by
triage, but triage set `needs_trace=0` on it anyway, despite the unsafe
value (`user.getEmail()`, read from a previously-queried object) being
exactly the case `needs_trace`'s own definition describes. Gating Stage 3's
queue on `needs_trace` would have silently dropped a known regression case,
so the builder enqueues every `sql_unsafe` row unconditionally and treats
`needs_trace` as informational only.

**How `assembled_context_symbol_ids` and `target_variable` actually get
populated:** the graph walk (`assemble_context()`) starts with the target
method's own `symbol_id`, adds any `call_edges` already `resolved=1` (real
intra-file method-to-method calls — rare in this corpus, 4 of 224 edges,
but real), and then scans the target's own `call_edges.callee_raw_name` for
a getter-style pattern (e.g. `user.getEmail` → property `email`), searching
*other same-file* methods whose `input_sources.param_name` matches that
property **and** whose own `sink_type = 'sql_unsafe'` — a deterministic,
same-file stand-in for "where might this value have been written." This is
what links `profile` (reads `user.getEmail()`) to `editProfilePOST` (writes
raw `email`) with zero LLM involvement, and is why `target_variable` gets
set to the matched property name (`"email"`) only when this heuristic
fires — it stays `NULL` for direct-parameter cases where the flagged value
came straight from the method's own request parameters (e.g.
`AuthController.signupPOST`). Because this walk is intra-file only (per
`CLAUDE.md`'s build order), it will **not** find `AuthController.signupPOST`
as a second write site for `profile`'s `email` — that's a different file,
and a known, accepted gap rather than something the heuristic guesses at.

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

**Why:** Because this pipeline's output is a hypothesis for a human to
verify — not an automated finding — the trace has to be checkable, not just
trusted. `evidence_symbol_ids` requires the model to cite the actual
`symbol_id`s forming the path it's claiming, so a human verifier can jump
straight to the cited code and confirm (or refute) the chain instead of
re-deriving it from a prose narrative alone. `path_narrative` is kept
alongside it so the citation and the explanation stay linked. The prompt
that produces this row is restricted to reasoning only over
`assembled_context_symbol_ids` from `trace_queue` — it's instructed not to
speculate about files it hasn't been shown, since anything it wasn't shown
also isn't in `evidence_symbol_ids` and couldn't be verified anyway.
`pipeline/stage4_deep_trace/deep_trace.py` also defensively filters
`evidence_symbol_ids` down to the subset actually shown to the model before
writing the row — the instruction alone is never trusted unenforced.

**A real reliability finding, not a hypothetical:** a full run against
BlueBird found `AuthController.resetPOST` and `PostController.createPost` —
both known Stage 1 false positives (their real DML calls are parameterized)
— still verdicted `exploitable_path` at Stage 4, even with the exact
parameterized call visible in the context they were shown; the
`path_narrative` restated the method's control flow without ever noting the
`new Object[]{...}` / `?` placeholder parameterization. This is why the
checkability this table is designed around (citations, not just a verdict)
matters in practice, and why this table's output is never treated as a
final finding on its own — `findings` (below) requires human verification
regardless of what `trace_results.verdict` says.

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

## Stage 4.5 — Dynamic verification (deterministic probe-firing; local-LLM interpretation only for ambiguous results)

Turns a Stage 4 `exploitable_path` hypothesis into observed evidence: stands
up a disposable local replica of the target, fires a small fixed
non-destructive probe battery at each flagged variable, and records exactly
what happened. Never itself a `findings` row — this is evidence for Stage
5's human to review, and the prioritized candidate list a separate,
human-directed tool (e.g. `sqlmap`) gets handed next.

### `target_environments`

One row per disposable local replica Stage 4.5 stood up (or was pointed at
across CLI calls).

**Why:** `pipeline/stage4_5_dynamic_verify/env_setup.py` automates a real,
multi-step manual process (recompile decompiled source, stand up a
container, start the app) validated by hand in
`tests/searching_for_strings_live_debug_writeup.md` — this table is the
audit trail of exactly which source root, build, and running process a
given probe battery ran against, so a `dynamic_probe_results` row can always
be traced back to precisely what was tested, not just "some local copy at
some point." `app_pid` and `db_container_name` exist specifically so
`teardown_environment()` can find and stop the right process/container
later, across separate CLI invocations (the Python process that started
them has long since exited by teardown time). `app_log_path` is recorded
here — not derived on the fly — because `probes.py` needs to know exactly
which file to read from to capture what the app logged during a specific
request; guessing this from `build_dir` was tried first, but that's the
mechanism, not the actual value in the row (the same reasoning that led
`llm_runs` to store a real reported token count rather than re-deriving an
estimate).

**Why `db_user`/`db_name` are separate columns from `db_container_name`**:
found necessary during implementation, not designed upfront —
`probes.py`'s verify-row lookup (`podman exec <container> psql -U <user> -d
<name> ...`) needs the actual credentials/database name, not just which
container to exec into.

| Column | Type | Description |
|---|---|---|
| `env_id` | INTEGER (PK) | Unique identifier for this environment. |
| `source_root` | TEXT | Decompiled source root used (e.g. `~/BlueBirdSourceCode`). |
| `build_dir` | TEXT | Where the recompiled `.class` files were written. |
| `start_class` | TEXT | The app's actual entry-point class, read from the jar's `META-INF/MANIFEST.MF` — needed because the decompiled jar's own bootstrap loader is unusable (see "Why" below the table in `env_setup.py`'s module docstring, and `tests/searching_for_strings_live_debug_writeup.md` Step 4). |
| `app_host` | TEXT | Where the app is reachable. Always a verified-local hostname — see `guard.py`. |
| `app_port` | INTEGER | Port the app was told to bind via a `--server.port` override (see "Why" below). |
| `app_pid` | INTEGER | PID of the background `java` process, so teardown can find it later. |
| `app_log_path` | TEXT | Where the app's stdout/stderr was redirected. |
| `db_container_name` | TEXT | The disposable Postgres container's name. |
| `db_host` / `db_port` | TEXT / INTEGER | Where that container is reachable. |
| `db_user` / `db_name` | TEXT | Credentials/database `probes.py` needs to query the verify row afterward. |
| `status` | TEXT | Lifecycle state. See factors below. |
| `started_at` / `stopped_at` | TIMESTAMP | When this environment came up / was torn down. |

**`status` factors:**
- `starting` — environment setup in progress.
- `running` — app and DB both confirmed reachable.
- `stopped` — torn down via `teardown_environment()`.
- `failed` — setup didn't complete.

**Why `app_port`/the datasource connection are passed as explicit
overrides, not left to the target's own defaults:** discovered directly
during implementation, not anticipated in the design. `start_app()`
originally just launched the target's classpath with no port or datasource
argument, trusting whatever was hardcoded in the target's own
`application.properties`. The first real test crashed immediately —
`Port 8080 was already in use` — because the target's own default port
collided with an unrelated, already-running instance. Worse, had the ports
not collided, the app would have silently connected to *whichever*
Postgres instance happened to be listening on the hardcoded default port —
possibly the wrong disposable replica entirely, defeating Stage 4.5's whole
guarantee of knowing precisely what a probe battery ran against. Fixed by
passing `--server.port=<app_port>` and
`--spring.datasource.url=jdbc:postgresql://<db_host>:<db_port>/<db_name>`
(plus credentials) as Spring Boot property-override program arguments —
verified for real afterward: a probe-battery signup landed in exactly the
intended container and not a second, coincidentally-identical one running
alongside it.

### `dynamic_probe_batches`

One row per (flagged hypothesis, candidate variable) pair queued for
probing — the unit `dynamic-probe` schedules and skips if already run.

**Why:** Mirrors `trace_queue`'s "scripted work assignment, not an LLM
decision" role one stage later. `source_trace_id` is `NOT NULL` (every
battery must trace back to a real Stage 4 `exploitable_path` row);
`input_source_id` is nullable specifically for second-order candidates that
have no direct `input_sources` row of their own (e.g. `profile`'s `email`,
which is Stage 3's `trace_queue.target_variable` linkage, not a request
parameter `profile` itself declares). `verify_table`/`verify_column` are
human-supplied (via `request-templates.json`), the same trust level as
`env_setup.apply_schema`'s schema file — Stage 4.5 does not infer either
from decompiled source (see `CLAUDE.md`'s Stage 4.5 section).

| Column | Type | Description |
|---|---|---|
| `batch_id` | INTEGER (PK) | Unique identifier for this batch. |
| `source_trace_id` | INTEGER (FK → `trace_results`) | The `exploitable_path` hypothesis this battery verifies. |
| `input_source_id` | INTEGER (FK → `input_sources`, nullable) | The request-param row being probed, if this is a direct (first-order) candidate. |
| `target_param_name` | TEXT | The actual form/query parameter name fired. |
| `env_id` | INTEGER (FK → `target_environments`) | Which disposable replica this battery ran against. |
| `endpoint` / `http_method` | TEXT | Where and how the request is sent. |
| `order_hypothesis` | TEXT | See factors below. |
| `verify_table` / `verify_column` | TEXT | Where to look afterward for the probe's resulting row. |
| `started_at` | TIMESTAMP | When this battery was created. |

**`order_hypothesis` factors:**
- `first_order` — the flagged value comes straight from this method's own request parameters (`trace_queue.target_variable` was `NULL`).
- `second_order` — the flagged value is a stored value read back unsafely elsewhere (`trace_queue.target_variable` was set — reuses Stage 3's already-established linkage rather than re-deriving it).

### `dynamic_probe_results`

One row per individual probe fired within a battery — the actual recorded
evidence: what was tested, what came back.

**Why the fixed four-probe set:** `baseline` (a plain control value, to
confirm normal behavior), `single_quote`, `double_quote`, `backslash` — a
small, versioned, non-attacker-chosen set (see `CLAUDE.md`'s "the probe set
is fixed and versioned, never LLM-chosen"). Real results against
`AuthController.signupPOST`'s `name` parameter: `single_quote` reproduced
the exact `BadSqlGrammarException`/`PSQLException` from
`tests/searching_for_strings_live_debug_writeup.md`'s manual test, while
`double_quote` and `backslash` both classified `passthrough_unmodified` —
correct, not a miss: neither character is special in standard PostgreSQL
string-literal syntax, so this genuinely tells you *which specific
character* matters for this sink, not just "something breaks it."

**Why `classification` checks `error` before `passthrough_unmodified`:** a
request that 500s with a matching exception in the app's own log is a
stronger, more specific signal that the value broke the query than merely
finding the raw value in a row that may not even have been written by this
probe — see `classify.classify_probe()`'s documented priority order.

**A real, discovered limitation, not a hypothetical:** probing
`signupPOST`'s `password`/`repeatPassword` against real BlueBird classified
every probe `rejected` — but real rows *were* inserted each time, with a
real BCrypt hash in the `password` column. `rejected` is the wrong read
here: the value did reach a sink, it just went through a one-way transform
first, so a `LIKE '%nonce%'` lookup against the stored hash can never match
regardless of what was actually accepted. Deterministic classification
cannot currently distinguish "genuinely validated away before any sink"
from "reached a sink but was transformed by a one-way function this method
of verification can't see through" — both look identical from here (no
matching row, a clean response, no error). This is a known, accepted gap in
this pass, not a silent one: anyone authoring a `request-templates.json`
`verify_column` for a field known to be hashed/encoded one-way should read
a `rejected` classification skeptically rather than trust it at face value.

| Column | Type | Description |
|---|---|---|
| `probe_id` | INTEGER (PK) | Unique identifier for this probe result. |
| `batch_id` | INTEGER (FK → `dynamic_probe_batches`) | Battery this probe belongs to. Cascades on delete. |
| `probe_name` | TEXT | Which of the fixed four probes this is. See factors below. |
| `input_value` | TEXT | The exact value sent for this probe. |
| `http_status` | INTEGER | Observed HTTP response status. |
| `response_snippet` | TEXT | Truncated response body. |
| `app_log_snippet` | TEXT | Everything the target logged during this specific request — captured by recording the log's line count immediately before firing and reading everything written after, *not* a fixed-size tail (a fixed 50-line tail was tried first and found to truncate real evidence: a single Spring Security stack trace routinely runs 60-100+ lines, easily pushing the actual exception summary line out of a short fixed window). |
| `db_row_snippet` | TEXT | The `verify_table`/`verify_column` value found afterward, if any. |
| `classification` | TEXT | The deterministic (or local-LLM-assisted) read of what happened. See factors below. |
| `interpreted_by_run_id` | INTEGER (FK → `llm_runs`, nullable) | Set only when an `ambiguous` result went through the local-LLM interpretation pass — never set for the four deterministic classifications. |
| `notes` | TEXT | Free-text notes (e.g. the interpreting model's reasoning, or a parse-failure message). |
| `created_at` | TIMESTAMP | When this probe ran. |

**`probe_name` factors:**
- `baseline` — a plain alphanumeric control value.
- `single_quote` — the value includes a literal `'`.
- `double_quote` — the value includes a literal `"`.
- `backslash` — the value includes a literal `\`.

**`classification` factors:**
- `error` — the application or database visibly broke handling this value.
- `passthrough_unmodified` — the value reached storage/output exactly as sent.
- `transformed` — the value reached storage/output, but in a different form.
- `rejected` — the value never reached storage, and nothing indicates an application fault (see the `password` limitation above for when this reading is unreliable).
- `ambiguous` — the deterministic rules couldn't confidently pick one of the above; resolved (or left as-is on a parse failure) by the local-LLM interpretation pass.

## Stage 5-6 — Human verification + final findings

Only findings with `verified_by_human = 1 AND status = 'confirmed'` should
ever leave the internal DB in an exported report.

### `findings`

The only table a report generator should read from. One row per candidate
finding, pending or after human review.

**Why:** This table is the boundary between "the pipeline's guess" and
"a claim a human is willing to put in front of a client." An unverified LLM
hypothesis reaching a pentest report would be a real false-positive risk in
an actual engagement deliverable, so `verified_by_human`/`status` aren't
just display flags — the combination `verified_by_human = 1 AND
status = 'confirmed'` is a hard export filter (backed by
`idx_findings_status`) that every report generator is expected to apply, and
nothing upstream of this table (triage, audit, trace) is ever allowed to be
read directly by a report.

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
