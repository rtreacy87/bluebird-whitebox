# CLAUDE.md

Guidance for Claude Code when working in this repository.

## Project Purpose

This is a **white-box source-review recon pipeline** for penetration testing engagements.
It ingests decompiled Java source (starting with Spring Boot / PostgreSQL apps), builds a
deterministic structural index, then uses a **local LLM (WhiteRabbitNeo)** to triage,
audit, and trace potential SQL injection (and related) vulnerabilities.

**This tool is for defensive security assessment recon and mapping.** It does not generate
exploit payloads, bypass strings, or attack code. Its output is a structured findings map —
locations, data flow, and confidence — that a human then verifies against a live system
(via debugger, query logs, or authorized testing). Any request to extend this tool to
auto-generate payloads or perform automated exploitation is out of scope; keep the tool's
job at "map and explain," not "attack."

All source material processed by this tool may be client-confidential. **Nothing in this
pipeline should call an external/hosted API.** Every LLM call must go to a locally-hosted
model endpoint. Treat any code path that reaches out to the network as a bug.

## Architecture Overview

```
Stage 0: Static Index      (deterministic, no LLM)  -> symbols, call_edges, field_access
Stage 1: Triage Pass       (LLM, per-file)           -> triage_results
Stage 2: Audit Pass        (LLM, adversarial)        -> audit_results
Stage 3: Trace Worklist    (deterministic queue)     -> trace_queue
Stage 4: Deep-Trace Pass   (LLM, per-item)           -> trace_results
Stage 4.5: Dynamic Verification Probe (deterministic firing,
           local-only, non-destructive, LLM only for
           ambiguous-result interpretation)          -> dynamic_probe_results
Stage 5: Human Verification Gate                     -> findings.verified_by_human
Stage 6: Findings Store / Report Export (deterministic,
         reads only verified_by_human=1 AND status=
         'confirmed' findings)                       -> report_exports
                                                          + a human-readable report
                                                          + a versioned JSON candidate
                                                            export for sqlmap-wrapper/
                                                            (a separately-governed tool,
                                                            see sqlmap-wrapper/CLAUDE.md)
```

Design principle: **the LLM never decides what to look at next.** All traversal,
chunking, and queueing decisions are deterministic and scripted. WhiteRabbitNeo is
invoked with pre-assembled, bounded context and a fixed task — never given an
open-ended "explore this codebase" instruction. This is intentional given it is not
a highly agentic model; do not refactor toward an autonomous agent loop.

## Build Order (do not reorder without discussion)

1. **Stage 0 — intra-file resolution first.** Build the parser, symbol table, and
   call-graph extraction working within single files only. Cross-file calls are logged
   in `call_edges` with `resolved = 0` and the raw callee name preserved — do not drop
   them, do not attempt to resolve them yet.
2. **Stage 1 + Stage 2 (triage + audit) end-to-end**, validated against the BlueBird
   test corpus (see `~/BlueBirdSourceCode` — do not confuse with `~/bluebird`, see
   Testing section) before adding any new capability. This is the regression gate —
   all three known BlueBird vulnerabilities (`/find-user`, `/forgot`,
   `/profile/{id}`) must be surfaced by the pipeline before other work proceeds.
3. **Stage 3 + Stage 4 (trace queue + deep trace)**, built on top of intra-file
   `call_edges` and `field_access` data only.
4. **Only after 1-3 are working and validated against a second corpus** (Pass2,
   decompiled the same way as BlueBird — see Testing section) should cross-file
   resolution be considered. This is a deliberate, measured decision based on
   observed gaps in `resolved = 0` edges — not a default next step. Do not silently
   start building it.
5. **Stage 4.5 (dynamic verification)**, built only after Stage 1-4 are validated
   against BlueBird (the three known vulnerabilities must already surface as
   `exploitable_path` `trace_results` rows). Validate the environment-automation and
   probe-firing mechanics against a disposable local BlueBird replica (recompiled
   from `~/BlueBirdSourceCode` per `tests/searching_for_strings_live_debug_writeup.md`)
   before trusting this stage against Pass2 or a real engagement target — do not
   assume the recompile/container/probe mechanics generalize to a new target for
   free, the same caution already applied to cross-file resolution above.
6. Human verification gate and findings export are last — they depend on
   everything upstream (now including wherever Stage 4.5 was run) being stable.
   Both are now built: Stage 5's write-side is `pipeline/stage5_verify/logger.py`
   (`log-finding`); Stage 6 is `pipeline/stage6_report/` (`export-report`), see
   "Reporting (Stage 6)" below.

## Database

SQLite. Schema lives in `schema.sql` — treat it as the source of truth for table
structure; do not add columns or tables ad hoc in application code without updating
the schema file first.

Key invariants to preserve:
- Stage 0 tables (`files`, `symbols`, `call_edges`, `field_access`, `input_sources`)
  are **ground truth**. Nothing derived from an LLM call may write to these tables.
- Every LLM-derived table (`triage_results`, `audit_results`, `trace_results`) must
  carry a `run_id` foreign key back to `llm_runs`, which records `model_name` and
  `prompt_version`. Never write LLM output without this provenance.
- `triage_results.symbol_id` may be NULL with `symbol_name_raw` populated instead —
  this is intentional and is what makes hallucination detection possible via a join
  against `symbols`. Do not "fix" this by forcing a symbol_id match.
- Coverage must always be computable as a **query** (LEFT JOIN symbols against
  triage_results/trace_queue), never as a stored/self-reported percentage field.
- `findings` is the only table a report generator should read from, and only rows
  with `verified_by_human = 1 AND status = 'confirmed'` should ever leave the
  internal DB in an exported report.

## Prompt Templates

Prompt templates live in `/prompts/` and are versioned by filename
(`triage_v1.txt`, `audit_v1.txt`, `trace_v1.txt`). When a template is edited,
increment the version — do not overwrite in place, since `llm_runs.prompt_version`
must remain resolvable to an exact historical template for audit purposes.

Prompt requirements (do not weaken these when editing):
- **Triage** must enumerate a fixed checklist (input sources, sink type incl. safe
  parameterized queries as a first-class category, validation description, indirect
  flow flag, confidence) and must require a row for every method reviewed, including
  "clean" ones. Silence on a method is not an acceptable output shape.
- Triage and trace prompts must explicitly instruct the model **not** to suggest
  payloads or bypass techniques — the task is describing data flow and sink type,
  not producing exploitation guidance.
- **Audit** must be a separate invocation from triage (do not let a single call both
  triage and grade itself), and must compare against Stage 0's symbol list, not
  against the model's own re-derivation of the file's contents.
- **Trace** prompts must only reason over the context explicitly assembled and
  provided by the Stage 3 graph walk — instruct the model not to speculate about
  files it hasn't been shown.

## Local Model Runtime

- **Ollama is the inference runtime for this project.** All LLM calls go through
  Ollama's local API (default `http://localhost:11434`) — not llama.cpp directly,
  not an OpenAI-compatible wrapper, not any hosted endpoint. If a library or code
  pattern assumes a different runtime, stop and flag it rather than silently adapting.
- **Why Ollama over calling llama.cpp/`llama-server` directly** (evaluated, not
  just assumed): Ollama's own inference engine is a llama.cpp/ggml fork, so there
  is no correctness or output-quality difference between the two at the model
  level — this is a choice about operational surface area, not capability.
  Ollama wins on that basis for this project: it owns model lifecycle (load/unload,
  GPU/CPU offload heuristics, keep-alive) so the pipeline doesn't need to supervise
  a long-running `llama-server` process itself, and its tag registry (`ollama list`,
  `ollama create` from a Modelfile) is what `llm_runs.model_name` provenance and the
  "confirm the exact tag" rule below are built on. Concretely: don't expect a
  runtime switch to fix output-formatting reliability problems (e.g. a model
  continuing to emit prose after a structurally complete JSON value) — that's a
  general property of grammar-constrained decoding, present in both engines since
  they share the same grammar mechanism, not an Ollama-specific defect. Parse
  defensively (see `json.JSONDecoder().raw_decode` usage in
  `pipeline/stage1_triage/triage.py` / `pipeline/stage2_audit/audit.py`) regardless
  of runtime, rather than assuming a runtime change would make whole-string
  `json.loads` safe.
- Use the official `ollama` Python library for calls where practical
  (`ollama.chat(...)` / `ollama.generate(...)`), falling back to direct HTTP calls
  against the Ollama REST API only where the library doesn't expose needed options
  (e.g. specific context-length overrides).
- **Model tag**: confirm the exact tag as it appears in `ollama list` before wiring
  it into `llm_runs.model_name` — do not assume the name is literally
  `whiterabbitneo`; if it was imported via a custom Modelfile it may have a
  different local tag. `llm_runs.model_name` must record this exact tag string so
  results are reproducible against the same model build later.
- Context length: Ollama defaults to a much smaller context window (commonly 2048
  or 4096 tokens) than a model's actual maximum unless explicitly overridden via the
  `num_ctx` parameter (either in the request options or in a custom Modelfile).
  **This must be set explicitly and match the value used in the context-window
  benchmark** (`/bench/context_benchmark.py`) — a mismatch here would silently
  reintroduce the truncation problem the audit layer is designed to catch.
- Keep Ollama bound to localhost only (default behavior) — do not expose it on a
  network interface as part of this project's setup.

- Never assume the marketed context window is the effective one. Effective context
  should be established empirically (see `/bench/context_benchmark.py`) using a
  known-ground-truth file before being trusted in the pipeline.
- Chunk by parser-verified method boundary only — never split a file by raw token
  count. If a file must be chunked, include the last method of the previous chunk
  again at the start of the next (overlap) so boundary-adjacent logic isn't reviewed
  with a truncated view.
- Any file whose token count exceeds the benchmarked safe threshold must be routed
  to forced multi-chunk review, even if it would technically fit under the model's
  stated max.
- Log `chunk_index` / `chunk_total` on every `llm_runs` row so any result is
  traceable back to exactly which slice of the file produced it.

## Dynamic Verification (Stage 4.5)

Stage 4.5 turns a Stage 4 `exploitable_path` hypothesis into evidence: it
stands up a disposable local copy of the target, fires a small, fixed,
non-destructive battery of "interpretation probes" at each flagged
candidate variable, and records exactly what happened. It exists to produce
a prioritized, evidence-backed candidate list for a human to hand to a
separate, human-directed tool (e.g. `sqlmap`) — not to redo that tool's job
itself.

**Hard local-only guardrail.** Every code path that fires an HTTP request or
opens a database connection for Stage 4.5 must call
`pipeline/stage4_5_dynamic_verify/guard.py`'s `validate_local_target()`
before doing anything else — the same enforcement pattern as
`pipeline/llm/ollama_client.py`'s `_validate_local_host()`. This pipeline
never fires a probe, of any kind, at a hostname outside
`{"localhost", "127.0.0.1", "::1"}`. Treat any code path that would reach a
non-local target as a bug, exactly as this document already treats a
non-local Ollama call.

**The probe set is fixed and versioned, never LLM-chosen.** Consistent with
"the LLM never decides what to look at next" above: Stage 4.5 always fires
the same four probes per candidate variable — `baseline`, `single_quote`,
`double_quote`, `backslash` — defined once in
`pipeline/stage4_5_dynamic_verify/probes.py`. If the probe set itself needs
to change, that's a deliberate, versioned code change, never a per-run
model decision.

**In scope:** firing the fixed probe set at a single candidate request
parameter (one battery per `trace_results`/candidate-variable pair);
observing HTTP status, response body, the target's own app log, and the
resulting database row; deterministic classification (`error`,
`passthrough_unmodified`, `transformed`, `rejected`, with `ambiguous`
resolved via the existing local Ollama `LLMRunner` — never a hosted model,
never the raw probe-firing path itself); deterministic first-order/
second-order tagging reusing Stage 3's `trace_queue.target_variable` linkage.

**Explicitly out of scope (this is not sqlmap, and isn't trying to be):**
no UNION-based extraction, no boolean-blind or time-blind oracles, no
stacked queries, no authentication bypass, no payload/bypass-string
generation of any kind. Stage 4.5 answers "does an ordinary metacharacter
survive unescaped to the sink" — not "can I extract data" or "can I bypass
a filter."

**Standing up a local replica is scoped to BlueBird first, like everything
else here.** `pipeline/stage4_5_dynamic_verify/env_setup.py` automates the
exact manual process validated in
`tests/searching_for_strings_live_debug_writeup.md` (recompile the
decompiled source with `javac --release <N> -g -parameters`, read
`Start-Class` from the jar's manifest, run the app directly via classpath, a
disposable rootless Podman Postgres container for the DB). This automates
*re-running* against a target already worked out this way once — it does
not solve, for an arbitrary new target, either of two problems a human must
still handle: (1) producing a minimal DB schema (there is no
`schema.sql`-equivalent shipped with decompiled source — a human reads the
target's own `SELECT`/`INSERT` statements, exactly as was done for
BlueBird's `users` table), or (2) knowing the request shape a given
endpoint needs (its route, HTTP method, and the other same-request
parameters a candidate variable's sibling fields require, e.g. `signupPOST`
needing `username`/`email`/`password`/`repeatPassword` alongside whichever
parameter is being probed). Both are supplied by a human as explicit input
(a schema file, a request-template JSON file) — Stage 4.5 does not infer
either from decompiled source. Treat this the same way cross-file
resolution is treated: validate against BlueBird first, do not assume it
generalizes to an arbitrary new target for free.

**Why the interpretation pass, specifically, must be local-model-only.** Any
code path (in Stage 4.5's `interpret.py`) that has to make an interpretive
judgment call on an ambiguous probe result must go through the existing
`LLMRunner`/Ollama path — the same "nothing in this pipeline should call an
external/hosted API" rule this document already states, applied to Stage
4.5's one judgment-requiring step. The raw HTTP request/response mechanics
and the deterministic classification rules need no model at all — this
mirrors Stage 3's deterministic graph walk vs. Stage 4's LLM judgment split
above.

## Reporting (Stage 6)

Stage 6 (`pipeline/stage6_report/`, `export-report` CLI command) is
deterministic — it reads `findings` and renders it, it never queries an
LLM, and it never decides which rows count as reportable. Per "Database"
above, the one hard rule this stage exists to enforce is: **only rows with
`verified_by_human=1 AND status='confirmed'` ever leave the DB** in any
exported format. `pipeline/stage6_report/query.py`'s
`assemble_finding_records()` is the single query both renderers below read
from — there is exactly one place this filter is applied, not two
independently-maintained guesses at the same rule.

Two output formats, both provenance-tracked in `report_exports`:
- **`--format markdown`**: a human-readable report for the engagement
  writeup — one section per finding, with triage/trace narrative and
  Stage 4.5 dynamic-probe evidence (a per-parameter classification table)
  when available.
- **`--format sqlmap-json`**: a versioned JSON export
  (`schema_version: "sqlmap_candidate_v1"`, documented in
  `pipeline/stage6_report/schemas/sqlmap_candidate_v1.schema.json`) — the
  input contract for `sqlmap-wrapper/`, a separate, separately-governed
  tool (see `sqlmap-wrapper/CLAUDE.md`) that this repo's own "no automated
  exploitation" rule already reserves sqlmap for. This export is
  deliberately narrowed to parameters Stage 4.5 already showed reactive
  (`error`/`transformed` classifications) — a finding with no such evidence
  still exports as one candidate with `target_param_name: null` and a
  human-actionable note, never silently dropped.

**Bump `render_sqlmap_json.SCHEMA_VERSION` (and add a new versioned sibling
schema file, never edit the old one in place) if this export's shape ever
changes** — `sqlmap-wrapper/` validates against this exact contract by
hand (no shared library dependency), so a silent shape change on one side
would break the other without either test suite noticing.

## Testing

- **`~/BlueBirdSourceCode`** — primary regression corpus. This is the decompiled
  BlueBird source (already extracted from `BlueBird-0.0.1-SNAPSHOT.jar`; contains
  `BOOT-INF`, `META-INF`, `org`, and the jar itself). Java source lives under
  `~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird/`. Ground truth (the
  three known vulnerabilities and their locations) should be documented in
  `EXPECTED_FINDINGS.md` at the repo root (not inside the source tree, since that
  tree is a read-only decompiled artifact and shouldn't be mixed with pipeline
  metadata). Any change to Stage 0-2 must be run against this corpus before being
  considered done.
- There is also a `~/bluebird` directory (lowercase) present in the home
  directory — **do not assume this is the same thing as `~/BlueBirdSourceCode`**.
  Confirm its contents before treating it as a data source; it may be an unrelated
  project/notes directory rather than decompiled source. When in doubt, ask rather
  than guessing which one a task refers to.
- Pass2 corpus: `~/opt/Pass2` per the module (`Pass2-1.0.3-SNAPSHOT.jar`), used to
  check generalization once the pipeline is stable against BlueBird. If not yet
  present locally, decompiling it follows the same Fernflower process as BlueBird.
  Ground truth here is intentionally *not* pre-documented in this repo — findings
  from Pass2 should be verified by the human-in-the-loop process, not hardcoded as
  an oracle.
- Treat all paths under the user's home directory as **read-only inputs** unless a
  task explicitly says to write there. Pipeline-generated artifacts (the SQLite DB,
  logs, exported findings) belong in this repo's own working directory, not
  scattered into `~`.
- Structural completeness (Layer A audit) must be checked with a deterministic
  parser-based method count compared against triage row count — implement this as
  an actual test assertion, not a manual read of output.
- Stage 4.5 (dynamic verification) must be validated against a disposable,
  locally-running copy of BlueBird — reusing
  `tests/searching_for_strings_live_debug_writeup.md`'s manual process, now
  automated by `pipeline/stage4_5_dynamic_verify/env_setup.py` — before
  being trusted against Pass2 or a real engagement target. Gate any test
  that actually fires a probe or stands up a container behind
  `RUN_DYNAMIC_TESTS=1`, the same pattern `RUN_LLM_TESTS=1` already
  establishes for tests that need a real Ollama call.

## What NOT to build here

- No autonomous agent loop where the LLM decides its own next action or spawns
  sub-tasks dynamically. Orchestration is deterministic and lives in Python, not
  in a prompt.
- No calls to hosted/external LLM APIs anywhere in this codebase.
- No payload generation, bypass-string generation, or automated exploitation
  technique — no UNION-based extraction, no boolean/time-blind oracles, no
  stacked queries, no auth bypass — against any target, local or otherwise.
  The one narrow exception is Stage 4.5's fixed, versioned probe battery
  (baseline / single-quote / double-quote / backslash), which only ever fires
  against a verified-local disposable replica the pipeline itself stood up
  (see "Dynamic Verification (Stage 4.5)" above) and exists purely to turn a
  static hypothesis into an evidence-backed, prioritized candidate list for a
  human to hand to a separate, human-directed tool (e.g. sqlmap) — it does
  not itself perform exploitation, and it never resembles an actual
  injection technique. Outside that one exception, this tool stops at "here
  is a mapped, cited hypothesis" — exploitation and verification remain
  manual, human-led steps outside this codebase.
- No silent fallback that treats an unresolved cross-file call as "no issue" —
  unresolved must always remain a visible, queryable state (`resolved = 0`), never
  collapsed into a clean result.
