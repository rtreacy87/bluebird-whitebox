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
Stage 5: Human Verification Gate                     -> findings.verified_by_human
Stage 6: Findings Store                              -> findings (report source of truth)
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
5. Human verification gate and findings export are last — they depend on everything
   upstream being stable.

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

## What NOT to build here

- No autonomous agent loop where the LLM decides its own next action or spawns
  sub-tasks dynamically. Orchestration is deterministic and lives in Python, not
  in a prompt.
- No calls to hosted/external LLM APIs anywhere in this codebase.
- No payload generation, bypass-string generation, or automated request-firing
  against a target application. This tool stops at "here is a mapped, cited
  hypothesis" — exploitation and verification are manual, human-led steps outside
  this codebase.
- No silent fallback that treats an unresolved cross-file call as "no issue" —
  unresolved must always remain a visible, queryable state (`resolved = 0`), never
  collapsed into a clean result.
