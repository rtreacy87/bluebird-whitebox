# Architecture

How the pieces fit together, for anyone reading the code or extending it.
`CLAUDE.md` is the authoritative *spec* (what must be true, and why); this
document is the *map* of how the current implementation satisfies that spec.
If the two ever disagree, `CLAUDE.md` wins and this file needs updating.

## Design philosophy in one paragraph

All control flow -- which file gets read, how it gets split up, what gets
written where, what counts as "done" -- is plain deterministic Python. The
LLM is only ever handed a bounded, pre-assembled chunk of text and a fixed
task ("answer this checklist for these methods"); it never decides what to
look at next, never sees the whole codebase at once, and never writes
directly to the "ground truth" tables. Every LLM call is recorded with
exactly which model and prompt version produced it. This is why the system
is a *pipeline* of scripted stages rather than an agent loop.

## Stage diagram

```
                    ┌─────────────────────────────────────────────┐
                    │  Stage 0 -- Static Index (deterministic)     │
  .java files ─────▶│  pipeline/stage0_index/                     │
                    │  parser.py (pure) + indexer.py (DB writer)   │
                    └───────────────────┬───────────────────────--┘
                                         │ writes: files, symbols,
                                         │ call_edges, field_access,
                                         │ input_sources
                                         ▼
                    ┌───────────────────────────────────────────---┐
                    │  Stage 1 -- Triage (LLM, per file/chunk)      │
                    │  pipeline/stage1_triage/triage.py             │
                    │  prompts/triage_v1.txt                        │
                    └───────────────────┬────────────────────────--┘
                                         │ reads: symbols, files
                                         │ writes: triage_results,
                                         │         llm_runs
                                         ▼
                    ┌────────────────────────────────────────────--┐
                    │  Stage 2 -- Audit (LLM, adversarial)          │
                    │  pipeline/stage2_audit/audit.py               │
                    │  prompts/audit_v1.txt                         │
                    └───────────────────┬────────────────────────--┘
                                         │ reads: symbols, call_edges,
                                         │        input_sources, triage_results
                                         │ writes: audit_results, llm_runs
                                         ▼
              ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
                NOT YET BUILT (see CLAUDE.md build order -- deliberately
                gated behind validated Stage 0-2, not a missing feature)

                Stage 3 -- Trace Worklist   (deterministic queue)
                Stage 4 -- Deep-Trace Pass  (LLM, per queue item)
                Stage 5 -- Human Verification Gate
                Stage 6 -- Findings Store / report export
              ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
```

Everything left of that dashed line is implemented and validated against the
BlueBird corpus. Everything right of it is spec'd in `CLAUDE.md` but
intentionally not started -- also note **cross-file call resolution** isn't
built either; Stage 0 only resolves calls within a single file (see
"Known boundaries" below).

## Directory map

```
pipeline/
  db.py                  connect(path) -> sqlite3 connection, initializes
                          schema.sql on first use. Every stage goes through
                          this; nothing else touches sqlite3 directly.
  config.py               SAFE_CONTEXT_TOKENS_HEURISTIC, DEFAULT_NUM_CTX --
                          constants that must trace back to bench/
                          context_benchmark.py, never a guess.
  cli.py                  argparse entrypoint: index / triage / audit /
                          coverage subcommands. Thin -- just wires args to
                          the stage modules below.

  stage0_index/
    parser.py             Pure function: java source text in, ParsedFile
                          (symbols/call_edges/field_access/input_sources as
                          plain dataclasses) out. No DB, no I/O beyond
                          reading the string it's given. javalang-based.
    indexer.py             Walks a source tree, sha256-fingerprints each
                          file, calls parser.py, writes results into the
                          DB. Owns the "only re-parse changed files" logic.
    tokenizer.py            estimate_token_count() -- offline heuristic
                          (regex-based), used only for chunking decisions
                          since Stage 0 has no LLM access to ask a real
                          tokenizer.

  llm/
    ollama_client.py        OllamaClient (wraps the `ollama` library,
                          enforces localhost-only, verifies the model tag
                          exists), LLMRunner (wraps a call + writes the
                          matching llm_runs provenance row in one place so
                          no call site can forget to record it).
    chunking.py              build_chunks(): method-boundary splitting with
                          overlap, using symbols table line ranges as the
                          only source of truth for where a method starts
                          and ends -- never raw token/character counts.

  stage1_triage/triage.py   Orchestrates Stage 1: for each file, build
                          chunks, call LLMRunner, parse the JSON response,
                          resolve each claimed method name back to a
                          symbol_id (or leave it NULL), synthesize
                          placeholder rows for any method the model
                          silently dropped.

  stage2_audit/audit.py     Orchestrates Stage 2: computes structural
                          matched/hallucinated/missing/ambiguous status in
                          plain Python (never LLM-derived), then makes a
                          *separate* LLM call fed only Stage 0's structured
                          facts (never raw source) to adversarially compare
                          against Stage 1's claims.

prompts/
  triage_v1.txt, audit_v1.txt   Versioned system prompts. CLAUDE.md's rule:
                          edit by incrementing the version suffix, never
                          overwrite in place -- llm_runs.prompt_version must
                          always resolve to an exact historical prompt.

bench/context_benchmark.py    Standalone script, not part of the pipeline
                          proper. Needle-in-haystack test that empirically
                          derives SAFE_CONTEXT_TOKENS_HEURISTIC /
                          DEFAULT_NUM_CTX in pipeline/config.py.

schema.sql                 Source of truth for DB structure. Every stage's
                          writes must match this exactly -- application
                          code never ALTERs or invents columns.

tests/
  test_stage0_bluebird.py        Fast, no LLM. Runs the real parser/indexer
                          against ~/BlueBirdSourceCode and asserts
                          structural invariants (entrypoints found, calls
                          resolved correctly, idempotent re-index, etc).
  test_stage1_2_bluebird.py       Slow, drives real Ollama calls (~15 min).
                          Gated behind RUN_LLM_TESTS=1 so a normal `pytest`
                          run doesn't trigger it. This is the automated
                          form of CLAUDE.md's "must be run against BlueBird
                          before Stage 0-2 changes are done" rule.
```

## The database is the integration contract

Stages don't call each other's Python functions or pass data structures
directly -- **the only thing one stage hands the next is rows in
`data/recon.db`**, structured exactly per `schema.sql`. This is deliberate:
it means each stage can be re-run independently, inspected with a plain
`sqlite3` query, and re-run against a fixed input from an earlier stage
without re-running everything upstream of it.

```
files ──┬─▶ symbols ──┬─▶ call_edges         (Stage 0, all deterministic,
        │             ├─▶ field_access        "ground truth" -- no LLM
        │             └─▶ input_sources        output ever writes here)
        │
        └─▶ llm_runs ◀────────────────┬── every LLM call, any stage,
             │                         │   records model_name/prompt_version/
             │                         │   chunk position/real token count here
             ▼                         │
        triage_results ────────────────┘
             │        (symbol_id nullable on purpose --
             │         see "Hallucination detection" below)
             ▼
        audit_results
             (audited_run_id points back at the triage llm_runs row
              being checked; run_id points at the audit's own llm_runs row --
              two different provenance links on one row, on purpose)
```

## What happens on one `triage` call, step by step

Tracing `pipeline.cli triage` end to end, because this is the shape every
future LLM-driven stage (Stage 4's deep-trace, if/when it's built) will
follow too:

1. `cli.py` builds an `OllamaClient`, calls `verify_model_available()`
   (queries `ollama list` equivalent -- fails loudly if the `--model` tag
   isn't actually present, rather than recording a wrong tag).
2. `triage_all_files()` reads every row from `files`, and for each one calls
   `triage_file()`.
3. `triage_file()` reads that file's `class`/`field`/`method` rows from
   `symbols` -- **not the source file's text directly for structure**, only
   for the literal characters of each method body (line ranges come from
   Stage 0, already-parsed).
4. `chunking.build_chunks()` decides, using `files.token_count` and
   `SAFE_CONTEXT_TOKENS_HEURISTIC`, whether the whole file fits in one
   request or needs splitting at method boundaries (with the last method of
   chunk N repeated at the start of chunk N+1).
5. For each chunk: `LLMRunner.run()` sends the system prompt
   (`prompts/triage_v1.txt`) + the assembled chunk text to Ollama with
   `format="json"`, a bounded `num_predict`, `temperature=0`, and the
   configured `num_ctx`. It inserts the `llm_runs` row (model, prompt
   version, chunk index/total, and the *real* token count Ollama reports)
   in the same call, so a run and its provenance can never get out of sync.
6. The response is parsed defensively (`json.JSONDecoder().raw_decode` --
   see "A grammar-decoding gotcha" below), one row inserted into
   `triage_results` per method the model answered about.
7. Any method Stage 0 said should be in this chunk, but the model's response
   didn't mention, gets a synthesized placeholder row
   (`confidence='low'`, a note explaining it was synthesized) -- coverage
   completeness is enforced by code, not by trusting the prompt was obeyed.

`audit_file()` follows the same shape, with one structural difference: step
3 doesn't hand the model any source text at all, only already-extracted
Stage 0 facts (input-source presence, keyword-flagged callee names) plus
Stage 1's claims -- see `pipeline/stage2_audit/audit.py`'s module docstring
for why that separation matters.

## Key design decisions (and why)

**Hallucination detection via nullable `symbol_id`.** `triage_results` keeps
both `symbol_id` (nullable, resolved by the pipeline) and `symbol_name_raw`
(whatever string the model actually said) as separate columns. The pipeline
deliberately does *not* fuzzy-match a not-quite-right name to "the closest"
real symbol -- if `symbol_id` is NULL, that's a real signal (either the name
doesn't exist in this file at all, i.e. a hallucination, or it matches more
than one same-named overload and can't be disambiguated). Forcing a match to
make the number look cleaner would destroy this signal. `audit_results`
turns this into an explicit status per row: `hallucinated_row` (no match),
`ambiguous` (multiple matches), `matched` (exactly one), or
`missing_from_table` (a real symbol with zero triage rows).

**Method-boundary chunking with overlap, never raw token splitting.** A
prompt is only ever cut between two complete methods, never mid-method, and
the last method of the previous chunk is repeated verbatim at the start of
the next one. This means a method that references something explained at
the very end of the previous chunk doesn't get reviewed with half its
context missing.

**Two genuinely separate LLM calls for triage vs. audit**, not one call
asked to both review and grade itself. `audit_file()` opens its own
`llm_runs` row via a fresh `LLMRunner.run()` invocation; it never reuses
triage's `run_id` for its own output. And audit is fed Stage 0's
already-extracted facts, not the raw file -- so its "does this claim look
right" judgment is checked against ground truth, not against its own
independent re-reading of the source (which could hallucinate all over
again and just agree with itself).

**A grammar-decoding gotcha, and why parsing is defensive everywhere.**
Ollama's `format="json"` (and llama.cpp's underlying GBNF grammar mechanism
generally, since Ollama's engine is a llama.cpp/ggml fork -- see
`CLAUDE.md`'s "Local Model Runtime" section) constrains the model to
*produce* valid JSON, but does not force it to *stop* the moment that JSON
value is complete -- a model can and does keep emitting prose afterward.
`json.JSONDecoder().raw_decode()` is used everywhere a model response is
parsed specifically because it reads just the first complete JSON value and
ignores anything trailing after it, instead of failing on `json.loads()`
over the whole string. Any new stage that parses model output should reuse
this pattern rather than assuming the whole response string is clean JSON.

**Every generation call has `num_predict` bounded.** An uncapped call was
observed, during development, to ramble for 10+ minutes on a two-method file
instead of stopping once it had answered. `num_predict` is scaled to the
number of methods in the current chunk (`pipeline/stage1_triage/triage.py`,
`pipeline/stage2_audit/audit.py`) rather than a single fixed constant, so
small files stay fast and large chunks still get enough room to answer
every method.

## Known boundaries (not bugs -- deliberate scope limits)

- **Cross-file call resolution isn't built.** `call_edges.resolved` is only
  ever `1` when the caller and callee are both defined in the *same file*
  Stage 0 just parsed. A call into another file, or into a framework class
  like `JdbcTemplate`, is recorded with `resolved=0` and the raw callee name
  preserved -- never silently dropped, never guessed at. Per `CLAUDE.md`,
  this is deliberately not started until Stage 0-2 are validated against a
  second corpus (Pass2) and a measured gap in `resolved=0` edges justifies
  it -- not a default next step.
- **No multi-step data-flow tracing yet.** Stage 1 can tell you a specific
  method contains an unsafe sink, but it reasons about that one method in
  isolation. A vulnerability where attacker-controlled data is stored in one
  method and read back unsafely in a completely different method (a
  "second-order" pattern -- see `EXPECTED_FINDINGS.md`'s `/profile/{id}`
  writeup for BlueBird's real example of this) is exactly what Stage 3/4 are
  designed to eventually automate; today a human has to trace that chain by
  hand. `triage_results.needs_trace` is Stage 1's own best-effort flag for
  "this might be one of those," but it's a hint, not a guarantee -- see
  `WALKTHROUGH.md`'s interpretation section for a real example of that flag
  being set incorrectly.
- **`triage`/`audit` re-process every file on every run.** There's no
  "only re-process files whose Stage 0 fingerprint changed since the last
  triage run" logic yet, unlike `index`, which is fully incremental. On a
  large codebase this means re-running `triage` after a small source change
  currently costs the same as the first full run.

## Extending this

**Adding a new prompt version** (e.g. `triage_v2.txt`): add the new file to
`prompts/`, bump `PROMPT_VERSION` in the relevant stage module, leave the
old prompt file in place (don't overwrite `triage_v1.txt`) so old
`llm_runs` rows stay resolvable to the exact prompt that produced them.

**Adding Stage 3 (trace worklist)**: per `CLAUDE.md`, this stage's queueing
logic must be deterministic Python (a graph walk over `call_edges` /
`field_access`), not an LLM decision. It reads `triage_results` rows where
`needs_trace = 1` and writes `trace_queue` rows (schema already defined in
`schema.sql`); no existing table's write-side needs to change. Model it
after `stage1_triage`/`stage2_audit`'s existing shape: a pure
orchestration module, one `LLMRunner` call per queue item for Stage 4,
`llm_runs` provenance on every call, defensive JSON parsing.

**Swapping the model**: no code changes needed -- `--model <tag>` on any CLI
command. Re-run `bench/context_benchmark.py` against the new model first
(see `README.md`) and update `pipeline/config.py` if the recommended safe
threshold differs meaningfully; those constants must trace back to an actual
benchmark run for the model in use, not be copied from WhiteRabbitNeo's
numbers.
