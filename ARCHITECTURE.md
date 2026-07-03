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
                    ┌────────────────────────────────────────────--┐
                    │  Stage 3 -- Trace Queue (deterministic,       │
                    │             graph walk, no LLM)               │
                    │  pipeline/stage3_trace/builder.py             │
                    └───────────────────┬────────────────────────--┘
                                         │ reads: triage_results, call_edges,
                                         │        input_sources, symbols
                                         │ writes: trace_queue
                                         ▼
                    ┌────────────────────────────────────────────--┐
                    │  Stage 4 -- Deep-Trace (LLM, per queue item)  │
                    │  pipeline/stage4_deep_trace/deep_trace.py     │
                    │  prompts/trace_v1.txt                         │
                    └───────────────────┬────────────────────────--┘
                                         │ reads: trace_queue, symbols, files
                                         │ writes: trace_results, llm_runs,
                                         │         trace_queue.status
                                         ▼
              ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
                NOT YET BUILT (see CLAUDE.md build order -- deliberately
                gated behind validated Stage 0-4, not a missing feature)

                Stage 5 -- Human Verification Gate
                Stage 6 -- Findings Store / report export
              ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄
```

Everything left of that dashed line is implemented and validated against the
BlueBird corpus (Stage 3/4's validation run: `enqueue-trace` produced 17
`trace_queue` rows from the corpus's 17 `sink_type='sql_unsafe'` triage rows,
and a full `trace` pass correctly traced all three regression vulnerabilities
-- `/find-user`, `/forgot`, `/profile/{id}` -- as `exploitable_path`; see
"Known boundaries" below for what that run also revealed about Stage 4's
reliability). Everything right of the dashed line is spec'd in `CLAUDE.md`
but intentionally not started -- also note **cross-file call resolution**
isn't built either; Stage 0 only resolves calls within a single file, and
Stage 3's graph walk is intra-file-only for the same reason (see "Known
boundaries" below).

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
                          enqueue-trace / trace / coverage subcommands. Thin
                          -- just wires args to the stage modules below.

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

  stage3_trace/builder.py   Orchestrates Stage 3: no LLM call at all. Reads
                          every `triage_results` row with
                          `sink_type='sql_unsafe'` (deliberately not gated
                          on `needs_trace` -- see "Known boundaries" below)
                          and, per row, deterministically walks (a) any
                          `call_edges` already resolved intra-file and (b) a
                          same-file getter-name-matching heuristic (e.g. a
                          call to `user.getEmail()` in one method is matched
                          against another same-file method's
                          `input_sources.param_name = 'email'`) to assemble
                          `trace_queue.assembled_context_symbol_ids` -- the
                          bounded context Stage 4 is allowed to see.

  stage4_deep_trace/deep_trace.py   Orchestrates Stage 4: for each `pending`
                          `trace_queue` row, slices the source of every
                          symbol in `assembled_context_symbol_ids` (never
                          anything outside that set), calls `LLMRunner` with
                          `prompts/trace_v1.txt`, defensively parses the
                          JSON verdict, filters `evidence_symbol_ids` down to
                          only IDs actually shown to the model (never
                          trusted unfiltered), and updates
                          `trace_queue.status` to `done` or `blocked`.

prompts/
  triage_v1.txt, audit_v1.txt, trace_v1.txt   Versioned system prompts.
                          CLAUDE.md's rule: edit by incrementing the version
                          suffix, never overwrite in place --
                          llm_runs.prompt_version must always resolve to an
                          exact historical prompt.

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
  test_stage3_4_bluebird.py       Two tiers in one file: a fast deterministic
                          tier (no Ollama -- real Stage 0 parse output plus
                          hand-inserted `triage_results` rows, asserting the
                          builder's graph walk finds the right same-file
                          links) and a RUN_LLM_TESTS=1 tier (full Stage 0-4
                          run, ~30+ min, asserting the three known
                          vulnerabilities trace as `exploitable_path`).
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
             ├──────────────────────────▶ audit_results
             │       (audited_run_id points back at the triage llm_runs row
             │        being checked; run_id points at the audit's own
             │        llm_runs row -- two provenance links on one row)
             │
             ▼ (Stage 3: WHERE sink_type='sql_unsafe', deterministic)
        trace_queue ──▶ trace_results
             (assembled_context_symbol_ids is Stage 3's graph walk output;
              Stage 4 may only cite evidence_symbol_ids from within it)
```

## What happens on one `triage` call, step by step

Tracing `pipeline.cli triage` end to end, because this is the shape Stage
4's `trace` call follows too (see "Stage 3 then Stage 4, step by step"
below for where that shape diverges):

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

## Stage 3 then Stage 4, step by step

`enqueue-trace` (Stage 3) has no `--model`/`--host` -- it's pure Python and
never touches Ollama:

1. `enqueue_trace_targets()` selects every `triage_results` row with
   `sink_type='sql_unsafe'` not already enqueued (idempotent re-run). If a
   row's `symbol_id` is NULL (a hallucinated triage row -- nothing to walk),
   it's enqueued directly as `status='blocked'` with an empty context.
2. For every other row, `assemble_context()` starts with the target
   method's own `symbol_id`, adds any `call_edges` already `resolved=1`
   (real intra-file method-to-method calls), then scans the target's own
   `call_edges.callee_raw_name` for a getter pattern (`user.getEmail` ->
   property `email`) and looks for *other* same-file methods whose
   `input_sources.param_name` matches that property AND whose own
   `sink_type='sql_unsafe'` -- a same-file, deterministic stand-in for
   "where might this value have been written."
3. The result (a JSON array of symbol_ids, plus the matched property name as
   `target_variable` if the heuristic fired) is written to one
   `trace_queue` row, `status='pending'`.

`trace` (Stage 4) then behaves like `triage`/`audit`: for each `pending`
`trace_queue` row, it fetches only the symbols listed in
`assembled_context_symbol_ids` (all guaranteed same-file, by construction of
step 2 above), slices their source by `line_start`/`line_end`, and sends
Ollama the Stage 1 origin claim + those method bodies via
`prompts/trace_v1.txt`. The response's `evidence_symbol_ids` are filtered
down to whatever subset of the shown symbols the model actually cited --
never trusted unfiltered, same defensive posture as everywhere else in this
pipeline. `trace_queue.status` becomes `done`, or `blocked` if the verdict
is `insufficient_context` (meaning the model itself reported it would need
something outside what Stage 3 could assemble intra-file).

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
- **`needs_trace` is not used to gate Stage 3's queue -- it's empirically
  unreliable.** `ProfileController.profile` is one of the three regression
  vulnerabilities (`/profile/{id}`, second-order SQLi) and triage correctly
  flagged it `sink_type='sql_unsafe'`, but set `needs_trace=0` even though
  the unsafe value (`user.getEmail()`) is a textbook case of that flag's own
  definition (came from a queried object, not the method's own parameter).
  Because of this, Stage 3 enqueues every `sink_type='sql_unsafe'` row
  regardless of `needs_trace` -- treating the flag as informational only,
  never as a filter that could silently drop a real regression case.
- **Second-order tracing works, but only intra-file.** Stage 3's
  getter-name-matching heuristic correctly links `ProfileController.profile`
  (reads `user.getEmail()`) to `ProfileController.editProfilePOST` (writes
  raw `email`) because both live in the same file. It would **not** find
  `AuthController.signupPOST` -- the *other* real write site for `email` --
  because that's a different file, and per `CLAUDE.md`'s build order,
  cross-file resolution is a deliberately deferred, separate decision. This
  is a known, accepted gap, not a bug: Stage 3 does not attempt to bridge it
  by guessing.
- **One verdict per queued item, not per concatenated variable.** A method
  can concatenate several variables into one unsafe query where only some
  are actually exploitable (see `tests/searching_for_strings_pipeline_writeup.md`:
  `AuthController.signupPOST` concatenates `name`/`username`/`email`
  (exploitable) and `passwordHash` (not, since it's BCrypt output) into one
  INSERT). `trace_results.verdict` is still one structured value per
  `trace_queue` row -- that per-variable nuance can only live in the
  free-text `path_narrative`, the same granularity limit Stage 1's
  `validation_desc` already has. Fixing this would need a schema change and
  wasn't done in this pass.
- **Stage 4's verdict isn't guaranteed to correct Stage 1's mistakes,
  even when shown the exact code that contradicts them.** A real run against
  BlueBird found `AuthController.resetPOST` and `PostController.createPost`
  -- both triage false positives (their actual DML calls are parameterized)
  -- still came back `exploitable_path` from Stage 4: its `path_narrative`
  restated the method's control flow without ever noting the
  `new Object[]{...}` / `?` placeholder parameterization visible in the
  exact source it was shown. This is a real WhiteRabbitNeo reliability
  limitation surfaced by actually running Stage 4, not a bug in the
  orchestration code -- one more reason Stage 5's human verification gate
  isn't optional.
- **`triage`/`audit` re-process every file on every run.** There's no
  "only re-process files whose Stage 0 fingerprint changed since the last
  triage run" logic yet, unlike `index`, which is fully incremental. On a
  large codebase this means re-running `triage` after a small source change
  currently costs the same as the first full run.

## Future direction: a real code-graph backend (Joern or similar) under Stage 0/3

Not a default next step -- like cross-file resolution above, this is a
deliberate, measured decision to make only if a specific trigger below is
actually hit for a real target, not something to build preemptively.

**What this would replace**: Stage 0 (`pipeline/stage0_index/parser.py`/
`indexer.py`) and Stage 3 (`pipeline/stage3_trace/builder.py`)'s current
mechanics. Stage 3's graph walk today is a hand-rolled, same-file-only
stand-in for real interprocedural dataflow -- a resolved-call-edge lookup
plus a getter-name-matching regex, built specifically to work around the
lack of a real dataflow engine underneath it (see `assemble_context()`).
A Code Property Graph tool like Joern -- chosen over CodeQL specifically
because it tolerates partial/decompiled/bytecode-derived source, where
CodeQL generally wants a working build (often the actual blocker for a
target you only have a decompiled jar for) -- would replace both of these
with a real graph: resolved calls and dataflow/taint paths across file
boundaries, computed algorithmically instead of approximated by regex.

**What would NOT change**: Stage 1, 2, and 4 -- the LLM judgment layers.
Their design (separate bounded calls, defensive JSON parsing, `llm_runs`
provenance, "the LLM never decides what to look at next") stays exactly as
it is; they'd just read chunk/context boundaries from whatever schema sits
on top of the CPG instead of the current `symbols`/`call_edges` tables, and
get to reason over genuinely complete cross-file context instead of the
current same-file-only slice.

**Concrete triggers that would justify doing this** (any one, not a
schedule):
- A target has a real service/DAO/repository layer, where the actual
  concatenation happens inside a shared utility class several calls away
  from the controller, and that utility method's own parameters carry no
  Spring input annotations -- Stage 0's `input_sources` table would never
  mark it as attacker-reachable at all, a true miss, not just an
  incompletely-explained one.
- Cross-file second-order chains become the common case rather than the
  exception -- e.g. a target where the write site and the unsafe read site
  for a stored value are routinely in different files, the way
  `AuthController.signupPOST` (a second, real write path for `profile()`'s
  `email`) already is for BlueBird, but which Stage 3's same-file heuristic
  cannot follow (see `EXPECTED_FINDINGS.md`'s `/profile/{id}` writeup).
- Scale or audit-grade repeatability starts mattering more than the current
  tool's flexibility -- many/large codebases where LLM-per-method cost and
  the demonstrated judgment errors (see "Known boundaries" above) start
  costing more analyst re-checking time than they save.

Until one of these is actually true for a real target, the current
approach's practical advantages -- no build step required, and an LLM's
flexible judgment that doesn't need a new query written per validation
pattern -- outweigh a CPG's soundness and cross-file completeness.

## Extending this

**Adding a new prompt version** (e.g. `triage_v2.txt`): add the new file to
`prompts/`, bump `PROMPT_VERSION` in the relevant stage module, leave the
old prompt file in place (don't overwrite `triage_v1.txt`) so old
`llm_runs` rows stay resolvable to the exact prompt that produced them.

**Stage 5 (human verification gate)**: the write-side is built --
`pipeline/stage5_verify/logger.py`'s `log_finding()`, wired to
`pipeline.cli log-finding`. It's deliberately minimal: a human records a
verdict they already reached -- via live debugging (`tests/live-debugging.md`,
`tests/searching_for_strings_live_debug_writeup.md`), query-log inspection,
or manual payload testing -- into `findings`, with `verification_method`/
`status` validated against `schema.sql`'s `CHECK` constraints before
anything is written. Nothing about live debugging or payload testing lives
in pipeline code, and nothing here does that -- it only ever persists a
decision a human already made. Still unbuilt: any workflow beyond this one
write command (a review queue, browsing un-verified candidates one at a
time) -- add that only if the raw `sqlite3`/CLI workflow in `WALKTHROUGH.md`'s
verification section stops scaling, not preemptively.

**Swapping the model**: no code changes needed -- `--model <tag>` on any CLI
command. Re-run `bench/context_benchmark.py` against the new model first
(see `README.md`) and update `pipeline/config.py` if the recommended safe
threshold differs meaningfully; those constants must trace back to an actual
benchmark run for the model in use, not be copied from WhiteRabbitNeo's
numbers.
