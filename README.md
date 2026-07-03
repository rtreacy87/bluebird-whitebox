# White-Box Source-Review Recon Pipeline

A recon tool for penetration testing engagements that ingests decompiled Java
source (Spring Boot / JDBC apps), builds a deterministic structural index,
then uses a **local** LLM to triage and adversarially audit potential SQL
injection (and related) vulnerabilities.

This tool produces a **mapped, cited hypothesis** -- file/line locations,
data flow, sink type, and a confidence level. It does not generate exploit
payloads, bypass strings, or fire requests at a target. Every finding needs a
human to verify it against the live application before it goes in a report.

See `CLAUDE.md` for the full design spec and build-order rationale, and
`EXPECTED_FINDINGS.md` for the BlueBird regression corpus's ground truth.

## Current scope

Implemented: **Stage 0 (static index) → Stage 1 (triage) → Stage 2 (audit)
→ Stage 3 (deterministic trace queue) → Stage 4 (LLM deep-trace)**, plus
Stage 5's write-side (`log-finding` -- a human records a finding they've
already manually verified).

Not yet built: Stage 6 (findings report export), and cross-file call
resolution (Stage 3's graph walk is intra-file-only, same boundary as
Stage 0 -- see `ARCHITECTURE.md`'s "Known boundaries"). Stage 3/4 trace
multi-step, same-file data flow (e.g. "attacker-controlled value gets
stored by one method, then read back into an unsafe query by another") --
see the worked `/profile/{id}` example in `EXPECTED_FINDINGS.md`, which
Stage 3/4 traces correctly today. Cross-*file* chains still require a human
to trace manually. Stage 4's verdicts are advisory, same as Stage 1/2 --
see `ARCHITECTURE.md`'s "Known boundaries" for a real example of Stage 4
not catching a false positive it was shown evidence against.

## Requirements

- **Python 3.10+**
- **Ollama**, running locally (`http://localhost:11434` by default) with a
  model imported that's suited to code review. This project was built and
  validated against WhiteRabbitNeo-33B-v1.5 (see "Getting a model" below --
  it isn't in Ollama's own library, so it needs a manual import). Any model
  you use should be capable enough at instruction-following to reliably
  return structured JSON -- smaller/weaker models will still run but produce
  lower-quality, less-reliable triage (during development, a smaller 8B model
  correctly parsed the plumbing but conflated a hash computation with the
  actual SQL sink in its reasoning, which the 33B model did not).
- Decompiled Java source to point the pipeline at. Fernflower (bundled with
  most modern decompiler toolchains) or CFR both produce source the parser
  handles well. Extract a Spring Boot fat jar (`BOOT-INF/classes/...`) and
  point `--source` at the package root you want indexed.
- No internet access is required or used by the pipeline itself -- every LLM
  call stays local. You do need internet once, during setup, to `pip
  install` dependencies and download a model.
- **~20-30GB free disk** for a 33B-class quantized model (a Q5_K_M GGUF of
  WhiteRabbitNeo-33B-v1.5 is ~23GB), plus enough GPU/system RAM to run it at
  a usable speed. If the model doesn't fully fit in VRAM, Ollama falls back
  to partial CPU offload, which is dramatically slower (single-digit tokens/sec
  in testing) -- expect multi-minute triage/audit calls on large files in
  that case, not a bug, just the cost of running a 33B model on constrained
  hardware.

### Why Ollama, not `llama-server` directly

This was a deliberate evaluation, not a default. Ollama's engine is itself a
llama.cpp/ggml fork, so there's no output-quality difference between running
through Ollama or running `llama-server` directly -- the choice is about
operational overhead. Ollama wins here because it owns model lifecycle
(load/unload, GPU/CPU offload, keep-alive) instead of the pipeline needing to
supervise a long-running server process, and its tag registry (`ollama
list`/`ollama create`) is what this project's model-provenance recording is
built on. One thing switching runtimes would *not* fix: a model continuing to
emit prose after a structurally complete JSON value is a general property of
grammar-constrained decoding, not an Ollama-specific bug -- the pipeline
already parses defensively for this (see `CLAUDE.md`'s "Local Model Runtime"
section) regardless of which engine is underneath.

## Setup

```bash
# from the repo root
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

# confirm Ollama is running and see what's actually installed --
# do not assume a model's tag matches its marketed name
ollama list
```

### Getting a model: WhiteRabbitNeo is not in the Ollama library

`ollama pull whiterabbitneo-33b` will fail -- WhiteRabbitNeo isn't published
to Ollama's own model library. [WhiteRabbitNeo-33B-v1.5](https://huggingface.co/WhiteRabbitNeo/WhiteRabbitNeo-33B-v1.5)
is distributed on Hugging Face as safetensors, under a modified DeepSeek
Coder license (review its usage restrictions -- e.g. no military use -- before
adopting it for an engagement). To run it in Ollama you need a GGUF-format
quantization, then import it locally:

```bash
# 1. Download a GGUF quantization from Hugging Face. The base repo is
#    safetensors-only; community quantizations exist as separate repos, e.g.:
#      https://huggingface.co/manuelgutierrez/WhiteRabbitNeo-33B-v1.5-GGUF
#      https://huggingface.co/dranger003/WhiteRabbitNeo-33B-v1.5-iMat.GGUF
#    Verify availability yourself -- community repos move/disappear -- and
#    pick a quant level (e.g. Q5_K_M) that fits your available VRAM/RAM.
pip install -U huggingface_hub   # provides the `hf` CLI (huggingface-cli is deprecated/removed)
hf download manuelgutierrez/WhiteRabbitNeo-33B-v1.5-GGUF \
    whiterabbitneo-33b-v1.5.Q5_K_M.gguf --local-dir ./models

# 2. Write a Modelfile pointing at the downloaded weights
cat > Modelfile <<'EOF'
FROM ./models/whiterabbitneo-33b-v1.5.Q5_K_M.gguf
EOF

# 3. Import it into Ollama under a local tag of your choosing
ollama create whiterabbitneo-33b:latest -f Modelfile
```

Alternatively, if a GGUF repo supports it, `ollama pull
hf.co/<user>/<repo>:<quant-tag>` pulls and imports directly from Hugging
Face in one step, without a manual Modelfile -- but it tags the model as
`hf.co/<user>/<repo>:<quant-tag>` rather than a short name, so you'll likely
want `ollama cp` afterward to give it a shorter local tag.

Either way, run `ollama list` afterward and use **whatever tag actually
shows up** as `--model` below -- a custom import like this routinely leaves a
tag that doesn't match the model's marketed name (`whiterabbitneo-33b:latest`
above is just what this repo happened to name it locally, not a fixed
requirement), and the pipeline records this exact string in `llm_runs` for
reproducibility, so getting it right matters.

### Benchmark the model's effective context window (recommended once per model)

Ollama's default context window is much smaller than a model's marketed
maximum, and truncation is silent unless you check for it. Before trusting
the pipeline against a new model or a corpus with much larger files than
BlueBird's, re-run the benchmark:

```bash
.venv/bin/python -m bench.context_benchmark --model whiterabbitneo-33b:latest --sizes 512,1024,2048,4096 --trials 2
```

This writes `bench/context_benchmark_results.json` and prints a recommended
safe token threshold. If it differs meaningfully from the checked-in value,
update `SAFE_CONTEXT_TOKENS_HEURISTIC` / `DEFAULT_NUM_CTX` in
`pipeline/config.py` to match -- those constants must always trace back to an
actual benchmark run, not a guess.

## Running the pipeline

All commands take `--db` (default `data/recon.db`); the DB is created and
initialized from `schema.sql` automatically on first use.

```bash
# Stage 0: deterministic static index -- no LLM, safe to re-run any time
# (only changed files, by sha256, get re-parsed)
.venv/bin/python -m pipeline.cli index \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird \
    --db data/recon.db

# Stage 1: per-file LLM triage
.venv/bin/python -m pipeline.cli triage \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird \
    --db data/recon.db \
    --model whiterabbitneo-33b:latest

# Stage 2: adversarial audit of the triage pass
.venv/bin/python -m pipeline.cli audit \
    --db data/recon.db \
    --model whiterabbitneo-33b:latest

# Stage 3: deterministic trace-queue builder -- no LLM, safe to re-run
# (enqueues every sink_type='sql_unsafe' triage row not already queued)
.venv/bin/python -m pipeline.cli enqueue-trace --db data/recon.db

# Stage 4: LLM deep-trace over whatever Stage 3 queued
.venv/bin/python -m pipeline.cli trace \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird \
    --db data/recon.db \
    --model whiterabbitneo-33b:latest

# Sanity check: did every method actually get triaged?
.venv/bin/python -m pipeline.cli coverage --db data/recon.db
```

Run `index` again any time the source changes -- it's incremental and
idempotent. `triage`/`audit`/`trace` currently re-process every file/item
each run (there's no "only re-process changed things" logic yet for those
three); `enqueue-trace` *is* incremental (it skips any triage row already
enqueued). On a large codebase, expect the LLM-bound stages to take a
while -- larger, CPU/GPU-shared models can take single-digit minutes per
call.

### Stage 4.5: dynamic verification

Once Stage 4 has produced `exploitable_path` hypotheses, Stage 4.5 turns them
into observed evidence by firing a small, fixed, non-destructive probe
battery at a disposable local replica of the target -- see `CLAUDE.md`'s
"Dynamic Verification (Stage 4.5)" section for the exact scope boundary
(this is deliberately *not* a sqlmap replacement, see "When it's not"
below). Three commands, always against a **local** target only
(`pipeline/stage4_5_dynamic_verify/guard.py` enforces this):

```bash
# Stand up a disposable local replica: recompile the decompiled source,
# start a throwaway Postgres container, apply your own schema file, boot
# the app pointed at that container. Prints env_id=<N>.
.venv/bin/python -m pipeline.cli setup-target-env \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes \
    --schema-sql ~/BlueBirdSourceCode/schema.sql \
    --db-user bluebird --db-password bluebird --db-name bluebird \
    --db data/recon.db

# Fire the fixed probe battery (baseline / single_quote / double_quote /
# backslash) at every pending exploitable_path candidate that has a request
# template, classify each result, and optionally resolve ambiguous ones via
# the local model.
.venv/bin/python -m pipeline.cli dynamic-probe \
    --env-id 1 \
    --request-templates request-templates.json \
    --model whiterabbitneo-33b:latest \
    --db data/recon.db

# Tear it down when done -- not automatic on a crash, so run this
# explicitly even after an interrupted run.
.venv/bin/python -m pipeline.cli teardown-target-env --env-id 1 --db data/recon.db
```

`--request-templates` is a human-supplied JSON file describing each
endpoint's request shape -- Stage 0 has no route/HTTP-method or
sibling-parameter information to infer this from, so it's trusted input,
the same trust level as the schema file passed to `--schema-sql`:

```json
{
  "signupPOST": {
    "endpoint": "/signup",
    "http_method": "POST",
    "param_defaults": {
      "name": "Probe User",
      "username": "probeuser_{nonce}",
      "email": "probe_{nonce}@test.com",
      "password": "ProbePass123",
      "repeatPassword": "ProbePass123"
    },
    "verify_table": "users"
  }
}
```

`{nonce}` in a sibling parameter's default marks it as needing a fresh
per-probe value (e.g. `username`, which must be unique per signup attempt) --
see `ARCHITECTURE.md`'s "Known boundaries" for why reusing the same sibling
value across all four probes in a battery silently broke three of them the
first time this was tried. Results land in `dynamic_probe_results`
(`classification`: `error`/`passthrough_unmodified`/`transformed`/
`rejected`/`ambiguous`) -- this is the prioritized, evidence-backed candidate
list you hand to a separate, human-directed tool like `sqlmap` next, not a
`findings` row on its own.

Once you've picked a finding worth manually verifying (e.g. via a live
debugger -- see "Verifying and logging a finding" below), record the
result:

```bash
.venv/bin/python -m pipeline.cli log-finding \
    --db data/recon.db \
    --verification-method live_debug \
    --status confirmed \
    --notes "..." \
    --source-trace-id <id>
```

### A note on speed

Whatever model you use, always cap `num_predict` (the pipeline does this
internally, scaled to the number of methods in a chunk) -- an uncapped model
can ramble for many minutes on a single call instead of stopping once it's
answered. If you're extending the pipeline (new prompts, new stages), keep
this in mind; it's easy to accidentally reintroduce unbounded generation.

## Reading the output

Everything lives in the SQLite DB (`schema.sql` is the source of truth for
structure). A few `sqlite3 data/recon.db` queries you'll actually use:

**What did triage flag, and how confident is it?**
```sql
SELECT f.path, s.name, tr.sink_type, tr.confidence, tr.validation_desc
FROM triage_results tr
JOIN llm_runs r ON r.run_id = tr.run_id
JOIN files f ON f.file_id = r.file_id
LEFT JOIN symbols s ON s.symbol_id = tr.symbol_id
WHERE tr.sink_type = 'sql_unsafe'
ORDER BY tr.confidence DESC;
```

`sink_type` is one of: `sql_unsafe`, `sql_safe`, `file_path`, `command_exec`,
`template`, `none`. `sql_safe` is a first-class result, not the absence of a
finding -- it means the triage pass looked at a query and concluded it's
properly parameterized. `needs_trace = 1` means the triage pass believes the
value reaching a sink didn't come directly from that method's own
parameters (a field, a stored value, another call's return) -- but don't
rely on this flag to know what Stage 3 will actually enqueue: it's
demonstrated-unreliable (BlueBird's `profile()` needs tracing but was
flagged `needs_trace=0` anyway), so Stage 3 enqueues every
`sink_type='sql_unsafe'` row regardless of this flag. See
`ARCHITECTURE.md`'s "Stage 3 then Stage 4, step by step" for what actually
drives the trace queue.

**What did Stage 3/4 conclude for those?**
```sql
SELECT tr1.symbol_name_raw AS method, tq.target_variable, tres.verdict, tres.path_narrative
FROM trace_results tres
JOIN trace_queue tq ON tq.queue_id = tres.queue_id
JOIN triage_results tr1 ON tr1.result_id = tq.origin_triage_result_id
ORDER BY tres.trace_id;
```
`verdict` is one of `exploitable_path`, `safe_path`, `insufficient_context`,
`inconclusive` -- one verdict per queued item, not per individual variable
inside a multi-variable concatenation (see
`tests/searching_for_strings_stage3_4_writeup.md` for a concrete case where
that granularity limit matters). `insufficient_context` specifically means
Stage 4 itself reported it would need something outside what Stage 3 could
assemble intra-file -- not a parsing failure.

**Did every method get reviewed?**
```bash
.venv/bin/python -m pipeline.cli coverage --db data/recon.db
```
This is a live query against Stage 0 vs. Stage 1, never a stored percentage
-- if a method has no row here, either it was never triaged (a bug worth
investigating) or it's one half of an overloaded method/constructor pair
that can't be individually attributed by name alone (see `symbol_id may be
NULL` below).

**Is a triage row hallucinated, or does it check out against Stage 0's
ground truth?**
```sql
SELECT s.name, f.path, ar.status, ar.notes
FROM audit_results ar
LEFT JOIN symbols s ON s.symbol_id = ar.symbol_id
LEFT JOIN files f ON f.file_id = s.file_id
WHERE ar.status != 'matched' OR (ar.notes != '' AND lower(ar.notes) != 'none');
```
`audit_results.status`:
- `matched` -- the triage row corresponds to a real Stage 0 symbol.
- `hallucinated_row` -- triage named a method that isn't actually in this
  file. Treat any finding attached to one of these with real suspicion.
- `missing_from_table` -- a real method that never got a triage row at all.
- `ambiguous` -- the name matches more than one real symbol in the file
  (overloaded methods/constructors); the pipeline deliberately does not
  guess which overload a row refers to, rather than risk a wrong match.

`ar.notes` on a `matched` row is the audit LLM's adversarial second opinion
-- e.g. flagging that triage claimed `has_input=true` but Stage 0's own
parser found no request-bound parameter for that method. **Treat these notes
as a heuristic prompt to look closer, not as ground truth themselves** -- in
practice the audit model sometimes misreads the very facts it's given (this
was directly observed and verified during the BlueBird validation run: it
claimed no SQL-related callee existed for a method that Stage 0 clearly
showed calling `jdbcTemplate.queryForObject`). Stage 0's facts are the only
things in this pipeline guaranteed to be correct; both LLM stages are
advisory.

**Provenance for any result:**
```sql
SELECT * FROM llm_runs WHERE run_id = <id>;
```
Every triage/audit row traces back to an `llm_runs` row recording the exact
model tag, prompt version, chunk position, and the real token count Ollama
reported for that call -- useful when a finding looks off and you want to
know exactly what the model was shown.

## Verifying and logging a finding

Nothing this pipeline produces (`triage_results`, `audit_results`,
`trace_results`) should reach a report unverified. `log-finding` is how you
record that verification into the same database, once you've done it --
it's Stage 5's write-side: a human records a verdict, nothing here decides
one. This section assumes you're verifying with VS Code's Java debugger
attached to a locally running copy of the target, per
`tests/live-debugging.md` (full setup: installing VS Code/the Java
extension pack, getting a runnable copy of decompiled source, attaching via
JDWP) and `tests/searching_for_strings_live_debug_writeup.md` (a fully
worked example against BlueBird). The steps below assume that setup is
already done and a breakpoint has already told you something concrete.

1. **Find the `trace_id` (or `result_id`) the finding traces back to**, so
   `log-finding` can link your verification to the exact upstream evidence:
   ```sql
   SELECT tres.trace_id, tr1.symbol_name_raw, tres.verdict
   FROM trace_results tres
   JOIN trace_queue tq ON tq.queue_id = tres.queue_id
   JOIN triage_results tr1 ON tr1.result_id = tq.origin_triage_result_id
   WHERE tr1.symbol_name_raw = 'signupPOST';
   ```
   If the method you're verifying was never queued for a trace (Stage 3
   only enqueues `sink_type='sql_unsafe'` rows), use `--source-triage-result-id`
   with `triage_results.result_id` instead.

2. **Set your breakpoint and confirm what you're looking for** in VS Code's
   Variables panel -- e.g. for `AuthController.signupPOST`'s INSERT (line
   171), confirm `passwordHash` is BCrypt output while `name`/`username`/
   `email` are untransformed, exactly as in
   `tests/searching_for_strings_live_debug_writeup.md`.

3. **Log it**, right after you've confirmed it -- while the details are
   still in front of you, not from memory later:
   ```bash
   .venv/bin/python -m pipeline.cli log-finding \
       --db data/recon.db \
       --endpoint /signup \
       --vuln-class sql_injection \
       --verification-method live_debug \
       --status confirmed \
       --severity medium \
       --notes "Confirmed live via VS Code debugger: name/username/email pass through signupPOST's INSERT unescaped; passwordHash is BCrypt output and cannot be exploited." \
       --source-trace-id 4
   ```
   Prints `logged finding_id=<n>` on success. `--verification-method` must
   be one of `live_debug`, `query_log`, `manual_payload`; `--status` one of
   `confirmed`, `rejected`, `needs_review` (default). `verified_by_human` is
   set to `1` automatically -- this command exists specifically to record
   that a human did the verifying, so pass `--not-verified` only in the
   rare case you want to log a note without actually asserting that.
   A bad `--verification-method`/`--status` or a `--source-trace-id` that
   doesn't exist fails immediately with a clear error, before writing
   anything.

4. **Review what you've logged so far:**
   ```sql
   SELECT finding_id, endpoint, vuln_class, verification_method, status, reviewed_at
   FROM findings ORDER BY reviewed_at DESC;
   ```
   Nothing outside this table should ever be treated as report-ready --
   per `CLAUDE.md`, only rows with `verified_by_human = 1 AND status =
   'confirmed'` are meant to leave the internal DB in an exported report
   (Stage 6, not yet built, will be what actually automates that filter).

## When this tool is appropriate

- You're doing **white-box source review** as part of an authorized
  penetration test or security assessment, and you have (or can produce)
  decompiled or actual Java source for a Spring Boot / JDBC-style
  application.
- You want a fast, structured **first pass** across a codebase to prioritize
  where to spend manual review time -- not a replacement for manual review.
- You need results that stay **entirely on infrastructure you control**: no
  source ever leaves the machine, since every LLM call goes to a local
  Ollama instance.
- You're comfortable with the current scope: single-file (intra-file) data
  flow reasoning. Multi-file and second-order chains (stored data read back
  into a later unsafe query, cross-service data flow, etc.) still require
  manual tracing -- the tool will often still flag the unsafe *sink*
  correctly even when it doesn't correctly explain the chain that reaches
  it (see `EXPECTED_FINDINGS.md`'s `/profile/{id}` writeup for a concrete
  example of this exact gap).

## When it's not

- **Automated exploitation or payload generation.** Out of scope by design
  (see `CLAUDE.md`); if you need working proof-of-concept payloads, that's a
  manual step after a finding is verified.
- **A substitute for `sqlmap` (or similar).** Stage 4.5's probe battery is
  deliberately narrow -- four fixed, non-destructive metacharacter probes
  against a local replica, to confirm a hypothesis and prioritize a
  candidate list. It never attempts UNION-based extraction, blind/time-based
  oracles, stacked queries, or auth bypass. Once Stage 4.5 tells you *which*
  parameter is worth pursuing and roughly how the sink reacts, actual
  exploitation-technique automation against the real target is still a
  separate, human-directed step outside this codebase.
- **Unauthorized testing.** This is a defensive-assessment recon aid for
  engagements you're authorized to perform, not a scanning tool to point at
  arbitrary targets.
- **A substitute for the human verification step.** Nothing here should go
  into a client report without independent confirmation (live debugger,
  query logs, or manual testing) -- `log-finding` (Stage 5's write-side,
  see below) exists to *record* that a human did this, not to replace it.
  Until you've run it against a specific finding, treat every row in
  `triage_results` / `audit_results` / `trace_results` as a lead, not a
  finding.
- **Non-Java codebases, or languages/frameworks the parser doesn't
  understand.** Stage 0 is a javalang-based Java parser; it won't run against
  other languages without a new Stage 0 implementation.
