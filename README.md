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

Implemented: **Stage 0 (static index) → Stage 1 (triage) → Stage 2 (audit)**.

Not yet built (deliberately, per the project's build order): Stage 3 (trace
worklist), Stage 4 (deep-trace), Stage 5 (human verification gate), Stage 6
(findings export), and cross-file call resolution. Today the pipeline tells
you *which methods look like unsafe sinks and why*, per file. It does not yet
trace multi-file/second-order data flow (e.g. "attacker-controlled value
gets stored, then later read back into an unsafe query elsewhere") -- a
human reviewer needs to do that tracing manually for now. See the worked
second-order example in `EXPECTED_FINDINGS.md` (`/profile/{id}`) for what
this looks like in practice.

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

# Sanity check: did every method actually get triaged?
.venv/bin/python -m pipeline.cli coverage --db data/recon.db
```

Run `index` again any time the source changes -- it's incremental and
idempotent. `triage`/`audit` currently re-process every file each run (there's
no "only re-triage changed files" logic yet); on a large codebase, expect
this to take a while -- triage/audit calls are LLM-bound, and larger,
CPU/GPU-shared models can take single-digit minutes per file.

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
parameters (a field, a stored value, another call's return) -- these are
exactly the ones a human should chase manually right now, since Stage 3/4
(automated tracing) isn't built yet.

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
- **Unauthorized testing.** This is a defensive-assessment recon aid for
  engagements you're authorized to perform, not a scanning tool to point at
  arbitrary targets.
- **A substitute for the human verification step.** Nothing here should go
  into a client report without independent confirmation (live debugger,
  query logs, or manual testing) -- that's Stage 5 in the design (not yet
  built), and until it exists, treat every row in `triage_results` /
  `audit_results` as a lead, not a finding.
- **Non-Java codebases, or languages/frameworks the parser doesn't
  understand.** Stage 0 is a javalang-based Java parser; it won't run against
  other languages without a new Stage 0 implementation.
