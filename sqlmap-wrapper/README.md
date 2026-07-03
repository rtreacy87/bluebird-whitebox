# sqlmap-wrapper

Orchestrates real `sqlmap` runs against a candidate list exported from the
parent `bluebird-whitebox` recon pipeline's Stage 6, and wrangles sqlmap's
own output into a queryable SQLite store using a local LLM. See `CLAUDE.md`
for the full rules (why this tool is governed separately, what it may and
may not do, the CTF/POC-phase framing) and `DATA_DICTIONARY.md` for the
schema. This README is the "how to actually run it" reference.

**Read `CLAUDE.md`'s "A real, discovered limitation" section before relying
on a `not_confirmed` result meaning "safe."** It doesn't.

## Setup

This tool lives inside the `bluebird-whitebox` repo but is a separate
Python package (`sqlmap_wrapper/`). All commands below assume your shell's
cwd is the **repo root** (`bluebird-whitebox/`, one level up from this
file), not this directory — that keeps `pipeline.*` importable (needed by
`llm_runner.py`) while still finding `sqlmap_wrapper` itself via
`PYTHONPATH`:

```bash
# from the bluebird-whitebox repo root
export PYTHONPATH=sqlmap-wrapper
```

`sqlmap` itself must be installed and on `PATH` (`sqlmap --version` should
print something). Local Ollama, same instance the parent pipeline uses, is
only needed for `interpret-run`.

## Running it end to end

**1. Produce a Stage 6 export from the parent pipeline first** (see
`../README.md`'s "Stage 4.5"/reporting sections):

```bash
.venv/bin/python -m pipeline.cli export-report \
    --db data/recon.db --format sqlmap-json --out candidates.json \
    --request-templates request-templates.json
```

The `--request-templates` flag matters here even though it's optional --
without it, every candidate's `param_defaults` is `null`, and a POST
candidate can't be run (see `MissingRequestBodyError` below).

**2. Register and authorize the target you're actually allowed to test.**
This is the one deliberate, auditable "yes, this is in scope" step every
`--execute` run is checked against:

```bash
python -m sqlmap_wrapper.cli register-target \
    --host 10.10.11.5 --port 80 --label "HTB-BlueBird" --authorize
```

**3. Import the export:**

```bash
python -m sqlmap_wrapper.cli import-candidates --file candidates.json
```

Prints `import_id=<N> candidates=<count>`. Each imported candidate gets a
`candidate_id` — list them with `sqlite3 sqlmap-wrapper/data/wrapper.db
"SELECT candidate_id, endpoint, target_param_name FROM candidates;"`.

**4. Assign a candidate to the target you registered:**

```bash
python -m sqlmap_wrapper.cli assign-target --candidate-id 1 --target-id 1
```

**5. Preview the command before running it** (this is the default — no
network/subprocess call happens without `--execute`):

```bash
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id 1 --output-dir out/candidate-1
```

Prints the exact `sqlmap` command it would run and records a `dry_run=1`
row. Read it before adding `--execute` — this is your chance to catch a
wrong host, a missing `param_defaults`, or a flag you want to add via
`--extra-args` (checked against a hard denylist -- `--os-shell` and similar
RCE/file-write primitives are refused, see `CLAUDE.md`).

**6. Actually run it:**

```bash
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id 1 --output-dir out/candidate-1 --execute
```

Refuses (with a clear error, nothing fired) if the assigned target isn't
`authorized=1`. On success, prints `run_id=<N>` and writes sqlmap's own
`--output-dir` artifacts plus `out/candidate-1/wrapper_stdout.log` /
`wrapper_stderr.log` (the captured subprocess streams `interpret-run`
reads from).

**7. Wrangle the result into a structured row:**

```bash
python -m sqlmap_wrapper.cli interpret-run --run-id <N> --model whiterabbitneo-33b:latest
```

Prints `result_id=<N>`. Query it:

```sql
SELECT result_type, summary_text FROM sqlmap_results WHERE result_id = <N>;
```

## A worked example, run for real against BlueBird

Steps 1-7 above were run for real against a disposable local BlueBird
replica (the same one Stage 4.5's own writeups use) as part of validating
this tool, targeting `signupPOST`'s `name` parameter — already known,
via three separate prior writeups, to be genuinely SQL-injectable. The real
`sqlmap` run completed (`exit_code=0`) but reported **"all tested
parameters do not appear to be injectable"** — `interpret-run` correctly
recorded `result_type: "not_confirmed"`, not a fabricated `"confirmed"`.

This is not a bug in this tool. See `CLAUDE.md`'s "A real, discovered
limitation" section for the full explanation: sqlmap only sees the HTTP
response (a generic Spring Boot `500` JSON body with no DB-specific text),
while the actual proof of exploitability lived in the target's own
server-side log, which only Stage 4.5's white-box dynamic verification had
access to. A `not_confirmed` result from this tool is not the same claim as
"this isn't exploitable" — treat it as "sqlmap's default technique set
didn't independently reproduce this one," and consider `--extra-args` (a
`--tamper` script, a higher `--level`) deliberately before concluding
otherwise.

## Command reference

| Command | Touches network/subprocess? | Notes |
|---|---|---|
| `register-target` | No | `--authorize` marks it usable immediately; omit it to register without authorizing yet. |
| `import-candidates` | No | Validates against the `sqlmap_candidate_v1` shape by hand (no `jsonschema` dependency) before writing anything. |
| `assign-target` | No | Links an already-imported candidate to an already-registered target. |
| `run-sqlmap` (no `--execute`) | No | Dry-run: builds and prints the argv, records a `dry_run=1` row. |
| `run-sqlmap --execute` | **Yes** | The one command that fires a real subprocess. Gated behind `guard.require_authorized()`. |
| `interpret-run` | **Yes** (local Ollama only) | Only valid against a non-dry-run `run_id`. |

## Testing

```bash
# Tier 1: deterministic, no network, no subprocess
PYTHONPATH=sqlmap-wrapper .venv/bin/python -m pytest sqlmap-wrapper/tests/ -v

# Tier 2: real BlueBird replica + real sqlmap + real Ollama call
RUN_SQLMAP_TESTS=1 PYTHONPATH=sqlmap-wrapper .venv/bin/python -m pytest sqlmap-wrapper/tests/ -v
```
