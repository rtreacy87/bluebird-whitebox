# Walkthrough: Running a Recon Pass on BlueBird

This is a guided, plain-language tour of the whole pipeline, start to finish,
using the BlueBird test application as the target. It's written for someone
who is comfortable typing commands into a terminal but doesn't necessarily
write code -- every command is explained before you run it, and every piece
of output is explained after.

If you just want the command reference, see `README.md`. This document is
the "why does it say that, and what do I do next" companion to it.

## The scenario

Pretend you've been authorized to do a white-box source review of BlueBird,
a small social-media-style web app, as part of a penetration test. You've
been handed decompiled Java source (the client's build artifact was
decompiled ahead of time -- that process is outside this tool's scope) at
`~/BlueBirdSourceCode`. Your job: figure out where in this codebase user
input might reach a database query unsafely, before you go test it live
against the running application.

A few terms this walkthrough uses a lot:

- **Terminal / command line**: the text window where you type commands like
  `.venv/bin/python -m pipeline.cli index ...` and press Enter. Every command
  below is meant to be typed there, from inside the `bluebird-whitebox`
  project folder.
- **Database**: think of it as a structured filing cabinet. Instead of one
  big text file, the pipeline's results are organized into labeled drawers
  (tables) -- one drawer for "every method in the codebase," one for "what
  the AI thinks about each method," and so on. `sqlite3 data/recon.db
  "<question>"` is how you open the cabinet and ask it a question.
- **Sink**: the place in code where a value actually gets used dangerously --
  e.g. the exact line that runs a SQL query. Not every place a value is
  *used* is a sink; a sink is specifically a sensitive operation.
- **LLM**: the local AI model (WhiteRabbitNeo, in this setup) that reads code
  and describes what it sees. It runs entirely on this machine -- no code
  is sent anywhere else.

## Before you start

Confirm the two things everything else depends on:

```bash
ollama list
```
You should see your model tag in the list (this walkthrough uses
`whiterabbitneo-33b:latest`). If Ollama isn't running at all, `ollama list`
will fail to connect -- start it first (see `README.md`'s Setup section).

```bash
ls ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird
```
This should show folders like `controller`, `model`, `security` -- the
decompiled Java source you're about to point the tool at.

## Step 1 -- Stage 0: build the map

**What this does, conceptually**: Stage 0 reads every `.java` file and builds
a structural map of the codebase -- what classes exist, what methods each
class has, which methods are web endpoints, which parameters come from a
user's request, and which methods call which other methods. Think of it like
a librarian cataloging every book and chapter title in a library, without
reading and judging the content yet. This step never involves the AI model
-- it's a plain, deterministic parser, so its output is exactly reproducible
every time you run it against the same source.

Run it:

```bash
.venv/bin/python -m pipeline.cli index \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird \
    --db data/recon.db
```

**The first time** you run this against a fresh database, you'll see
something like:

```
indexed BlueBirdApplication.java: 2 symbols
indexed controller/AuthController.java: 16 symbols
...
{'files_indexed': 14, 'files_unchanged': 0, 'files_failed': 0, 'symbols': 121}
```

**If you run it again** without changing any source files, you'll see:

```
{'files_indexed': 0, 'files_unchanged': 14, 'files_failed': 0, 'symbols': 0}
```

**This is correct, not an error.** Stage 0 fingerprints every file (a
`sha256` hash -- a short code that changes if even one character of the file
changes) and only re-reads a file if its fingerprint changed since last time.
`files_unchanged: 14` means "I checked all 14 files, none of them changed, so
I didn't waste time re-parsing them." This matters in practice: if you're
re-running the pipeline after a small source update, or after adding one new
controller file to a much larger codebase, you don't want to wait for
everything to be re-parsed -- just the files that actually changed. If you
*do* edit a `.java` file and re-run `index`, that specific file's row would
show up as re-indexed and its old results are replaced automatically.

**A peek at what got built**, if you're curious:

```bash
sqlite3 -header -column data/recon.db \
  "SELECT path, loc, token_count FROM files ORDER BY path LIMIT 3;"
```
```
path                              loc  token_count
--------------------------------  ---  -----------
BlueBirdApplication.java          12   57
controller/AuthController.java    199  1653
controller/IndexController.java   79   590
```
`loc` is lines of code, `token_count` is a rough size estimate used later to
decide whether a file is small enough to hand to the AI in one piece, or
needs to be split up. Nothing to act on here -- just confirms the map got
built.

## Step 2 -- Stage 1: triage (the first read-through)

**What this does, conceptually**: for every method Stage 0 found, the AI
model reads that method's actual code and answers a fixed checklist: does it
take user input? Does it do anything sensitive with a database, file, or
system command? If so, is that done safely (e.g. a parameterized query) or
unsafely (e.g. gluing a raw string together)? How confident is it? Think of
this like handing every method in the codebase to a fast first-pass reviewer
and asking them to flag anything that looks risky, one method at a time,
never skipping one.

Run it:

```bash
.venv/bin/python -m pipeline.cli triage \
    --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird \
    --db data/recon.db \
    --model whiterabbitneo-33b:latest
```

**Expect this to take a while.** Each method (or small group of methods) is
one separate call to the AI model, and a 33B-parameter model on typical
hardware can take anywhere from a few seconds to several minutes per file,
depending on your GPU and how many methods are in that file. For the whole
14-file BlueBird corpus, budget 10-15 minutes. You'll see one line per file
as it finishes:

```
BlueBirdApplication.java: 1 triage rows written across 1 chunk(s)
controller/AuthController.java: 9 triage rows written across 1 chunk(s)
...
{'files': 14, 'rows_written': 67, 'methods_missing': [...]}
```

`9 triage rows written across 1 chunk(s)` means AuthController.java's 9
methods all fit in a single request to the AI (small files do). A much
larger file would show `across 2 chunk(s)` or more -- the tool automatically
splits large files at method boundaries (never mid-method) so the AI always
sees complete, readable code.

## Step 3 -- Stage 2: audit (double-checking the first reviewer)

**What this does, conceptually**: a second, separate AI call cross-checks
Stage 1's claims against Stage 0's ground-truth map -- not by re-reading the
source code again, but by comparing two lists it's handed directly: "here's
what Stage 0 actually found in this method" vs. "here's what Stage 1 claimed
about it." This step exists because an AI reviewer can occasionally
mis-describe or even invent things (see "hallucination" in the next
section) -- audit is the mechanism that catches that, or at least flags it
for you to look at.

Run it:

```bash
.venv/bin/python -m pipeline.cli audit \
    --db data/recon.db \
    --model whiterabbitneo-33b:latest
```

Output, one line per file:

```
BlueBirdApplication.java: 1 audit rows, 0 concerns flagged
controller/AuthController.java: 9 audit rows, 4 concerns flagged
...
{'files': 14, 'rows_written': 71, 'concerns_flagged': 10}
```

`concerns flagged` doesn't mean "4 new vulnerabilities" -- it means "4
methods where the audit pass thought Stage 1's claim didn't quite line up
with Stage 0's facts." Some of these concerns turn out to be useful, some
turn out to be the audit AI itself being wrong (see the interpretation
section below for a real example of that). Either way, they're a prompt to
look closer, not a verdict.

## Step 4 -- coverage check: did anything get skipped?

**What this does**: a sanity check, not an AI call. It asks the database
directly: "of every method Stage 0 found, how many actually got a triage
result?" This is a live question against the data, not a number the AI
reported about itself -- so it can't be fooled by the AI saying "I reviewed
everything" when it didn't.

```bash
.venv/bin/python -m pipeline.cli coverage --db data/recon.db
```
```
methods triaged (resolved to a symbol): 63/67
hallucinated_row rows (per Stage 2 audit): 0
symbols with no resolved triage row (4):
  model/Post.java: Post
  model/Post.java: Post
  model/User.java: User
  model/User.java: User
```

`0` hallucinated rows is a good sign. The 4 "missing" ones aren't actually
missing -- `Post` and `User` each have two constructors with the same name
(a normal Java thing called overloading -- one constructor that takes all
the fields, one that takes none). Since both share the exact name `Post` (or
`User`), the tool can't tell from the name alone which physical constructor
a given AI answer was about, so it deliberately refuses to guess and leaves
those rows unresolved rather than risk attaching the wrong one. This is a
documented, expected gap for overloaded methods/constructors -- not a sign
triage skipped anything. (Both constructors *did* get a triage row each --
`coverage` is specifically counting rows it could confidently attribute to
one exact method.)

## Interpreting the results

This is the part where you, the analyst, actually read what the tool found.
Everything below is a real query against the real BlueBird database from
this walkthrough.

### Finding the flagged sinks

Start broad: what did triage think was an unsafe database sink anywhere in
the codebase?

```bash
sqlite3 -header -column data/recon.db "
SELECT f.path, tr.symbol_name_raw AS method, tr.confidence, tr.needs_trace
FROM triage_results tr
JOIN llm_runs r ON r.run_id = tr.run_id
JOIN files f ON f.file_id = r.file_id
WHERE tr.sink_type = 'sql_unsafe'
ORDER BY tr.confidence DESC;
"
```
```
path                                method            confidence  needs_trace
----------------------------------  ----------------  ----------  -----------
controller/AuthController.java      forgotPOST        high        1
controller/IndexController.java     findUser          high        0
controller/ProfileController.java   profile           high        0
controller/AuthController.java      signupPOST        high        0
controller/AuthController.java      verifyResetCode    high        0
controller/AuthController.java      resetPOST          high        0
```

Three of these -- `forgotPOST`, `findUser`, `profile` -- are the endpoints
`/forgot`, `/find-user`, and `/profile/{id}` respectively (the endpoint-to-
method mapping is something you cross-reference against the source, or
`EXPECTED_FINDINGS.md` if you're working against this same BlueBird corpus).
All three came back `sql_unsafe` with `high` confidence -- a strong signal to
prioritize.

### Reading one finding in full

Pick the top one and read everything the tool said about it:

```bash
sqlite3 -column data/recon.db "
SELECT validation_desc FROM triage_results WHERE symbol_name_raw='forgotPOST';
"
```
```
The method takes a request parameter 'email'. It checks if the email is
empty and if it matches an email pattern. If it does not match, it
redirects to the forgot page with an error message. If it does match, it
queries the database for the user using string concatenation in the SQL
query.
```

This is the analyst payoff: the tool isn't just saying "this is bad," it's
telling you *why* -- there's an email-format check, but the actual database
query is still built by gluing the raw input into a SQL string (string
concatenation) rather than using a parameterized query. That's exactly the
shape of a SQL injection: a validation check that looks reassuring but
doesn't actually stop the dangerous part. This is where you'd go read the
actual line of source the tool is describing, and plan how you'd verify it
against the live application (a manual step -- this tool stops at "here's a
mapped hypothesis," see `README.md`'s scope section).

### Checking the audit's second opinion

```bash
sqlite3 -header -column data/recon.db "
SELECT s.name, ar.notes FROM audit_results ar
LEFT JOIN symbols s ON s.symbol_id = ar.symbol_id
WHERE s.name = 'forgotPOST';
"
```
```
name        notes
----------  --------------------------------------------------------------
forgotPOST  The TRIAGE CLAIM says sink_type=sql_unsafe, but STAGE0 FACTS
            shows no callee names flagged as potentially unsafe.
```

Here's an important, honest example of the audit stage being *wrong*: Stage
0's facts for `forgotPOST` actually do list a database call
(`jdbcTemplate.queryForObject`) that should have been keyword-flagged. The
audit AI simply misread the facts it was handed. **This is exactly why the
tool's design treats both AI stages as advisory, not authoritative** -- Stage
0's structural facts (the librarian's catalog) are the only thing guaranteed
correct in this pipeline; both the triage and audit AI passes can be wrong,
and audit disagreeing with triage doesn't automatically mean triage was the
one that got it wrong. Read the underlying source yourself before trusting
either AI's conclusion on a specific finding.

### What "needs_trace" is telling you

Notice `forgotPOST` had `needs_trace = 1` while `findUser` and `profile` had
`needs_trace = 0`. In plain terms, triage is saying "for `forgotPOST`, I
believe the unsafe value came from somewhere other than this method's own
direct input" (worth a deeper look at where the value actually originates),
versus "for `findUser` and `profile`, I believe the unsafe value comes
straight from this method's own parameter."

Worth knowing: this flag is triage's own self-assessment, made without
seeing the rest of the codebase, and it can be wrong in either direction. In
this BlueBird corpus, `profile()` is actually the more subtle case -- the
raw input it directly receives (a numeric ID) is fine and safe; the actual
unsafe query later in that same method uses a *different* value that was
read back out of the database (a user's stored email address), not the raw
ID. Triage's plain-English description named the wrong variable as the
culprit and marked `needs_trace = 0`, when arguably it should have said the
opposite. Multi-step, "value gets stored now, read back and misused later"
chains like this are exactly what this pipeline does *not* yet trace
automatically (that's planned future work, Stage 3/4) -- a human has to
follow that chain by reading the code. `EXPECTED_FINDINGS.md` has the full
worked example for this specific case if you want to see the actual lines.

**Practical takeaway**: `needs_trace = 1` is a useful hint about where to
look harder, but `needs_trace = 0` is not a guarantee the finding is simple
-- read the method yourself either way before ruling out a multi-step chain.

## Teardown / archiving after an engagement

Once you're done with a pass -- whether that's the end of a real engagement
or just the end of a testing session -- you'll want to preserve what the
pipeline found without losing it, and get a clean slate for the next target,
all **without touching the source code you were given** (it's someone else's
read-only evidence, not yours to modify or delete).

**What you keep forever**: the client's source code
(`~/BlueBirdSourceCode` in this walkthrough) and this project's own files
(everything under `bluebird-whitebox/` that isn't in `data/`). Never delete
either of these as part of teardown.

**What's actually disposable/archivable**: just `data/recon.db` -- that's
the only place this pipeline writes engagement-specific results.

### 1. Archive the database itself

```bash
mkdir -p archive
cp data/recon.db "archive/bluebird-$(date +%Y%m%d).db"
```

This gives you a timestamped, frozen copy of every table -- files, symbols,
every triage/audit row, full `llm_runs` provenance (which exact model and
prompt version produced each result) -- exactly as it stood at the end of
the engagement. If a client or teammate asks "what did the tool actually
find, and can you prove which model said it," this file is the answer; you
can point `sqlite3` at it later without needing to re-run anything.

### 2. Export a human-readable summary alongside it

A raw `.db` file isn't something you can casually attach to a report. Pull
the highlights into a plain text file too:

```bash
sqlite3 -header -csv data/recon.db "
SELECT f.path, tr.symbol_name_raw, tr.sink_type, tr.confidence, tr.needs_trace, tr.validation_desc
FROM triage_results tr
JOIN llm_runs r ON r.run_id = tr.run_id
JOIN files f ON f.file_id = r.file_id
WHERE tr.sink_type != 'none'
ORDER BY tr.confidence DESC;
" > "archive/bluebird-$(date +%Y%m%d)-findings.csv"
```

Open that CSV in a spreadsheet and you have a working list to hand-verify
against the live application -- one row per flagged method, with the sink
type, confidence, and the plain-English explanation, ready to check off as
you confirm (or rule out) each one manually.

### 3. Reset the working database for the next target

The pipeline always writes to whatever `--db` path you give it, so the
simplest "teardown" for a fresh start is just to stop pointing at the old
file:

```bash
# for a brand new target, just use a new --db path -- nothing to delete
.venv/bin/python -m pipeline.cli index --source /path/to/next/target --db data/next-engagement.db
```

If you specifically want to clear BlueBird's working copy back to empty
(e.g. you're about to re-validate the pipeline itself after a code change,
per `CLAUDE.md`'s testing requirements) -- since you said you're still using
this BlueBird data, **don't do this as part of a normal engagement
teardown**, but for reference, the safe way is:

```bash
# only do this if you actually want to wipe BlueBird's results and re-run
# from scratch -- this does NOT touch ~/BlueBirdSourceCode, only the DB
rm data/recon.db
```

Because `data/*.db` is gitignored, none of this ever touches version
control either way -- archiving and resetting are both purely local file
operations.
