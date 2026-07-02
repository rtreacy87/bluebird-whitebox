---
tags: [writeup, pipeline-demo]
companion_to: tests/searching_for_strings.md, tests/searching_for_strings_pipeline_writeup.md
last_updated: 2026-07-01
---

# Writeup: Re-solving "Searching for Strings" with Stage 3 + Stage 4

`tests/searching_for_strings_pipeline_writeup.md` solved this lab's question
— *which variable in `AuthController.java`'s INSERT query cannot be
exploited?* — using only Stage 0-2 (static index, triage, audit), which at
the time were the only stages built. Stage 3 (deterministic trace queue) and
Stage 4 (LLM deep-trace) have since been implemented. This writeup re-runs
the same question through the full Stage 0-4 pipeline to see whether the
new stages get any closer to a fully automated answer.

**Result: no improvement on this specific question.** Stage 3 correctly
classifies `signupPOST` as a case needing no extra cross-method context, and
Stage 4 confirms the sink is exploitable — but its narrative doesn't
distinguish `passwordHash` from the other three concatenated variables any
better than Stage 1's `validation_desc` did. The final answer still comes
from a human reading the same ~25 cited lines as before. This isn't a bug in
Stage 3/4 — it's the known, already-documented "one verdict per queued item,
not per variable" limitation (see `ARCHITECTURE.md`'s "Known boundaries"),
observed here concretely instead of hypothetically.

## Setup

`data/recon.db` already has a full Stage 0-2 run against BlueBird from the
earlier writeup. This pass adds Stage 3+4:

```bash
.venv/bin/python -m pipeline.cli enqueue-trace --db data/recon.db
.venv/bin/python -m pipeline.cli trace --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird --db data/recon.db --model whiterabbitneo-33b:latest
```

## Step 1 — what Stage 3 assembled for `signupPOST`

```sql
SELECT queue_id, target_symbol_id, target_variable, status, assembled_context_symbol_ids
FROM trace_queue WHERE queue_id = 4;
```

```
queue_id  target_symbol_id  target_variable  status  assembled_context_symbol_ids
--------  ----------------  ---------------  ------  ----------------------------
4         17                (empty)          done    [17]
```

`target_variable` is empty and the context is just `[17]` (`signupPOST`
itself) — no other method got pulled in. This is Stage 3's
getter-name-matching heuristic (see `DATA_DICTIONARY.md`'s `trace_queue`
entry) correctly recognizing there's nothing to cross-reference: none of
`signupPOST`'s call edges (`name.isEmpty`, `password.equals`,
`BCrypt.hashpw`, `BCrypt.gensalt`, `this.jdbcTemplate.update`, ...) match the
getter pattern (`(?:^|\.)get([A-Z]\w*)$`) the heuristic looks for — verified
directly:

```python
>>> GETTER_RE.search("BCrypt.hashpw")
None
>>> GETTER_RE.search("BCrypt.gensalt")
None
```

This is the right call: `signupPOST`'s four concatenated variables
(`name`, `username`, `email`, `passwordHash`) are all either raw
`@RequestParam`s or a local transform of one (`passwordHash`), not a value
read back from another method's stored state. There's no second-order chain
here for Stage 3 to find — unlike `ProfileController.profile`, where the
same heuristic correctly pulls in `editProfilePOST` via the `email`
property (see `DATA_DICTIONARY.md`). So Stage 3 handed Stage 4 exactly the
right — and only — context: the method's own source, nothing more, nothing
less.

## Step 2 — what Stage 4 actually said

```sql
SELECT verdict, path_narrative, evidence_symbol_ids
FROM trace_results WHERE queue_id = 4;
```

```
verdict           path_narrative                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          evidence_symbol_ids
----------------  -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------  -------------------
exploitable_path  The method `signupPOST` takes user input from the request parameters 'name', 'username', 'email', 'password', and 'repeatPassword'. It checks if all fields are filled out. If they are not, it redirects to the signup page with an error message. If they are, it queries the database for the username and email using string concatenation in the SQL query. This is vulnerable because it directly uses user input without any validation or sanitization, which allows an attacker to perform SQL injection.  [17]
```

Stage 4 was shown the *exact same source lines* as a human would need to
answer the lab question — lines 155-180, including line 170
(`String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));`)
immediately before the concatenated INSERT at line 171. It had everything
required to say "three of these four variables are exploitable, but
`passwordHash` isn't, because it's BCrypt output." It didn't say that.
`path_narrative` never mentions `passwordHash` or `BCrypt` at all, and
`evidence_symbol_ids=[17]` only cites the whole method as one blob, not any
finer-grained distinction within it. The verdict (`exploitable_path`) is
directionally correct — the method genuinely is exploitable, via
`name`/`username`/`email` — but a report generator reading only this
structured row would have no way to know one of the four flagged variables
is actually safe.

## Step 3 — the answer still requires the same manual read

Nothing in Stage 3 or Stage 4's output changes what a human still has to do:
read `AuthController.java` lines 155-180 (same citation as the original
writeup) to see the literal `VALUES (...)` clause and confirm which
variables it names, then trace `passwordHash`'s one-line assignment back to
`BCrypt.hashpw`.

**Answer: `passwordHash`** — unchanged from the original writeup, and
obtained the same way: a targeted human read of the method Stage 0/3
correctly pointed at, not from anything in Stage 4's structured verdict.

## Why Stage 3/4 didn't help here, specifically

- **Stage 3's job is cross-method context assembly, and this question is
  single-method.** `signupPOST`'s four variables all live in one method
  body; there's no second-order chain to walk, so Stage 3 correctly handed
  Stage 4 nothing extra. Stage 3 isn't the bottleneck for this question —
  it did exactly what it should.
- **Stage 4's job is a path verdict, not a per-variable breakdown.**
  `trace_results.verdict`/`path_narrative`/`evidence_symbol_ids` are all
  scoped to one `trace_queue` row per method (or per cross-method chain),
  not per concatenated variable. Even with the BCrypt transform sitting one
  line above the sink in the exact context it was given, the model's
  summary collapsed all four variables into one generic "unsanitized user
  input" claim. This matches the same failure shape already observed
  elsewhere in this pipeline (`resetPOST`/`createPost` not being corrected
  by Stage 4 despite seeing their parameterized calls directly) — Stage 4
  restates the method's shape rather than reliably catching the one
  transformed value.
- **Fixing this would need a schema/prompt change, not a queueing change.**
  To get an automated per-variable answer, `trace_queue`/`trace_results`
  would need to represent one row per candidate variable within a sink
  (using `target_variable` for the direct-parameter case the same way it's
  already used for the cross-method case), and `trace_v1.txt` would need to
  ask the model to evaluate each named variable individually rather than
  the sink as a whole. That's a deliberate scope decision already flagged
  as a known limitation, not something this writeup's re-run changes.

## Where Stage 3/4 *does* add real value (for contrast)

This isn't a blanket verdict on Stage 3/4 — `ProfileController.profile`
(the `/profile/{id}` second-order case) is a clean counterexample: Stage 3
automatically discovered `editProfilePOST` as the same-file write site for
`profile`'s unsafely-reused `email` value (`target_variable="email"`,
`assembled_context_symbol_ids=[30, 32]`), something a human would otherwise
have to search for by hand, and Stage 4 traced it to `exploitable_path`.
The gap demonstrated here is specific to *this* lab's question shape (one
sink, several concatenated variables, only one of which is safe) — not a
general failure of Stage 3/4.
