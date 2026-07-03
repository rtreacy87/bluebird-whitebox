---
tags: [writeup, pipeline-demo, dynamic-verification]
companion_to: tests/searching_for_strings.md, tests/searching_for_strings_stage3_4_writeup.md, tests/searching_for_strings_live_debug_writeup.md
last_updated: 2026-07-02
---

# Writeup: Re-solving "Searching for Strings" with Stage 4.5 (dynamic verification)

Two earlier writeups already answered this lab's question — *which variable
in `AuthController.signupPOST`'s INSERT concatenation cannot be exploited?*
— twice: once from static analysis alone
(`tests/searching_for_strings_stage3_4_writeup.md`, which found Stage 3/4's
structured verdict does not distinguish `passwordHash` from the other three
variables, leaving the answer to a manual read), and once by attaching a live
debugger to a running copy of BlueBird
(`tests/searching_for_strings_live_debug_writeup.md`, which got the answer by
watching `passwordHash` be BCrypt output in the Variables panel).

Stage 4.5 (dynamic verification) has since been built specifically to close
part of this gap: instead of a human manually crafting one apostrophe test in
a debugger, the pipeline now fires a fixed, non-destructive probe battery at
*every* request parameter on a flagged method automatically, and records what
happened as queryable rows. This writeup re-runs the same question through
Stage 4.5 to see how close that gets to a fully automated answer — and, where
it falls short, exactly why, using real evidence rather than a hypothetical
gap.

**Result: closer, but still not fully automatic — and it surfaces a new
nuance the earlier writeups didn't need to address.** Stage 4.5 correctly and
automatically identifies `name`, `username`, and `email` as exploitable (a
harmless `single_quote` probe crashes the app with a real
`BadSqlGrammarException` for each). It also correctly flags something is
*different* about `password` and `repeatPassword` — every probe against them,
including the harmless `baseline`, classifies `rejected`, a pattern that
never occurs for the three exploitable fields. But `classify_probe()` alone
cannot tell *why* they're both `rejected`: `password` actually does reach the
INSERT, just transformed into a BCrypt hash first; `repeatPassword` never
reaches the INSERT (or any query) at all — it exists only to be compared
against `password` for a match. One quick follow-up check (reading the app's
own log line for the literal SQL executed) resolves both at once. This is
exactly the intended shape of Stage 4.5 per `CLAUDE.md`: narrow the candidate
list and produce evidence, not replace the final human read.

## Setup

`data/recon.db` already has a full Stage 0-4 run against BlueBird from the
earlier writeups (`trace_results.trace_id = 4` is `signupPOST`'s
`exploitable_path` verdict — see
`tests/searching_for_strings_stage3_4_writeup.md`). This pass adds Stage 4.5.

**1. Describe `signupPOST`'s request shape once.** Stage 0 has no
route-path or sibling-parameter information to infer this from (see
`ARCHITECTURE.md`'s "Known boundaries"), so it's supplied directly:

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

**2. Stand up a disposable local replica** (recompiled decompiled source,
throwaway Postgres, the app started with explicit port/datasource overrides
so it definitely talks to *this* container):

```bash
.venv/bin/python -m pipeline.cli setup-target-env \
    --source ~/BlueBirdSourceCode \
    --schema-sql bluebird_target_schema.sql \
    --db-container-name s45-writeup-pg \
    --db-user bbuser --db-password bbpassword --db-name bluebird \
    --db-port 5435 --app-port 8083 \
    --db data/recon.db
# -> env_id=1
```

**3. Fire the battery** against every pending candidate `dynamic-probe` can
find a template for:

```bash
.venv/bin/python -m pipeline.cli dynamic-probe \
    --env-id 1 \
    --request-templates request-templates.json \
    --db data/recon.db
```

`candidates.pending_candidates()` (see `DATA_DICTIONARY.md`'s
`dynamic_probe_batches` entry) enumerates every `input_sources` row belonging
to `signupPOST` — that's all five of its `@RequestParam`s, not just the four
named in the INSERT's `VALUES` clause. This is worth flagging up front:
Stage 0 has no structural concept of "which parameters this specific sink's
query actually references," only "this method has a `sql_unsafe` sink," so
`repeatPassword` gets queued as a candidate here even though a quick read of
line 171 shows it was never part of the INSERT to begin with. Nothing here
is wrong — it's the same "candidate list, not a verdict" honesty the rest of
Stage 4.5 is built around — but it means the candidate list itself doesn't
tell you which of its members are even relevant to the original question.

## Step 1 — the three exploitable fields, confirmed automatically

```sql
SELECT b.target_param_name, r.probe_name, r.http_status, r.classification, r.input_value
FROM dynamic_probe_results r
JOIN dynamic_probe_batches b ON b.batch_id = r.batch_id
WHERE b.source_trace_id = 4 AND b.target_param_name IN ('name', 'username', 'email')
ORDER BY b.target_param_name, r.probe_name;
```

```
target_param_name  probe_name    http_status  classification          input_value
------------------  ------------  -----------  -----------------------  --------------------
email               backslash     200          passthrough_unmodified  b3_backslash_bs\x
email                baseline      200          passthrough_unmodified  b3_baseline_baseline
email                double_quote  200          passthrough_unmodified  b3_double_quote_dq"x
email                single_quote  500          error                    b3_single_quote_sq'x
name                 backslash     200          passthrough_unmodified  b1_backslash_bs\x
name                 baseline      200          passthrough_unmodified  b1_baseline_baseline
name                 double_quote  200          passthrough_unmodified  b1_double_quote_dq"x
name                 single_quote  500          error                    b1_single_quote_sq'x
username             backslash     200          passthrough_unmodified  b2_backslash_bs\x
username             baseline      200          passthrough_unmodified  b2_baseline_baseline
username             double_quote  200          passthrough_unmodified  b2_double_quote_dq"x
username             single_quote  500          error                    b2_single_quote_sq'x
```

For all three fields the pattern is identical, and it's the automatable
signal that matters: `baseline`/`double_quote`/`backslash` all classify
`passthrough_unmodified` (proving the verify-row lookup mechanism itself
works — a harmless value really does land in `users`, unmodified), while
`single_quote` alone flips to `error`. That divergence — same field, one
probe behaves differently from the other three — is exactly what a real
unescaped SQL sink looks like, and it required no human to craft a payload
or read a stack trace by hand. `app_log_snippet` on each `single_quote` row
(`probe_id` 2 for `name`, 6 for `username`, 10 for `email` — not reproduced
in full here, see `data/recon.db`) contains the real
`org.springframework.jdbc.BadSqlGrammarException`/
`org.postgresql.util.PSQLException: Unterminated string literal` text — the
same exception `tests/searching_for_strings_live_debug_writeup.md` found by
hand, just now captured automatically per-parameter instead of once,
manually, for whichever field a human happened to pick.

## Step 2 — `password` and `repeatPassword`: the same classification, for two different reasons

```sql
SELECT b.target_param_name, r.probe_name, r.http_status, r.classification, r.db_row_snippet
FROM dynamic_probe_results r
JOIN dynamic_probe_batches b ON b.batch_id = r.batch_id
WHERE b.source_trace_id = 4 AND b.target_param_name IN ('password', 'repeatPassword')
ORDER BY b.target_param_name, r.probe_name;
```

```
target_param_name  probe_name    http_status  classification  db_row_snippet
------------------  ------------  -----------  --------------  --------------
password             backslash     200          rejected
password             baseline      200          rejected
password             double_quote  200          rejected
password             single_quote  200          rejected
repeatPassword        backslash     200          rejected
repeatPassword        baseline      200          rejected
repeatPassword        double_quote  200          rejected
repeatPassword        single_quote  200          rejected
```

This is the interesting result: **every** probe against both fields —
including `baseline`, a completely harmless value — classifies `rejected`,
with an empty `db_row_snippet`. That's already a meaningfully different
signature from `name`/`username`/`email` above (where `baseline` reliably
finds a matching row), and it's something a report generator could flag
automatically: *"this parameter's harmless control value doesn't round-trip
either — investigate before trusting `rejected` at face value."* But
`classify_probe()`'s deterministic rules (see `ARCHITECTURE.md`'s "Known
boundaries" and `DATA_DICTIONARY.md`'s `dynamic_probe_results` entry) cannot
distinguish two very different underlying reasons for this pattern:

- `password` genuinely reaches the INSERT — just transformed into a BCrypt
  hash first, so a `LIKE '%nonce%'` lookup against the stored hash can never
  match the raw nonce, regardless of whether the value was accepted.
- `repeatPassword` never reaches *any* query at all — it's compared against
  `password` for equality and then discarded (confirmed statically: `grep -n
  "repeatPassword" ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java`
  shows it only ever appears in `!password.equals(repeatPassword)`, never in
  a query string).

Both look identical from `dynamic_probe_results` alone — this is the exact,
previously-documented "one-way transform" limitation, now demonstrated
concretely across two fields instead of hypothetically for one.

## Step 3 — resolving the ambiguity with one more piece of live evidence

Rather than trust the `rejected` classification at face value, one more
request against the same disposable replica (a fresh `env_id=2`, ports 8091/
5441, the earlier `env_id=1` already torn down) settles both fields at once,
by reading the app's own log for the literal SQL it tried to execute:

```bash
curl -s -i -X POST http://localhost:8091/signup \
  --data-urlencode "name=Inject'x" \
  --data-urlencode "username=writeupdemo2" \
  --data-urlencode "email=writeupdemo2@test.com" \
  --data-urlencode "password=DemoPass123" \
  --data-urlencode "repeatPassword=DemoPass123"
# -> HTTP/1.1 500
```

The app's log for that exact request:

```
ERROR ... threw exception [Request processing failed:
org.springframework.jdbc.BadSqlGrammarException: StatementCallback; bad SQL
grammar [INSERT INTO users (name, username, email, password) VALUES
('Inject'x', 'writeupdemo2', 'writeupdemo2@test.com',
'$2a$12$bOUXb2mn/gY5zZo9hc2EE.Ri9iL9mUFXrUnPXUsyKbktjkFPMYpEK')] with root
cause
org.postgresql.util.PSQLException: Unterminated string literal started at
position 174 in SQL INSERT INTO users (name, username, email, password)
VALUES ('Inject'x', 'writeupdemo2', 'writeupdemo2@test.com',
'$2a$12$bOUXb2mn/gY5zZo9hc2EE.Ri9iL9mUFXrUnPXUsyKbktjkFPMYpEK'). Expected  char
```

One log line answers both questions at once:

- **`password` reached the sink.** It's sitting right there in the literal
  `VALUES (...)` clause the app tried to run — as
  `$2a$12$bOUXb2mn/gY5zZo9hc2EE.Ri9iL9mUFXrUnPXUsyKbktjkFPMYpEK`, BCrypt's
  fixed output alphabet (letters, digits, `.`, `/`, `$`), not the raw
  `DemoPass123` that was sent. No single quote, no SQL keyword, nothing an
  attacker controls survives the hash. This is why `rejected` was
  misleading: the value wasn't rejected by validation, it was accepted and
  transformed before it ever reached the query.
- **`repeatPassword` never reached this sink at all.** The `VALUES` clause
  only names four columns — `name, username, email, password` — exactly as
  `tests/searching_for_strings.md`'s original static answer found. There is
  no fifth value, no `repeat_password` column, nothing to inject into,
  because the field was already consumed and discarded before this line ran.

A quiet baseline signup against the same replica confirms the same thing
without an exception in the way:

```sql
SELECT id, name, username, email, password FROM users WHERE username = 'writeupdemo1';
```
```
 id |     name     |   username   |         email         |                           password
----+--------------+--------------+------------------------+--------------------------------------------------------------
  1 | Writeup Demo | writeupdemo1 | writeupdemo1@test.com | $2a$12$iS6cIon4Y.rHZs5SzWNkreS2ReyH87MgswU1h9BW9AaqHf3OT66S2
```

A real row, with a real 60-character BCrypt hash in the `password` column —
`DemoPass123` is nowhere in it.

## Conclusion

**Answer: `passwordHash` — unchanged from both earlier writeups**, but this
time the exploitable fields (`name`, `username`, `email`) were confirmed
without a human crafting a single payload: Stage 4.5's fixed probe battery
found the divergence (`single_quote` alone breaking the query) automatically
and recorded it as queryable rows. The safe field required one extra,
still-manual step — reading a log line to see the BCrypt hash sitting where
raw input would otherwise be — because `classify_probe()`'s rules, by
design, can't see through a one-way transform (see `ARCHITECTURE.md`'s
"Known boundaries" for why this is an accepted, documented gap rather than a
bug to silently patch over).

The genuinely new finding this pass adds: `repeatPassword` is *also*
non-exploitable, and Stage 4.5 flagged it as worth a second look (uniform
`rejected` across every probe, same as `password`) — but for a reason that
has nothing to do with hashing. It's simply never part of the query at all.
Neither earlier writeup needed to address this, because a human reading
`AuthController.java` naturally skips a variable that isn't named in the
`INSERT`'s `VALUES` clause. Stage 4.5's candidate selection doesn't have
that context (see "Setup" above) — it queues every request parameter on a
flagged method, then leans on dynamic evidence to sort out which ones
matter, rather than trying to statically parse which columns a query
actually names.

## What this demonstrates about Stage 4.5, concretely

- **It closes the "which field, specifically" gap Stage 3/4 couldn't** —
  see `tests/searching_for_strings_stage3_4_writeup.md`'s "no improvement on
  this specific question." Firing the same probe battery at every parameter
  independently gets a per-parameter signal Stage 4's one-verdict-per-method
  `trace_results` row structurally cannot.
- **It doesn't fully replace the live-debug approach** — it replaces the
  part live-debugging is best at (proving an ordinary character breaks the
  query, per-field, repeatably) but not the part that needs a human to
  reason about *why* a uniform `rejected` happened. `interpret_ambiguous()`
  (the local-LLM interpretation step) only fires for `classification =
  'ambiguous'`, not `rejected` — a deliberate scope boundary, since
  `rejected` is a confident, if occasionally wrong, deterministic call, not
  an uncertain one the rules themselves flagged as unclear.
- **The candidate list can include fields irrelevant to the original
  question, and that's fine.** `repeatPassword` being queued at all, despite
  never being in the INSERT, is a real, working example of "Stage 4.5 hands
  a human a prioritized list, it doesn't hand them a finished report" — the
  same framing `CLAUDE.md`'s Dynamic Verification section and `README.md`'s
  "When it's not" section already commit to.

## What was actually run for this writeup

Every result shown above is real output from an actual run against a
disposable local BlueBird replica, not a reconstruction:
- `dynamic_probe_batches`/`dynamic_probe_results` for `source_trace_id = 4`
  (`env_id = 1`, ports 8083/5435) were produced by a real `dynamic-probe`
  run earlier in this same working session; the exact rows are still in
  `data/recon.db` and reproducible via the queries above.
- The Step 3 log line and `users` row came from a second, freshly stood-up
  disposable replica (`env_id = 2`, ports 8091/5441, `s45-writeup-pg`) spun
  up, probed by hand via `curl`, and torn down specifically for this
  writeup — kept on different ports/container name from both `env_id = 1`
  and the user's own separately-running BlueBird instance (port 8080/5432,
  from the live-debugging writeup) so neither was disturbed.
  `teardown-target-env --env-id 2` confirmed the container removed and the
  app process gone before this writeup was finished.
