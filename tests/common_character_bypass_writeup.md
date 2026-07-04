---
tags: [writeup, pipeline-demo, dynamic-verification]
companion_to: tests/searching_for_strings_stage4_5_writeup.md, EXPECTED_FINDINGS.md, sqlmap-wrapper/CLAUDE.md
last_updated: 2026-07-03
---

# Writeup: The "Common Character Bypass" lab (`/find-user`), run through the current tool

The HTB "Common Character Bypasses" lab targets `GET /find-user?u=`, an
endpoint with a space filter and a single-quote-count filter guarding a
concatenated SQL query. Solving it requires: recognizing a Java
`Matcher.matches()` semantics trap, building a payload that survives both
filters (`/**/` for spaces, PostgreSQL dollar-quoting instead of a second
single quote), discovering that the response's `<a href="/profile/ID">`
link is a usable data-exfiltration channel, and writing a blind
character-by-character extraction script. This writeup runs that same
target through the current pipeline — Stage 0-4 (static), Stage 4.5
(dynamic) — end to end, actually executing everything (nothing here is
hypothetical), to give a precise, evidence-backed answer to "what does this
tool actually get you for a lab like this, and where does a human still
have to take over."

**Result, up front:** Stage 0-4 correctly flags the sink and traces it to
`exploitable_path` — but both the triage and trace narratives describe the
method as having "no validation," when a real, non-trivial blocklist filter
sits directly above the sink. This directly falls short of this project's
own pre-written expectation for this exact endpoint (see
`EXPECTED_FINDINGS.md`, quoted below). Stage 4.5, run as it exists today
(no cookie/session support), produces a uniformly wrong "rejected" result
across all four probes — not because the endpoint is safe, but because
every probe request gets redirected to the login page before ever reaching
the vulnerable code, and Stage 4.5 has no way to know that. Simulating what
Stage 4.5 *would* see with authentication (real requests, fed through the
real `classify_probe()` function) surfaces something more specific and more
interesting: a **confident false negative**, not just an ambiguous result —
the exact payload that breaks the query still classifies `rejected`,
because the endpoint catches its own SQL exception and logs only the bare
message text, with no exception class name for `classify_probe()`'s marker
check to find. Everything past "this sink is unsafe" — the filter-bypass
payload, the exfiltration channel, the extraction script — is squarely
manual work; none of it is attempted by this tool, and none of it should
be, per `CLAUDE.md`.

## Setup

Real disposable BlueBird replica (recompiled decompiled source, throwaway
Postgres container, `env_id=4`, ports 8097/5450 — kept off the user's own
long-running BlueBird session on 8080/5432). Two real users signed up
(`attacker1`, the account used to authenticate; `victim@test.com`, the
target whose password hash is being exfiltrated), plus 128 filler rows
inserted directly via SQL so the `users.id` column spans a wide enough
range for the ASCII-value exfiltration technique to have something to
match against (see "What required a human" below for why this matters and
why it's a real, separate discovery in its own right).

## Step 1 — What Stage 0-4 (static analysis) found

```sql
SELECT tr.symbol_name_raw, tr.sink_type, tr.confidence, tr.validation_desc, tr.needs_trace
FROM triage_results tr WHERE tr.symbol_name_raw = 'findUser';
```
```
symbol_name_raw  sink_type   confidence  validation_desc                                                                                    needs_trace
---------------  ----------  ----------  -------------------------------------------------------------------------------------------------  -----------
findUser         sql_unsafe  high        The input 'u' is directly concatenated into the SQL query without any validation or sanitization.  0
```

```sql
SELECT tres.verdict, tres.path_narrative FROM trace_results tres
JOIN trace_queue tq ON tq.queue_id = tres.queue_id
WHERE tq.target_symbol_id = (SELECT symbol_id FROM symbols WHERE name = 'findUser');
```
```
verdict           path_narrative
----------------  ---------------------------------------------------------------------------------------------------------------------------------------------------------
exploitable_path  The attacker-controlled input 'u' is directly concatenated into the SQL query without any validation or sanitization. This allows an attacker to inject...
```

The sink is correctly identified (`sink_type=sql_unsafe`, `confidence=high`,
traced to `exploitable_path`) — Stage 0's structural index correctly found
the `@RequestParam String u` input source and the string-concatenated
`jdbcTemplate.query(sql, ...)` sink, and Stage 3/4 correctly walked that
single-method chain with no cross-method context needed (mirroring
`tests/searching_for_strings_stage3_4_writeup.md`'s finding that Stage 3/4
does the right thing when there's genuinely nothing to trace).

**But both narratives say "without any validation or sanitization" — and
that's not true.** The real source, immediately above the sink:

```java
Pattern p = Pattern.compile("'|(.*'.*'.*)");
Matcher m = p.matcher(u);
String u2 = u.toLowerCase();
if (!u2.contains(" ") && !m.matches()) {
   // ... sql executes here ...
```

There is a real filter — a space check and a regex blocklist — sitting
directly between the request parameter and the query. It's a *bad* filter
(that's the whole point of the lab), but it exists, and a report reader
relying only on `validation_desc`/`path_narrative` would have no idea it's
there at all, let alone that it's bypassable.

**This isn't a new gap — it's exactly the gap this project's own ground
truth already predicted.** `EXPECTED_FINDINGS.md`'s `/find-user` entry,
written before this run, says:

> **Attempted validation**: lines 53-56 apply a regex blocklist
> (`'|(.*'.*'.*)`) rejecting a literal apostrophe or an already-balanced-quote
> pattern, plus a space check. This is a blocklist, not a parameterized
> query — it does not eliminate the injection, it only raises the bar for
> exploitation. **Expected triage output**: ... `validation_desc` should
> describe the regex as a weak/bypassable blocklist (not "safe")...

The actual `validation_desc` doesn't describe the regex at all — it
describes the input as unvalidated. This is a direct, measurable miss
against this project's own documented bar for this endpoint, not a
hypothetical concern. It's the same class of failure
`tests/searching_for_strings_stage3_4_writeup.md` already found for
`signupPOST` (Stage 4 shown the exact `BCrypt.hashpw()` line and still
describing the whole method as uniformly unsanitized) — here it recurs on
a *filtered* endpoint, which matters more, since "no validation" and
"validation exists but is bypassable" call for different next steps from a
human reader.

## Step 2 — Running Stage 4.5 as it exists today: a uniformly wrong "rejected"

`/find-user` is behind Spring Security (`WebSecurityConfig.java`'s
`anyRequest().authenticated()` — it's not in the `permitAll()` list).
Stage 4.5's `probes.fire_probe()` has no cookie/session/header support at
all — it only ever sends the target parameter (and any `param_defaults`
siblings). Running the real `dynamic-probe` CLI against `findUser` produces:

```bash
.venv/bin/python -m pipeline.cli dynamic-probe --env-id 4 \
    --request-templates ccb-request-templates.json --no-llm-interpret --db data/recon.db
# {'batches': 1, 'probes': 4, 'rejected': 4, ...}
```

```sql
SELECT probe_name, http_status, classification FROM dynamic_probe_results r
JOIN dynamic_probe_batches b ON b.batch_id = r.batch_id WHERE b.target_param_name = 'u';
```
```
probe_name    http_status  classification
------------  -----------  --------------
baseline      200          rejected
single_quote  200          rejected
double_quote  200          rejected
backslash     200          rejected
```

Every probe's `response_snippet` is the **login page** ("Log In / BlueBird"),
not `find-user`'s own page. `requests.get()` follows redirects by default,
so the real chain was: unauthenticated request → Spring Security's `302`
to `/login` → followed → `200` on the login form. `classify_probe()` sees a
clean `200` with no error marker and no DB row to check, and calls it
`rejected` — the same label it would give a value that was genuinely
validated away. **There is no way, from this DB row alone, to distinguish
"the filter blocked this" from "this request never got anywhere near the
filter."** This is a real, current, unqualified limitation: Stage 4.5
cannot dynamically verify an authenticated endpoint at all right now, and
running it anyway produces a confidently wrong signal rather than an error
or a skip.

## Step 3 — What Stage 4.5 *would* see, with authentication (simulated with real requests + the real classifier)

To find out what closing that gap would actually reveal — not guess — real
authenticated requests (a genuine JWT cookie from a real `/login`, attached
by hand outside the pipeline) were fired with the *exact* values
`probes.probe_value()` generates for a batch:

| probe | value sent | what actually happened |
|---|---|---|
| `baseline` | `b1_baseline` | normal `find-user` results page, `200` |
| `single_quote` | `b1_sq'x` | **"Invalid search query"** — passed the filter, broke the SQL | 
| `double_quote` | `b1_dq"x` | normal `find-user` results page, `200` |
| `backslash` | `b1_bs\x` | normal `find-user` results page, `200` |

`single_quote` genuinely reaches and breaks the query — real, observed,
reproducible. Feeding the *actual* captured evidence for that exact request
into the real `classify.classify_probe()` function:

```python
>>> from pipeline.stage4_5_dynamic_verify.classify import classify_probe
>>> real_log_tail = ("Unterminated string literal started at position 50 in SQL "
...                   "SELECT * FROM users WHERE username LIKE '%b1_sq'x%'. Expected  char")
>>> classify_probe(http_status=200, app_log_tail=real_log_tail, db_row_value=None, input_value="b1_sq'x")
'rejected'
```

**`rejected` — for the one probe that demonstrably broke the query.** This
is a sharper, more specific finding than Stage 4.5's already-documented
BCrypt limitation (`ARCHITECTURE.md`'s "Known boundaries": a hashed value
misreading as `rejected` is at least an *honest* "can't tell" case hiding
behind a confident label). Here the mechanism is different and more subtle:

- `http_status` never reaches `500`, because `IndexController.findUser()`
  catches its own `BadSqlGrammarException` and renders a normal `error`
  view — so `classify_probe()`'s first, strongest check (`status>=500` +
  error marker) can never fire for this endpoint, no matter what breaks.
- The catch block only logs `e.getSQLException().getMessage()` — the bare
  PostgreSQL message text (`"Unterminated string literal started at
  position 50 ..."`), never the exception's class name or a full stack
  trace. None of `classify.py`'s `_ERROR_MARKERS`
  (`BadSqlGrammarException`/`PSQLException`/`SQLException`/`Exception`)
  appear anywhere in that message, so even the log-based fallback signal
  Stage 4.5 relies on elsewhere (see the `signupPOST` writeups, where the
  *uncaught* exception's full class-qualified stack trace *did* contain
  these markers) is silently absent here.

The result: a value that unambiguously reached and broke the sink reads
identically to a value that never got near it. This is a real, newly
discovered edge case in `classify_probe()`'s priority order — worth adding
to `ARCHITECTURE.md`'s "Known boundaries" (see below) — not a hypothetical
one; it required actually reproducing the endpoint's real exception-handling
behavior to find.

## Step 4 — What required a human (all of this is out of scope for this tool, deliberately)

Everything from here on is exactly the kind of "map and explain, not
attack" boundary `CLAUDE.md` draws — none of it was, or should be, produced
by this pipeline:

1. **Reading `Matcher.matches()` correctly.** `'|(.*'.*'.*)` blocks a value
   that is *exactly* a single quote, or contains *two or more* single
   quotes — but allows exactly one, anywhere, as long as the whole string
   isn't just `'`. Confirmed directly against the real running app:

   | payload | filter verdict |
   |---|---|
   | `'` (lone quote) | blocked — "Illegal search term" |
   | `'x` (one quote, not alone) | **passes** — reaches the query, breaks it: "Invalid search query" |
   | `'x'y` (two quotes) | blocked — "Illegal search term" |
   | `a b` (a space) | blocked — "Illegal search term" |

   Nothing in this pipeline reasons about regex semantics at this level —
   Stage 1/2's `validation_desc`/audit checks for the *presence* of
   validation-shaped keywords and structural facts, never simulates what a
   specific regex actually accepts or rejects.
2. **Building the bypass payload.** `/**/` in place of every space
   (PostgreSQL treats a multi-line comment as whitespace, and it contains
   no literal space characters), and PostgreSQL dollar-quoting (`$$...$$`)
   in place of the second single quote a normal string literal would need.
   `CLAUDE.md` explicitly bans this pipeline from ever generating a bypass
   string; Stage 4.5's four probes are fixed and generic by design (never
   endpoint-specific), so this had to be hand-built.
3. **Finding and using the exfiltration channel.** The `id` value in the
   query result gets rendered into `<a href="/profile/ID">` by Thymeleaf.
   Forcing `id` to equal a subquery's result turns an ordinary search page
   into a one-value-per-request oracle:
   ```
   '/**/AND/**/id=(SELECT/**/id/**/FROM/**/users/**/WHERE/**/email=$$victim@test.com$$)--
   ```
   real response: `href="/profile/2"` — matching the victim's real
   database id exactly. No part of this pipeline inspects rendered HTML for
   a reusable side-channel like this; that's a human noticing what the
   *application* does with a value, not what the *database* does with it.
4. **A real, separate discovery: the exfiltration channel needs a dense
   `id` keyspace, and that's an environmental fact, not a source-code
   fact.** The first extraction attempt (`SELECT LENGTH(password) ...`,
   expecting `60`) returned nothing — because the disposable replica only
   had 2 real users, so no row had `id=60` for the `id=(...)` condition to
   ever match. The lab's technique only works because whatever `users` rows
   already exist happen to span the ASCII range being read out. This was
   fixed by inserting 128 filler rows directly via SQL (ids 3-130) — a
   step that has nothing to do with reading `IndexController.java` and
   everything to do with the live data shape, which no static or dynamic
   analysis of *this* application's source could ever predict for a real,
   unknown target. A human still has to check what data actually exists.
5. **Writing and running the blind extraction.** With the payload and
   channel established, a small Python loop (not part of this pipeline)
   extracted the victim's real password hash character by character:
   ```
   password length: 60
   extracted hash: $2a$12$KHitxNBz58xumVi6BQcNqea3jtf0xn2Q5KqMgrmf/JPQcMkyCOCJ6
   ```
   Verified byte-for-byte against `SELECT password FROM users WHERE
   email='victim@test.com'` on the real container: **exact match.** This is
   full, working exploitation — 60 real HTTP requests, a real extracted
   secret — entirely outside this codebase, exactly where `CLAUDE.md` says
   it belongs.

## What this demonstrates about the tool, concretely

- **Static analysis (Stage 0-4) finds the right sink but can materially
  understate the obstacle in front of it.** `sink_type=sql_unsafe` /
  `exploitable_path` are both correct and useful triage signals — but
  `validation_desc`/`path_narrative` claiming "no validation" when a real,
  named, line-cited filter exists is a concrete miss against this
  project's own pre-written expectation for this exact endpoint. A report
  reader trusting the narrative text alone would under-estimate how much
  work is actually required, or not know to look for a filter at all.
- **Stage 4.5 cannot currently test authenticated endpoints, and running
  it anyway doesn't fail loudly — it produces a plausible-looking, uniform
  `rejected` result that is entirely wrong.** This is a sharper problem
  than "doesn't work" — a silent, confident false negative is worse than
  an explicit "can't test this" error, because nothing about the output
  flags that anything went wrong. Extending `request-templates.json`
  and `fire_probe()`/`run_battery()` to carry cookies/headers is a
  concrete, scoped next step this writeup surfaces but does not implement.
- **Even with authentication, `classify_probe()` has a real blind spot for
  endpoints that catch their own SQL exceptions and log only the bare
  message.** This is distinct from (and more specific than) the
  already-documented BCrypt/one-way-transform gap — that one produces an
  honestly-uncertain-looking `rejected`; this one produces a `rejected`
  that looks exactly as confident as a correct one, for a value that
  provably broke the query.
- **The actual bypass — regex semantics, `/**/`, dollar-quoting, the
  Thymeleaf `href` channel, the blind extraction script — is 100% manual,
  and that's correct, not a gap.** None of it fits Stage 4.5's fixed,
  generic, four-probe design, and `CLAUDE.md` explicitly reserves this
  category of work for a human or for `sqlmap-wrapper/`'s wrapped `sqlmap`.
  Notably, `sqlmap` ships a `--tamper=space2comment` script that performs
  exactly the `/**/`-for-space substitution used here — real, independent
  confirmation that `sqlmap-wrapper/CLAUDE.md`'s decision to **never
  default a tamper script**, only add one once a human has actually
  observed filtering behavior, is the right call: this lab is a concrete
  case where a human noticing "there's a space filter" is the prerequisite
  for picking the right tamper script, not something to guess up front.
  Neither the quote-count regex trap nor the `href`-as-exfiltration-channel
  trick would be found by `sqlmap` either, tamper script or not — both are
  specific to how *this* application is written, not generic SQLi evasion.

## Suggested follow-up (not implemented here)

- Add cookie/header support to `request-templates.json` and
  `fire_probe()`/`run_battery()` so Stage 4.5 can dynamically verify
  authenticated endpoints instead of silently misreading them.
- Add `ARCHITECTURE.md`/`DATA_DICTIONARY.md` "Known boundaries" entries for
  the two failure modes found here: (1) authenticated endpoints currently
  misclassify as `rejected` across the board; (2) an endpoint that catches
  its own SQL exception and logs only the bare message (no exception class
  name) can misclassify a query-breaking value as `rejected` even with
  authentication working correctly.

## What was actually run for this writeup

Every result above is real: a real disposable BlueBird replica (`env_id=4`,
ports 8097/5450, recompiled from `~/BlueBirdSourceCode`), a real signup and
login producing a real JWT, real `dynamic-probe` and `classify_probe()`
invocations against the real pipeline code (not a reconstruction), and a
real 60-request blind extraction whose output was verified character-for-
character against the container's actual `users.password` column. The
environment was fully torn down (container removed, app process killed,
ports confirmed clear) before this writeup was finished, without touching
the user's own separately-running BlueBird instance on port 8080/5432.
