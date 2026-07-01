---
tags: [writeup, pipeline-demo]
companion_to: tests/searching_for_strings.md
last_updated: 2026-07-01
---

# Writeup: Solving "Searching for Strings" with the recon pipeline

`tests/searching_for_strings.md` solves this lab by hand with `grep` against
decompiled BlueBird source. This writeup answers the same question — *which
variable in `AuthController.java`'s INSERT query cannot be exploited?* — using
this repo's pipeline instead, to see how far Stage 0 (static index), Stage 1
(triage), and Stage 2 (audit) get you without opening the JAR blind.

**Result: solvable.** The pipeline narrows a 14-file/121-symbol corpus down to
one exact method and one exact line where a transform happens right before the
sink; a short, precisely-cited read of the source finishes the job. Stage 3/4
(deep-trace) don't exist yet (see `CLAUDE.md`'s build order) — this is what
using the tool *as designed today* looks like: Stage 0-2 map and narrow,
a human verifies the final line of reasoning.

## Setup

The BlueBird corpus was already indexed, triaged, and audited into
`data/recon.db` (14 files, 121 symbols, 67 triage rows, 71 audit rows). The
commands that produced it (per `README.md`):

```bash
.venv/bin/python -m pipeline.cli index  --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird --db data/recon.db
.venv/bin/python -m pipeline.cli triage --source ~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird --db data/recon.db --model whiterabbitneo-33b:latest
.venv/bin/python -m pipeline.cli audit  --db data/recon.db --model whiterabbitneo-33b:latest
```

Everything below queries that existing database with plain `sqlite3`.

## Step 1 — narrow to INSERT/UPDATE candidates via SQL, not grep

The lab's first move is `grep -rn "INSERT" BOOT-INF/classes/ --include="*.java"`.
The pipeline equivalent: join Stage 1's `sink_type='sql_unsafe'` triage
verdicts against Stage 0's `call_edges` for a callee name Spring's
`JdbcTemplate` uses for non-`SELECT` DML (`.update(...)`, covering INSERT,
UPDATE, and DELETE):

```sql
SELECT f.path, s.name AS symbol_name, s.line_start, s.line_end,
       tr.sink_type, tr.needs_trace, tr.confidence
FROM triage_results tr
JOIN symbols s ON s.symbol_id = tr.symbol_id
JOIN files f ON f.file_id = s.file_id
WHERE tr.sink_type = 'sql_unsafe'
  AND EXISTS (
    SELECT 1 FROM call_edges ce
    WHERE ce.caller_symbol_id = s.symbol_id
      AND ce.callee_raw_name LIKE '%jdbcTemplate.update%'
  )
ORDER BY f.path, s.line_start;
```

Output:

```
path                               symbol_name      line_start  line_end  sink_type   needs_trace  confidence
---------------------------------  ---------------  ----------  --------  ----------  -----------  ----------
controller/AuthController.java     resetPOST        103         118       sql_unsafe  1            high
controller/AuthController.java     signupPOST       155         180       sql_unsafe  1            high
controller/PostController.java     createPost       19          27        sql_unsafe  0            high
controller/ProfileController.java  editProfilePOST  58          95        sql_unsafe  0            high
```

Four candidates out of 121 symbols — the same narrowing the lab's `grep`
achieves, done structurally. (Two of these four are false positives; see
**Limitations** below — the lab's own grep output already tells you
`PostController.java:22` and `AuthController.java` line 112's reset flow use
`?` placeholders, i.e. they're safe. `AuthController.java:171`'s `signupPOST`
is the real hit, matching the lab's expected output exactly.)

## Step 2 — inspect Stage 1 triage for `signupPOST`

```sql
SELECT s.name, tr.sink_type, tr.needs_trace, tr.confidence, tr.validation_desc
FROM triage_results tr JOIN symbols s ON s.symbol_id = tr.symbol_id
WHERE s.name = 'signupPOST';
```

Output:

```
name        sink_type   needs_trace  confidence  validation_desc
----------  ----------  -----------  ----------  ---------------------------------------------------------------
signupPOST  sql_unsafe  1            high        The method takes request parameters 'name', 'username', 'email',
                                                  'password', and 'repeatPassword'. It checks if all fields are
                                                  filled out. If they are not, it redirects to the signup page
                                                  with an error message. If they are, it queries the database for
                                                  the username and email using string concatenation in the SQL
                                                  query.
```

This confirms `signupPOST` is worth a closer look (`sql_unsafe`,
`needs_trace=1`, `high` confidence) and lists the five request parameters.
It does **not** name `passwordHash`, mention `BCrypt`, or break the four
concatenated variables down individually — Stage 1's `validation_desc` is a
per-method summary, not a per-variable one.

## Step 3 — inspect Stage 0 ground truth for the same method

Stage 0's `input_sources` confirms the untrusted entry points:

```sql
SELECT param_name, kind, line_no FROM input_sources
WHERE symbol_id = (SELECT symbol_id FROM symbols WHERE name='signupPOST');
```

```
param_name      kind          line_no
--------------  ------------  -------
name            RequestParam  155
username        RequestParam  155
email           RequestParam  155
password        RequestParam  155
repeatPassword  RequestParam  155
```

And `call_edges`, ordered by line, shows the call sequence inside the method:

```sql
SELECT callee_raw_name, resolved, line_no FROM call_edges
WHERE caller_symbol_id = (SELECT symbol_id FROM symbols WHERE name='signupPOST')
ORDER BY line_no;
```

```
callee_raw_name                   resolved  line_no
---------------------------------  --------  -------
name.isEmpty                       0         156
username.isEmpty                   0         156
email.isEmpty                      0         156
password.isEmpty                   0         156
repeatPassword.isEmpty             0         156
password.equals                    0         157
response.sendRedirect              0         158
this.jdbcTemplate.queryForObject   0         162
response.sendRedirect              0         163
this.jdbcTemplate.queryForObject   0         167
response.sendRedirect              0         168
BCrypt.hashpw                      0         170
BCrypt.gensalt                     0         170
this.jdbcTemplate.update           0         172
response.sendRedirect              0         173
response.sendRedirect              0         178
```

The load-bearing signal is right there: `BCrypt.hashpw`/`BCrypt.gensalt` at
line 170, immediately before `this.jdbcTemplate.update` at line 172 — a
transform call sitting directly in front of the sink. (`resolved=0` on every
row here just means these are all external-library/framework calls, not
unresolved cross-file application code — expected and not a gap.)

## Step 4 — targeted human read of the cited lines

Stage 0-2 has now narrowed the question to exactly one method and pointed at
exactly one line (170) worth reading closely. Reading
`~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird/controller/AuthController.java`,
lines 155-180:

```java
@PostMapping({"/signup"})
public void signupPOST(@RequestParam String name, @RequestParam String username, @RequestParam String email, @RequestParam String password, @RequestParam String repeatPassword, HttpServletResponse response) throws IOException {
   if (!name.isEmpty() && !username.isEmpty() && !email.isEmpty() && !password.isEmpty() && !repeatPassword.isEmpty()) {
      if (!password.equals(repeatPassword)) {
         response.sendRedirect("/signup?e=The+passwords+you+entered+do+not+match");
      } else {
         try {
            String sql = "SELECT * FROM users WHERE username = ?";
            User user = (User)this.jdbcTemplate.queryForObject(sql, new Object[]{username}, new BeanPropertyRowMapper(User.class));
            response.sendRedirect("/signup?e=This+username+is+already+taken");
         } catch (Exception var10) {
            try {
               String sql = "SELECT * FROM users WHERE email = ?";
               User user = (User)this.jdbcTemplate.queryForObject(sql, new Object[]{email}, new BeanPropertyRowMapper(User.class));
               response.sendRedirect("/signup?e=This+email+address+is+already+taken");
            } catch (Exception var9) {
               String passwordHash = BCrypt.hashpw(password, BCrypt.gensalt(12));
               String sql = "INSERT INTO users (name, username, email, password) VALUES ('" + name + "', '" + username + "', '" + email + "', '" + passwordHash + "')";
               this.jdbcTemplate.update(sql);
               response.sendRedirect("/login?e=Account+was+created");
            }
         }
      }
   } else {
      response.sendRedirect("/signup?e=Please+fill+out+all+fields");
   }
}
```

This is the last-mile step no Stage 0-2 table performs: enumerating the
literal variables inside a string-concatenated SQL statement, and confirming
which of them passed through a transform first. The four variables in the
INSERT's `VALUES` clause are `name`, `username`, `email`, `passwordHash`.

## Answer

**`passwordHash` cannot be exploited.** It's the output of
`BCrypt.hashpw(password, BCrypt.gensalt(12))` — always a 60-character string
restricted to `[A-Za-z0-9./$]`. No SQL metacharacter (quote, dash, semicolon)
survives that transform, so nothing in `password`'s original value reaches
the query string intact. `name`, `username`, and `email` remain exploitable —
they're raw `@RequestParam` values concatenated with zero transformation.

This matches `tests/searching_for_strings.md`'s documented answer exactly.

## Limitations observed

- **Triage's `sink_type` is per-method, not per-statement or per-variable.**
  The Step 1 query returned 4 candidates, but 2 are false positives:
  `resetPOST` (line 112's actual DML call is
  `this.jdbcTemplate.update(sql, new Object[]{passwordHash, ...})` —
  parameterized) and `createPost` (`PostController.java:22` uses `?`
  placeholders per the lab's own grep output). Triage flagged both
  `sql_unsafe` anyway, likely because another statement earlier in the same
  method looked unsafe to the model, or because the model conflated
  concatenation elsewhere with the DML call itself. A human still has to read
  each candidate's cited lines to filter these out — the pipeline narrows the
  search, it doesn't replace the final read.
- **No table records "which literal variables feed a concatenated SQL
  string" or "was this variable's value transformed before the sink."**
  That per-variable data-flow judgment — exactly the kind of question this
  lab asks — is what `trace_queue.target_variable` and
  `trace_results.evidence_symbol_ids` are designed for once Stage 3 (trace
  worklist) and Stage 4 (deep-trace) are built. Today, reaching that last
  step is a manual, human-verified read of a short, precisely-cited range —
  which is consistent with this tool's stated job ("map and explain," not
  "decide"), but it's worth knowing that's a deliberate, current-stage gap
  and not a design oversight.
