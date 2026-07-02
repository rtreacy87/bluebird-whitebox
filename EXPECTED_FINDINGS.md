# BlueBird Regression Corpus -- Expected Findings

Ground truth for the three known BlueBird vulnerabilities referenced in
`CLAUDE.md`'s build order (Stage 1+2 must surface all three before Stage 3+
work proceeds). Source: `~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird/`
(decompiled, read-only). All line numbers below refer to that decompiled
source as it exists at commit time of this doc; re-verify if the corpus is
re-decompiled.

This file is pipeline metadata, not part of the source tree -- kept at the
repo root per CLAUDE.md's Testing section, deliberately not colocated with
the read-only decompiled artifact.

---

## 1. `/find-user` -- reflected/blind SQL injection

- **File**: `controller/IndexController.java`
- **Method**: `findUser(String u, Model model, HttpServletResponse response)` (entrypoint, `@GetMapping("/find-user")`), lines 51-77
- **Input source**: `u` via `@RequestParam`, line 52
- **Sink**: line 58 -- `String sql = "SELECT * FROM users WHERE username LIKE '%" + u + "%'"`, executed via `this.jdbcTemplate.query(sql, ...)` at line 59
- **Sink type**: `sql_unsafe` (string concatenation directly into a JDBC query, no parameterization)
- **Attempted validation**: lines 53-56 apply a regex blocklist (`'|(.*'.*'.*)`) rejecting a literal apostrophe or an already-balanced-quote pattern, plus a space check. This is a blocklist, not a parameterized query -- it does not eliminate the injection, it only raises the bar for exploitation. Expected triage output: `has_input=true`, `sink_type=sql_unsafe`, `validation_desc` should describe the regex as a weak/bypassable blocklist (not "safe"), `confidence` medium-high.
- **vuln_class** (for `findings.vuln_class` once verified): `blind_sqli` (query result differences are visible via the returned user list / error page, but there's no direct error-message echo of DB output on the happy path -- `BadSqlGrammarException` is caught and only logged server-side).

## 2. `/forgot` -- SQL injection via email parameter

- **File**: `controller/AuthController.java`
- **Method**: `forgotPOST(String email, Model model, HttpServletResponse response)` (entrypoint, `@PostMapping("/forgot")`), lines 120-152
- **Input source**: `email` via `@RequestParam`, line 121
- **Sink**: line 133 -- `String sql = "SELECT * FROM users WHERE email = '" + email + "'"`, executed via `this.jdbcTemplate.queryForObject(sql, ...)` at line 134
- **Sink type**: `sql_unsafe`
- **Attempted validation**: lines 126-130 apply a regex format check (`^.*@[A-Za-z]*\.[A-Za-z]*$`) intended to look like email validation. Because the pattern starts with `.*`, it does not restrict which characters can appear before the `@` -- a value like `' OR '1'='1@a.com` still matches. Expected triage output: `has_input=true`, `sink_type=sql_unsafe`, `validation_desc` should flag the regex as not actually constraining injection-relevant characters, `confidence` high.
- **vuln_class**: `error_based` is plausible (the `catch (Exception e)` branch at line 145 surfaces `e.getMessage()` and a full stack trace back into the `error` view via `model.addAttribute("errorMsg", ...)` / `errorStackTrace`, lines 146-147) -- human verification should confirm whether that view actually renders those attributes to the response body.

## 3. `/profile/{id}` -- second-order SQL injection via stored email

- **File**: `controller/ProfileController.java`
- **Method**: `profile(int id, Model model, HttpServletResponse response)` (entrypoint, `@GetMapping("/profile/{id}")`), lines 29-47
- **Input source**: `id` via `@PathVariable`, line 30 -- this first hop is safe (see below), which is exactly why this finding requires tracing rather than single-method triage.
- **First query (safe, not the vuln)**: line 33 -- `SELECT username, name, description, email, id FROM users WHERE id = ?`, parameterized via `new Object[]{id}`. Expected triage `sink_type=sql_safe` for this statement.
- **Sink (the vuln)**: line 40 -- `String sql = "SELECT text, ... FROM posts JOIN users ... WHERE email = '" + user.getEmail() + "'"`, executed via `this.jdbcTemplate.queryForList(sql)` at line 41. The concatenated value is `user.getEmail()`, i.e. data read back out of the `users` table by the safe query above, not the raw path variable.
- **Sink type**: `sql_unsafe`, but `has_input` for the *sink method itself* is indirect -- the raw request input (`id`) never appears in the unsafe string directly. This is the case `triage_results.needs_trace` / the "indirect flow flag" in the triage checklist exists for: the risk is that `email` is attacker-controlled *stored* data, not request data.
- **How attacker-controlled data reaches the stored field**: `email` is set via `@PostMapping("/profile/edit")` -> `editProfilePOST` (`ProfileController.java` line 57) or at signup via `@PostMapping("/signup")` -> `signupPOST` (`AuthController.java` line 154). Both of those writes use parameterized `UPDATE`/`INSERT` statements (`ProfileController.java` line 66/84/86, `AuthController.java` line 171-172 -- note `signupPOST`'s INSERT is itself string-concatenated, a second, separate unsafe sink worth flagging independently), so the write path does not filter or escape quote characters -- it just stores whatever string the user submitted, verbatim. That stored value is later read back and concatenated unsafely in `profile()`.
  `signupPOST`'s INSERT is the subject of its own dedicated writeup series (three angles on the same question -- "which of its four concatenated variables can't be exploited" -- see "Related writeups" at the end of this file).
- **vuln_class**: `second_order`
- **Trace expectation for Stage 3+4** -- Stage 3/4 are now built; this is what actually happened, not a forecast. `pipeline/stage3_trace/builder.py`'s `enqueue_trace_targets()` enqueues every `triage_results` row with `sink_type='sql_unsafe'` (not gated on `needs_trace` -- see below for why), and its same-file getter-name-matching heuristic correctly linked `profile` (reads `user.getEmail()`) to `editProfilePOST` (writes raw `email`) with `target_variable="email"` and `assembled_context_symbol_ids=[profile's symbol_id, editProfilePOST's symbol_id]`, entirely deterministically, no LLM involved in the matching itself. Stage 4 then traced this to `verdict='exploitable_path'`. Full mechanism: `DATA_DICTIONARY.md`'s `trace_queue` entry; full walkthrough: `ARCHITECTURE.md`'s "Stage 3 then Stage 4, step by step".
- **Why triage's `needs_trace` flag doesn't gate Stage 3's queue**: triage set `needs_trace=0` on `profile` despite this being exactly the "value came from a queried object, not the method's own parameter" case that flag exists to catch (see "What `needs_trace` is telling you" in `WALKTHROUGH.md` for the full narrative). Gating Stage 3 on `needs_trace` would have silently dropped this required regression case, so Stage 3 enqueues on `sink_type='sql_unsafe'` instead and treats `needs_trace` as informational only -- documented as a known boundary in `ARCHITECTURE.md`.

---

## Explicitly out of scope for this ground-truth file

- `IndexController.index()` (`/`, `q` param, line 34) concatenates `q` unsanitized into a `LIKE` query with **no validation at all** -- also a real, unauthenticated SQL injection. It is not one of the three vulnerabilities CLAUDE.md names as the regression gate, so it is not asserted on by the Stage 1/2 regression test, but the triage pass should still surface it (and if it doesn't, that's a signal about triage prompt quality worth noting, not a gate failure).
- `ServerInfoController.serverInfo()` (`/server-info`) calls `Runtime.exec` with a hardcoded, non-attacker-controlled command array -- a command-exec sink with no reachable input, not a finding.

## Related writeups

Companion documents that work through specific findings from this file in
much more depth than fits here, each demonstrating a different way of
answering the same underlying question -- of `AuthController.signupPOST`'s
four INSERT-concatenated variables (`name`, `username`, `email`,
`passwordHash`), which one can't be exploited:

- `tests/searching_for_strings.md` -- the manual, grep-based HTB Academy lab
  this corpus is drawn from. Ground truth: `passwordHash` (BCrypt output,
  fixed alphabet, no SQL metacharacters) is the one that can't be exploited.
- `tests/searching_for_strings_pipeline_writeup.md` -- solves the same
  question using only this pipeline's Stage 0-2 (static index, triage,
  audit) -- narrows the corpus to the right method via SQL queries against
  `data/recon.db` instead of `grep`, then a short human read of the cited
  lines to finish the answer.
- `tests/searching_for_strings_stage3_4_writeup.md` -- re-solves it again
  with Stage 3/4 (built after the above), and finds **no improvement** on
  this specific question: Stage 3 correctly determines `signupPOST` needs no
  cross-method context (there's no second-order chain here, unlike
  `profile`), but Stage 4's verdict is still one structured value per
  queued item, not per concatenated variable -- the same manual read is
  still required. Directly informs the "one verdict per queued item" known
  boundary in `ARCHITECTURE.md`.
- `tests/searching_for_strings_live_debug_writeup.md` -- confirms the
  answer empirically instead of by reading, using `tests/live-debugging.md`'s
  technique: a live breakpoint showing `passwordHash`'s real BCrypt value
  next to the untransformed `name`/`username`/`email`, then a literal
  apostrophe in `name` that reaches the query unescaped and crashes the
  app with a real Postgres syntax error -- proof the pipeline's static
  hypothesis holds against the running application.
- `tests/live-debugging.md` -- the general live-debugging methodology
  (VSCode/Eclipse + JDWP remote attach) the live-debug writeup above
  applies to this specific case.
