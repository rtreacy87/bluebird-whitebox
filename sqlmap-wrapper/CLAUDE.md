# CLAUDE.md — sqlmap-wrapper

Guidance for Claude Code when working in this subtree specifically. This is
a governance document distinct from `../CLAUDE.md` (the parent
`bluebird-whitebox` recon pipeline's spec) — read that file too, but do not
assume its rules apply here unmodified. Where the two disagree for this
subtree, this file wins.

## Why this tool exists, and why it's governed separately

`../CLAUDE.md`'s "What NOT to build here" section bans automated
exploitation-technique execution in the parent recon pipeline, with one
named exception:

> The one narrow exception is Stage 4.5's fixed, versioned probe battery
> ... and exists purely to turn a static hypothesis into an
> evidence-backed, prioritized candidate list for a human to hand to a
> **separate, human-directed tool (e.g. sqlmap)** — it does not itself
> perform exploitation ... Outside that one exception, this tool stops at
> "here is a mapped, cited hypothesis" — exploitation and verification
> remain manual, human-led steps **outside this codebase**.

This subtree is that separate tool. It is not an extension of the parent
pipeline's own restrictions — it is the thing those restrictions
deliberately point to. It consumes the parent's Stage 6 export
(`schema_version: "sqlmap_candidate_v1"`, see
`../pipeline/stage6_report/schemas/sqlmap_candidate_v1.schema.json`),
orchestrates real `sqlmap` runs against a target a human has explicitly
registered and authorized, and uses a local LLM purely to wrangle sqlmap's
own already-produced output into clean relational rows — never to decide
what to test, never to craft a payload, never to choose a technique.
**Penetration testing as data wrangling**, per the framing this tool was
built for: sqlmap is "the analytics engine"; this tool's job is targeting
it correctly and turning its raw output into a queryable record, nothing
more.

## Proof-of-concept phase: HTB CTF labs, not real client engagements yet

This first iteration is explicitly scoped to disposable, resettable HTB-style
CTF lab targets — proving the whole chain (Stage 6 export → import → real
sqlmap run → local-LLM interpretation → relational storage) actually works,
end to end, against a target we already know the ground truth for. This
justifies being more aggressive with scan defaults than a first pass at a
real client engagement would warrant (see "Default sqlmap flags" below) —
but every default below must be revisited with fresh reasoning, not
silently carried forward, before this tool is ever pointed at a real
engagement. Nothing here should be read as "these defaults are safe in
general" — they are calibrated for *this* phase, *this* class of target.

## Explicitly allowed

- Deterministic `sqlmap` argv construction from `sqlmap_wrapper/flags.py`'s
  fixed, versioned rule table (`FLAGS_VERSION`).
- Executing that argv as a real subprocess, gated behind `--execute` and
  `guard.require_authorized()`.
- Local-LLM interpretation of already-completed sqlmap output
  (`sqlmap_wrapper/interpret.py`) into `{result_type, summary_text}` —
  the one place in this tool that touches a model at all.

## Explicitly disallowed

- Firing `sqlmap` (or anything else) at any `host:port` that is not a row
  in `targets` with `authorized = 1`. `sqlmap_wrapper/guard.py`'s
  `require_authorized()` is the one non-negotiable enforcement point every
  `--execute` path must call first — mirror of the parent pipeline's
  hardcoded-localhost guard
  (`pipeline/llm/ollama_client.py`'s `_validate_local_host()`,
  `pipeline/stage4_5_dynamic_verify/guard.py`'s `validate_local_target()`),
  except here the guard is an explicit, auditable human opt-in rather than
  a fixed allowlist, since a real target is not localhost by definition.
- Calling any hosted/external LLM API. Local Ollama only, exactly the
  parent pipeline's rule — `sqlmap_wrapper/llm_runner.py`'s
  `WrapperLLMRunner` wraps `pipeline.llm.ollama_client.OllamaClient`
  specifically because that client already enforces this.
- Letting any LLM choose sqlmap flags, techniques, tamper scripts, or what
  to test next. That is 100% `flags.py`'s job — a small, fixed, versioned
  rule table, never a per-run model decision. If `flags.py` needs to
  change, that's a deliberate, versioned code change (bump
  `FLAGS_VERSION`), never an inference-time choice.
- Auto-constructing or silently passing through any denylisted flag
  (`flags.DENYLIST`): `--os-shell`, `--os-pwn`, `--os-cmd`, `--sql-shell`,
  `--file-write`/`--file-dest`, `--reg-read`/`--reg-add`/`--reg-del`. These
  are full RCE/file-write/registry primitives, a different category of
  action than confirming SQL injection. `check_extra_args()` refuses any
  `--execute` whose `extra_args` intersects this set — invoking real
  `sqlmap` directly, fully outside this wrapper, is the correct path for
  that class of action, and it must remain a deliberate, unwrapped decision
  a human makes, not something this tool smooths over.
- Defaulting `--risk=3`, raised `--threads`, or any `--tamper` script (see
  "Default sqlmap flags" below for why each specifically).

## Default sqlmap flags, and why (validated against a real `sqlmap 1.10.6` install)

| Flag | Default | Why |
|---|---|---|
| `--batch` | always on | Non-negotiable — a subprocess-driven caller can't answer sqlmap's interactive prompts; without it, a run blocks forever on the first ambiguous decision. |
| `--level=3` | on | Adds cookie/header-based injection points beyond level 1's GET/POST-only scope — HTB web boxes routinely hide vulnerabilities there. Level 5 is a large time cost for POC-phase marginal gain; skip as a default. |
| `--risk=2` | on | Adds time-based tests, not OR-based ones. |
| `--risk=3` | **never a default** | Adds OR-based payloads that can be dangerous against a WHERE-backed `UPDATE`/`DELETE` — this hazard is general (any future candidate this wrapper is pointed at), not specific to any one worked example. Only a human-supplied `--extra-args` override, never assumed safe because "the box is disposable" — that argument protects against data-integrity risk, not this. |
| `--random-agent` | on | Free, no destructive-action risk, avoids trivial User-Agent filtering. |
| `--threads` | **1, never raised by default** | HTB lab boxes are typically small, resource-constrained VMs. Concurrent requests risk crashing the target service — worse for CTF progress (a crashed box blocks further work until reset) than the data-integrity risk "it's disposable" actually protects against. Do not raise this just because the target is a lab box; that reasoning doesn't transfer. |
| `--tamper` | **never defaulted** | Choosing a tamper script is itself an evidence-based judgment call (which filter/WAF behavior are you working around) — defaulting one blind conflicts with "never guess what to look at next." Left as a manual `--extra-args` addition once a human has actually observed filtering behavior. |
| `-p <target_param_name>` | when non-null | Narrows the scan to the parameter Stage 4.5 already showed reactive — keeps runs fast and targeted rather than re-doing Stage 4.5's own narrowing work. |
| `--dbms=<dbms_hint>` | when non-null | Confirmed: a real `sqlmap` install accepts `"postgresql"`/`"mysql"`/`"mssql"` verbatim, no translation needed. |
| `--data=<...>` | built from `param_defaults` | See "Known limitation" below on how `param_defaults` gets here and what happens when it's missing. |

## A real, discovered limitation — sqlmap's black-box view vs. Stage 4.5's white-box view

**This was found by actually running the tool, not anticipated in design.**
A real end-to-end run against the real, known-vulnerable BlueBird
`signupPOST`/`name` candidate (the same one three separate writeups this
session confirmed is genuinely injectable, most recently via Stage 4.5's own
dynamic probe battery reproducing a real
`BadSqlGrammarException`/`PSQLException`) completed with `sqlmap`'s own
verdict: **"all tested parameters do not appear to be injectable."**
`interpret.py` correctly and honestly summarized this as `result_type:
"not_confirmed"` — the wrapper did not force a false "confirmed," which is
the right behavior.

**Why this happened, concretely:** `dynamic_probe_results.response_snippet`
for this exact probe is `{"timestamp":"...","status":500,"error":"Internal
Server Error","path":"/signup"}` — Spring Boot's generic error JSON. The
real `PSQLException`/`BadSqlGrammarException` text that confirmed this
vulnerability only ever appeared in the **application's own server-side
log** (`dynamic_probe_results.app_log_snippet`), which Stage 4.5 had
privileged access to (see `CLAUDE.md`'s Stage 4.5 section) — `sqlmap`, a
purely black-box HTTP client, never sees it. Worse for `sqlmap`
specifically: `signupPOST`'s sink is an unconditional `INSERT` with no
query result reflected back to the client, so none of sqlmap's default
techniques apply cleanly — boolean-based blind needs a true/false
*response* difference a bare INSERT doesn't produce, error-based needs the
DB error *text* reflected in the response body (suppressed here by Spring's
default error handler), and UNION/time-based blind assume a result set or
timing channel this sink doesn't expose either.

**What this means, and what it doesn't:** this is not a wrapper bug, and it
does not mean the finding is wrong — Stage 4.5's evidence (a real
server-log exception) remains valid and, if anything, is now demonstrated
to catch something a default `sqlmap` scan alone would miss. It means:
white-box dynamic verification (Stage 4.5, with access to the target's own
logs) and black-box scanning (`sqlmap`, HTTP-response-only) are
**complementary, not redundant** — this tool hands `sqlmap` a narrowed,
evidence-backed candidate list precisely because `sqlmap`'s own detection
can fail on sinks like this one. A `not_confirmed` result from this tool
should be read as "sqlmap's default technique set didn't independently
reproduce this" — never as "the underlying Stage 4.5 finding was wrong."
Do not silently smooth this over or treat `not_confirmed` as equivalent to
"safe." A human reviewing a `not_confirmed` result on a candidate Stage 4.5
already flagged `error` should consider `--tamper`, a higher `--level`, or a
different technique deliberately — not assume the wrapper failed.

## Known open gaps (documented, not silently assumed away)

- **`param_defaults` is human-supplied, never inferred**, exactly like the
  parent pipeline's `request-templates.json` precondition. A POST candidate
  with no matching template entry at Stage 6 export time has
  `param_defaults: null`; `flags.build_args()` raises
  `MissingRequestBodyError` rather than guessing a request body shape.
- **Second-order candidates get no automatic `--second-url`/`--second-req`
  flag.** Real sqlmap supports these, but they need the actual URL where a
  stored value is read back unsafely — data the parent pipeline's Stage 0
  doesn't track (no route information) and Stage 6's export doesn't
  currently carry. `order_hypothesis = "second_order"` candidates need a
  human to supply this manually via `--extra-args` for now.
- **No cross-database foreign key for `candidates.finding_id_source`.**
  It's the parent repo's `findings.finding_id`, in a genuinely separate
  SQLite file — see `DATA_DICTIONARY.md`.
- **`targets.authorized` has no expiry or re-verification.** A target
  authorized once stays authorized indefinitely; there's no "confirm this
  is still in scope" step before a later `--execute` run.

## Testing

Mirrors the parent pipeline's two-tier convention. Tier 1 (deterministic,
always runs): guard rejects unregistered/unauthorized targets,
`flags.check_extra_args()`'s denylist, `import_candidates.validate_export()`
against well-formed and malformed fixtures, schema `CHECK` enforcement,
`runner.run(execute=False)` never invokes `subprocess`. Tier 2, gated behind
`RUN_SQLMAP_TESTS=1` (the same pattern `RUN_LLM_TESTS=1`/`RUN_DYNAMIC_TESTS=1`
already establish in the parent repo): stands up a real disposable BlueBird
replica (reusing `pipeline.stage4_5_dynamic_verify.env_setup` strictly as a
test fixture, never a production dependency of this tool), imports a real
Stage 6 export, runs real `sqlmap`, and asserts the run completes and
produces a parseable `sqlmap_results` row — **not** that it necessarily
finds `result_type: "confirmed"`, per the discovered limitation above; a
real run against the real, known-vulnerable `name` parameter is expected to
honestly report `not_confirmed`, and the test suite asserts that specific,
real, observed behavior rather than an assumption made before ever running
real `sqlmap`.
