"""Deterministic sqlmap argv construction -- the wrapper's equivalent of
Stage 4.5's FIXED_PROBE_SET: a small, fixed, versioned rule table, never an
LLM decision (see CLAUDE.md's "Explicitly disallowed" section: flag
selection is 100% this module's job).

Defaults are calibrated for the CTF/POC phase (disposable HTB lab boxes),
not a real client engagement -- see CLAUDE.md for the full reasoning behind
each choice. Bump FLAGS_VERSION and document the change if this rule table
is ever revised.
"""

import json
import urllib.parse

FLAGS_VERSION = "flags_v1"

# Full RCE/file-write/registry primitives sqlmap can perform beyond SQLi
# confirmation. Never auto-added, and never allowed through --extra-args --
# that class of action requires invoking real `sqlmap` directly, fully
# outside this wrapper, by a human who has decided to do it deliberately.
DENYLIST = {
    "--os-shell", "--os-pwn", "--os-cmd", "--sql-shell",
    "--file-write", "--file-dest", "--reg-read", "--reg-add", "--reg-del",
}

# Never a default, only ever a human-supplied override -- see CLAUDE.md:
# --risk=3 adds OR-based tests that can be dangerous against a WHERE-backed
# UPDATE/DELETE, a hazard that's general (any future candidate) not tied to
# any one worked example.
_NEVER_DEFAULT = {"--risk=3"}


class DangerousFlagError(Exception):
    """Raised when extra_args contains a denylisted flag."""


class MissingRequestBodyError(Exception):
    """Raised when a POST candidate has no param_defaults -- the wrapper
    cannot guess a request body shape (see CLAUDE.md/DATA_DICTIONARY.md:
    param_defaults is human-supplied via request-templates.json, never
    inferred). A human must either supply --data manually via extra_args
    or re-export from bluebird-whitebox with a matching request template."""


def check_extra_args(extra_args):
    if not extra_args:
        return
    for arg in extra_args:
        flag = arg.split("=")[0]
        if flag in DENYLIST:
            raise DangerousFlagError(
                f"{flag!r} is denylisted -- this wrapper never constructs or passes through "
                f"RCE/file-write/registry primitives. Invoke real `sqlmap` directly, outside "
                f"this wrapper, if you've deliberately decided to do this."
            )
        if flag in _NEVER_DEFAULT:
            # Not denylisted -- risk=3 is a legitimate, if hazardous, human override -- but
            # surfaced here so callers can choose to warn/confirm before executing.
            pass


def _resolve_nonce(value, nonce):
    return value.replace("{nonce}", nonce) if isinstance(value, str) else value


def _build_data_string(param_defaults, nonce):
    resolved = {k: _resolve_nonce(v, nonce) for k, v in param_defaults.items()}
    return "&".join(f"{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}" for k, v in resolved.items())


def build_args(candidate_row, target_row, output_dir, nonce="wrapper1", extra_args=None):
    """candidate_row/target_row: sqlite3.Row objects from `candidates`/
    `targets`. Returns the full argv list (["sqlmap", ...]). Raises
    DangerousFlagError or MissingRequestBodyError rather than building a
    partial/unsafe command."""
    check_extra_args(extra_args)

    url = f"http://{target_row['host']}:{target_row['port']}{candidate_row['endpoint']}"
    param_defaults = (
        json.loads(candidate_row["param_defaults_json"]) if candidate_row["param_defaults_json"] else None
    )

    argv = ["sqlmap", "-u", url, "--batch", "--random-agent", "--level=3", "--risk=2"]

    if candidate_row["target_param_name"]:
        argv += ["-p", candidate_row["target_param_name"]]

    if candidate_row["dbms_hint"]:
        argv += [f"--dbms={candidate_row['dbms_hint']}"]

    http_method = candidate_row["http_method"]
    if http_method == "POST":
        if not param_defaults:
            raise MissingRequestBodyError(
                f"candidate {candidate_row['candidate_id']} ({candidate_row['endpoint']}) is a POST "
                f"endpoint with no param_defaults -- re-export from bluebird-whitebox with a matching "
                f"request-templates.json entry, or supply --data manually via extra_args"
            )
        argv += ["--data", _build_data_string(param_defaults, nonce)]
    elif http_method == "GET" and param_defaults:
        argv[2] = url + "?" + _build_data_string(param_defaults, nonce)

    argv += [f"--output-dir={output_dir}"]

    if extra_args:
        argv += list(extra_args)

    return argv
