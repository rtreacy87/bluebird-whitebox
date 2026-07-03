"""Target-authorization enforcement for sqlmap-wrapper.

Every code path that would invoke `sqlmap` (a real, exploitation-capable
subprocess) must call `require_authorized()` here first. This is this
tool's equivalent of bluebird-whitebox's hardcoded-localhost guard
(pipeline/llm/ollama_client.py's _validate_local_host(),
pipeline/stage4_5_dynamic_verify/guard.py's validate_local_target()) --
except a real engagement/CTF target is not localhost by definition, so the
guard here can't be a fixed allowlist. Instead: a host:port is only ever
fireable at if a human has explicitly registered it in `targets` AND set
`authorized=1` -- an explicit, auditable opt-in rather than an implicit
default, kept even in this tool's more permissive (CTF/POC) risk profile.
See CLAUDE.md's "Explicitly disallowed" section.
"""


class UnauthorizedTargetError(Exception):
    """Raised if anything tries to fire sqlmap at a host:port that isn't a
    registered, authorized `targets` row. Treat any code path that would
    bypass this as a bug -- this tool's one non-negotiable safety rail."""


def require_authorized(conn, host, port):
    """Returns the target row if host:port is registered with
    authorized=1; raises UnauthorizedTargetError otherwise."""
    row = conn.execute(
        "SELECT * FROM targets WHERE host = ? AND port = ?", (host, port)
    ).fetchone()

    if row is None:
        raise UnauthorizedTargetError(
            f"{host}:{port} is not a registered target -- run `register-target` first"
        )
    if not row["authorized"]:
        raise UnauthorizedTargetError(
            f"{host}:{port} is registered but not authorized (targets.authorized=0) -- "
            f"re-register with --authorize to confirm this target is in scope"
        )
    return row
