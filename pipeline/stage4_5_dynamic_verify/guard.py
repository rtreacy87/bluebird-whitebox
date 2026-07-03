"""Local-only enforcement for Stage 4.5 dynamic verification.

Per CLAUDE.md's "Dynamic Verification (Stage 4.5)" section: every HTTP
request or database connection this stage makes must be checked here first.
This pipeline never fires a probe, of any kind, at a hostname outside
{"localhost", "127.0.0.1", "::1"} -- exact mirror of
pipeline/llm/ollama_client.py's _validate_local_host(), applied to the one
other place this codebase reaches out over the network.
"""

from urllib.parse import urlparse

_ALLOWED_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


class RemoteTargetError(Exception):
    """Raised if anything tries to point Stage 4.5 at a non-local target.

    Stage 4.5's probe battery only exists to observe a disposable local
    replica the pipeline itself stood up. Treat any code path that would
    reach a non-local host as a bug, exactly as CLAUDE.md already treats a
    non-local Ollama call.
    """


def _extract_hostname(url_or_host: str):
    # Bare IPv6 loopback has no unambiguous way to add a "//" prefix and
    # still parse correctly (the colons collide with host:port syntax).
    if url_or_host == "::1":
        return "::1"
    # url_or_host may be a full URL ("http://localhost:8080") or a bare
    # hostname/host:port ("localhost", "127.0.0.1", "localhost:8080") --
    # urlparse only populates .hostname when a scheme/netloc is present, so
    # bare forms need a "//" prefix to be parsed as a netloc instead of a path.
    candidate = url_or_host if "://" in url_or_host else "//" + url_or_host
    return urlparse(candidate).hostname


def validate_local_target(url_or_host: str) -> None:
    hostname = _extract_hostname(url_or_host)
    if hostname not in _ALLOWED_HOSTNAMES:
        raise RemoteTargetError(
            f"refusing to fire a Stage 4.5 probe or open a DB connection against "
            f"non-local target {url_or_host!r}; only {sorted(_ALLOWED_HOSTNAMES)} are allowed"
        )
