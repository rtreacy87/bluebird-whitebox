"""Local-only Ollama client + llm_runs provenance recording.

Per CLAUDE.md: Ollama is the only inference runtime for this project, it must
stay bound to localhost, and num_ctx must always be set explicitly (Ollama's
default context window is far smaller than what these prompts need). Every
call is recorded to llm_runs with the real prompt_eval_count Ollama reports,
not an estimate -- that's the number that actually matters for verifying the
benchmarked context threshold holds at run time.
"""

from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

import ollama

DEFAULT_HOST = "http://localhost:11434"
_ALLOWED_HOSTNAMES = {"localhost", "127.0.0.1", "::1"}


class RemoteEndpointError(Exception):
    """Raised if anything tries to point this pipeline at a non-local Ollama host.

    CLAUDE.md is explicit: nothing in this pipeline may call an external/hosted
    API, and any code path reaching out to the network is a bug. This is the
    one enforcement point all LLM calls funnel through.
    """


class ModelNotAvailableError(Exception):
    pass


def _validate_local_host(host: str) -> None:
    hostname = urlparse(host).hostname
    if hostname not in _ALLOWED_HOSTNAMES:
        raise RemoteEndpointError(
            f"refusing to call non-local Ollama endpoint {host!r}; "
            "this pipeline only ever talks to a localhost Ollama instance"
        )


@dataclass
class LLMResult:
    text: str
    prompt_eval_count: Optional[int]
    eval_count: Optional[int]


class OllamaClient:
    def __init__(self, model_name: str, num_ctx: int, host: str = DEFAULT_HOST):
        _validate_local_host(host)
        self.host = host
        self.model_name = model_name
        self.num_ctx = num_ctx
        self._client = ollama.Client(host=host)

    def verify_model_available(self) -> None:
        """Confirm model_name is an exact tag Ollama currently knows about.

        CLAUDE.md warns not to assume a marketed/expected name -- a custom
        Modelfile import can leave a different local tag. Fail loudly instead
        of silently recording a mismatched llm_runs.model_name.
        """
        tags = {m.model for m in self._client.list().models}
        if self.model_name not in tags:
            raise ModelNotAvailableError(
                f"{self.model_name!r} is not in `ollama list` output on {self.host}. "
                f"Available tags: {sorted(tags)}"
            )

    def generate(self, prompt: str, system: Optional[str] = None, extra_options: Optional[dict] = None) -> LLMResult:
        options = {"num_ctx": self.num_ctx}
        if extra_options:
            options.update(extra_options)
        response = self._client.generate(
            model=self.model_name,
            prompt=prompt,
            system=system,
            options=options,
            stream=False,
        )
        return LLMResult(
            text=response.response,
            prompt_eval_count=response.prompt_eval_count,
            eval_count=response.eval_count,
        )


class LLMRunner:
    """Wraps OllamaClient calls with llm_runs provenance recording.

    Every triage/audit/trace call must go through this so results are always
    traceable back to an exact model tag + prompt_version + chunk position
    (CLAUDE.md: "Never write LLM output without this provenance.").
    """

    def __init__(self, conn, client: OllamaClient):
        self.conn = conn
        self.client = client

    def run(
        self,
        stage: str,
        prompt_version: str,
        prompt: str,
        system: Optional[str] = None,
        file_id: Optional[int] = None,
        chunk_index: int = 0,
        chunk_total: int = 1,
        extra_options: Optional[dict] = None,
    ):
        result = self.client.generate(prompt, system=system, extra_options=extra_options)

        cur = self.conn.execute(
            "INSERT INTO llm_runs (stage, model_name, prompt_version, file_id, "
            "input_token_count, num_ctx, chunk_index, chunk_total) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                stage,
                self.client.model_name,
                prompt_version,
                file_id,
                result.prompt_eval_count,
                self.client.num_ctx,
                chunk_index,
                chunk_total,
            ),
        )
        run_id = cur.lastrowid
        self.conn.commit()
        return run_id, result
