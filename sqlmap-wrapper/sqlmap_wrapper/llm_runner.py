"""Wraps bluebird-whitebox's OllamaClient (the local-host-guarded call
primitive) with this tool's OWN provenance table (wrapper_llm_runs), rather
than reusing LLMRunner directly -- LLMRunner hardcodes writes against
bluebird-whitebox's llm_runs table, whose `stage` CHECK constraint doesn't
include 'sqlmap_interpret', and this tool has its own separate DB anyway.
Same "one call primitive, per-repo provenance table" split, just not
smuggling a foreign enum value into the parent schema.
"""

import sys
from pathlib import Path

# This is the one module in sqlmap_wrapper/ that crosses into the parent
# bluebird-whitebox repo (to reuse its local-host-guarded OllamaClient,
# never its LLMRunner -- see module docstring). Ensure the parent repo root
# is importable regardless of how this tool itself was invoked/what cwd is,
# since sqlmap-wrapper/ is a hyphenated directory name and can't be part of
# a dotted import path itself.
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from pipeline.llm.ollama_client import OllamaClient  # noqa: E402


class WrapperLLMRunner:
    def __init__(self, conn, client: OllamaClient):
        self.conn = conn
        self.client = client

    def run(self, stage, prompt_version, prompt, system=None, extra_options=None):
        result = self.client.generate(prompt, system=system, extra_options=extra_options)

        cur = self.conn.execute(
            "INSERT INTO wrapper_llm_runs (stage, model_name, prompt_version) VALUES (?, ?, ?)",
            (stage, self.client.model_name, prompt_version),
        )
        run_id = cur.lastrowid
        self.conn.commit()
        return run_id, result
