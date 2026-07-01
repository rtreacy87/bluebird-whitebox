"""Heuristic, offline token-count estimate for Stage 0 context-budget decisions.

This is NOT the real model tokenizer. It exists only so files.token_count can be
used deterministically at index time (Stage 0 has no LLM access) to decide which
files are candidates for forced multi-chunk review. The number that actually
gates chunking decisions against the model's effective context window is the
empirically measured value from bench/context_benchmark.py plus the real
prompt_eval_count Ollama returns per call (see pipeline/llm/ollama_client.py).
"""

import re

_TOKEN_RE = re.compile(
    r"[A-Za-z_][A-Za-z0-9_]*"      # identifiers/keywords
    r"|\"(?:\\.|[^\"\\])*\""       # string literals
    r"|'(?:\\.|[^'\\])*'"          # char literals
    r"|\d+\.?\d*"                  # numbers
    r"|[{}()\[\];,.<>=+\-*/%!&|^~?:@]"  # punctuation/operators, one token each
)


def estimate_token_count(source: str) -> int:
    return len(_TOKEN_RE.findall(source))
