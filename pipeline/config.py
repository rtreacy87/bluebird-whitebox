"""Pipeline-wide constants that must trace back to an empirical source, not a guess.

CLAUDE.md: "Never assume the marketed context window is the effective one."
These values come from bench/context_benchmark.py's run against the BlueBird
corpus (see bench/context_benchmark_results.json) and must be re-benchmarked
-- not hand-edited -- if the model, corpus size range, or Ollama version changes.
"""

# Threshold on pipeline.stage0_index.tokenizer's heuristic token estimate
# (Stage 0 has no LLM access, so chunking decisions must be made off this
# offline estimate). Files at or under this are safe for single-shot triage;
# above it, force method-boundary multi-chunk review.
SAFE_CONTEXT_TOKENS_HEURISTIC = 4096

# num_ctx to request from Ollama for triage/audit calls. Sized well above what
# SAFE_CONTEXT_TOKENS_HEURISTIC's worth of source actually costs in real BPE
# tokens (observed ~7000 real tokens at the 4096 heuristic-token benchmark
# point) plus room for the prompt scaffolding and generated output.
DEFAULT_NUM_CTX = 12288
