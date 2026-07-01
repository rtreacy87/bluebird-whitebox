"""Empirically measure the effective context window of the configured Ollama
model, per CLAUDE.md: "Never assume the marketed context window is the
effective one." This is a needle-in-haystack test -- a unique marker/secret
pair is buried inside real BlueBird source at a controlled depth, and the
model is asked to recall it. The largest size at which recall is still
reliable, minus a safety margin, is the threshold the pipeline's chunker
should treat as "safe" before forcing multi-chunk review.

This is NOT a substitute for good chunking hygiene -- it exists to catch the
case where Ollama's num_ctx default (or a value copied from marketed specs)
would silently truncate a file's context out from under the triage pass.

Usage:
    python -m bench.context_benchmark --model whiterabbitneo-33b:latest
    python -m bench.context_benchmark --sizes 512,2048,4096,8192 --trials 3
"""

import argparse
import glob
import json
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.llm.ollama_client import OllamaClient
from pipeline.stage0_index.tokenizer import estimate_token_count

CORPUS_ROOT = Path("~/BlueBirdSourceCode/BOOT-INF/classes/com/bmdyy/bluebird").expanduser()
# pipeline.stage0_index.tokenizer's heuristic estimate systematically under-counts
# real BPE tokens for Java source (observed ~1.8x on this corpus) -- num_ctx is
# sized off the heuristic target, so it needs a generous multiplicative margin,
# not just a fixed additive one, or Ollama silently truncates the constructed
# haystack and every trial "fails" for the wrong reason. Each trial still
# double-checks via actual_prompt_tokens and flags truncation explicitly.
HEURISTIC_TO_REAL_TOKEN_SAFETY_MULTIPLIER = 3.0
CONTEXT_HEADROOM_TOKENS = 256  # extra room for the question + generated answer
NUM_PREDICT = 24  # the answer is always a short digit string; keep generation fast/bounded


def _load_filler_text(min_tokens):
    files = sorted(glob.glob(str(CORPUS_ROOT / "**" / "*.java"), recursive=True))
    if not files:
        raise SystemExit(f"no source found under {CORPUS_ROOT} to build filler text from")
    corpus = "\n\n".join(Path(f).read_text() for f in files)
    # Tile the real corpus (not a repeated short snippet, to keep token
    # density representative) until it's long enough to slice from for the
    # largest requested target size.
    text = corpus
    while estimate_token_count(text) < min_tokens:
        text += "\n\n" + corpus
    return text


def _take_tokens(text, n_tokens):
    """Return a prefix of text with approximately n_tokens tokens."""
    if n_tokens <= 0:
        return ""
    density = len(text) / max(1, estimate_token_count(text))
    chars = min(len(text), int(n_tokens * density))
    chunk = text[:chars]
    while estimate_token_count(chunk) < n_tokens and chars < len(text):
        chars = min(len(text), chars + 200)
        chunk = text[:chars]
    return chunk


def _build_haystack(filler, target_tokens, secret):
    needle = f"\n// BENCHMARK-MARKER-{secret}: the verification code is {secret}\n"
    needle_tokens = estimate_token_count(needle)
    remaining = max(0, target_tokens - needle_tokens)
    before = _take_tokens(filler, remaining // 2)
    after = _take_tokens(filler[len(before):], remaining - remaining // 2)
    return before + needle + after


def run_trial(client, target_tokens, num_ctx, trial_index):
    secret = f"{random.randint(100000, 999999)}"
    filler = run_trial._filler
    haystack = _build_haystack(filler, target_tokens, secret)

    prompt = (
        f"{haystack}\n\n"
        "Somewhere above is a line starting with 'BENCHMARK-MARKER-'. "
        "Reply with ONLY the numeric verification code from that line, nothing else."
    )

    t0 = time.time()
    result = client.generate(
        prompt,
        system="You answer with only the requested value, no explanation.",
        extra_options={"num_predict": NUM_PREDICT, "temperature": 0},
    )
    elapsed = time.time() - t0

    # If Ollama had to truncate the prompt to fit num_ctx, prompt_eval_count
    # comes back == num_ctx and the needle may have been cut out entirely --
    # that's a test-setup failure, not evidence about the model's recall.
    truncated = result.prompt_eval_count is not None and result.prompt_eval_count >= num_ctx

    recalled = secret in result.text
    return {
        "target_tokens": target_tokens,
        "num_ctx": num_ctx,
        "trial": trial_index,
        "actual_prompt_tokens": result.prompt_eval_count,
        "truncated": truncated,
        "secret": secret,
        "response": result.text.strip(),
        "recalled": recalled and not truncated,
        "elapsed_s": round(elapsed, 1),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default="whiterabbitneo-33b:latest")
    parser.add_argument("--host", default="http://localhost:11434")
    parser.add_argument(
        "--sizes",
        default="1024,4096,8192",
        help="comma-separated target prompt sizes in (heuristic) tokens",
    )
    parser.add_argument("--trials", type=int, default=1, help="trials per size (default 1 -- raise for a production judgment call)")
    parser.add_argument("--out", default=str(Path(__file__).parent / "context_benchmark_results.json"))
    args = parser.parse_args()

    sizes = [int(s) for s in args.sizes.split(",")]
    filler = _load_filler_text(max(sizes))
    run_trial._filler = filler

    results = []
    for target_tokens in sizes:
        num_ctx = int(target_tokens * HEURISTIC_TO_REAL_TOKEN_SAFETY_MULTIPLIER) + CONTEXT_HEADROOM_TOKENS
        client = OllamaClient(model_name=args.model, num_ctx=num_ctx, host=args.host)
        if target_tokens == sizes[0]:
            client.verify_model_available()

        for trial in range(args.trials):
            r = run_trial(client, target_tokens, num_ctx, trial)
            results.append(r)
            flag = " TRUNCATED (test setup, not a model failure)" if r["truncated"] else ""
            print(
                f"size={target_tokens:>6} num_ctx={num_ctx:>6} trial={trial} "
                f"actual_prompt_tokens={r['actual_prompt_tokens']:>6} "
                f"recalled={r['recalled']} elapsed={r['elapsed_s']}s{flag}"
            )

    by_size = {}
    for r in results:
        by_size.setdefault(r["target_tokens"], []).append(r["recalled"])

    reliable_sizes = [size for size, recalls in sorted(by_size.items()) if all(recalls)]
    safe_threshold = max(reliable_sizes) if reliable_sizes else None

    report = {
        "model": args.model,
        "sizes_tested": sizes,
        "trials_per_size": args.trials,
        "results": results,
        "reliable_sizes": reliable_sizes,
        "recommended_safe_context_tokens": safe_threshold,
        "note": (
            "recommended_safe_context_tokens is the largest tested size where "
            "every trial recalled the needle. Files whose token_count (Stage 0 "
            "heuristic estimate) exceeds this must be routed to forced "
            "multi-chunk review. Re-run with more --trials before trusting this "
            "for anything beyond an initial threshold."
        ),
    }

    Path(args.out).write_text(json.dumps(report, indent=2))
    print(f"\nrecommended_safe_context_tokens = {safe_threshold}")
    print(f"report written to {args.out}")


if __name__ == "__main__":
    main()
