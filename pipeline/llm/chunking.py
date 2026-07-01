"""Method-boundary chunking for Stage 1/2 prompts.

CLAUDE.md: "Chunk by parser-verified method boundary only -- never split a
file by raw token count. If a file must be chunked, include the last method
of the previous chunk again at the start of the next chunk (overlap)."
Boundaries come from Stage 0's symbols table (ground truth), never re-derived
by counting characters.
"""

from dataclasses import dataclass
from typing import List

from pipeline.config import SAFE_CONTEXT_TOKENS_HEURISTIC
from pipeline.stage0_index.tokenizer import estimate_token_count


@dataclass
class Chunk:
    chunk_index: int
    chunk_total: int
    method_symbol_ids: List[int]  # DB symbol_ids of methods/constructors covered by this chunk
    method_names: List[str]
    text: str


def _slice_lines(lines, line_start, line_end):
    if line_start is None or line_end is None:
        return ""
    return "\n".join(lines[line_start - 1 : line_end])


def build_chunks(source_text, class_symbol, field_symbols, method_symbols, safe_threshold=SAFE_CONTEXT_TOKENS_HEURISTIC):
    """
    class_symbol, field_symbols, method_symbols: sqlite3.Row-like dicts from the
    symbols table (must include symbol_id, name, line_start, line_end), for one file.
    method_symbols must be sorted by line_start ascending and include constructors.
    """
    lines = source_text.split("\n")
    header_end = (class_symbol["line_start"] or 1) - 1
    header = "\n".join(lines[:header_end])
    fields_text = "\n\n".join(_slice_lines(lines, f["line_start"], f["line_end"]) for f in field_symbols)
    base_text = header + ("\n\n" + fields_text if fields_text else "")
    base_tokens = estimate_token_count(base_text)

    if not method_symbols:
        return [Chunk(0, 1, [], [], source_text)]

    method_texts = {m["symbol_id"]: _slice_lines(lines, m["line_start"], m["line_end"]) for m in method_symbols}
    method_tokens = {sid: estimate_token_count(t) for sid, t in method_texts.items()}

    whole_file_tokens = estimate_token_count(source_text)
    if whole_file_tokens <= safe_threshold:
        return [Chunk(0, 1, [m["symbol_id"] for m in method_symbols], [m["name"] for m in method_symbols], source_text)]

    groups: List[List[dict]] = []
    current: List[dict] = []
    current_tokens = base_tokens
    for m in method_symbols:
        t = method_tokens[m["symbol_id"]]
        if current and current_tokens + t > safe_threshold:
            groups.append(current)
            overlap_method = current[-1]
            current = [overlap_method]
            current_tokens = base_tokens + method_tokens[overlap_method["symbol_id"]]
        current.append(m)
        current_tokens += t
    if current:
        groups.append(current)

    total = len(groups)
    chunks = []
    for idx, group in enumerate(groups):
        body = "\n\n".join(method_texts[m["symbol_id"]] for m in group)
        text = base_text + ("\n\n" if base_text else "") + body
        chunks.append(
            Chunk(
                chunk_index=idx,
                chunk_total=total,
                method_symbol_ids=[m["symbol_id"] for m in group],
                method_names=[m["name"] for m in group],
                text=text,
            )
        )
    return chunks
