"""
Deduplication engine - ported from empero-org/taskgen.

Two-pass approach:
1. Exact match — normalized (lowercase, whitespace-collapsed) string comparison
2. Semantic match — word-trigram Jaccard similarity, removes entries above threshold
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


def word_trigrams(text: str) -> Set[str]:
    words = text.split()
    if len(words) < 3:
        return {w.lower() for w in words}
    return {" ".join(words[i:i+3]).lower() for i in range(len(words) - 2)}


def jaccard_similarity(a: Set[str], b: Set[str]) -> float:
    if not a and not b:
        return 1.0
    intersection = a & b
    union = a | b
    if not union:
        return 0.0
    return len(intersection) / len(union)


def normalize_prompt(text: str) -> str:
    return "".join(text.lower().split())


def exact_dedup(
    entries: List[Dict],
    prompt_key: str = "prompt",
) -> Tuple[List[Dict], int]:
    seen: Set[str] = set()
    kept = []
    dupe_count = 0
    for entry in entries:
        normalized = normalize_prompt(entry.get(prompt_key, ""))
        if normalized in seen:
            dupe_count += 1
        else:
            seen.add(normalized)
            kept.append(entry)
    return kept, dupe_count


def semantic_dedup(
    entries: List[Dict],
    threshold: float = 0.6,
    prompt_key: str = "prompt",
) -> Tuple[List[Dict], int]:
    if len(entries) < 2:
        return entries, 0

    trigrams: List[Set[str]] = []
    for entry in entries:
        text = entry.get(prompt_key, "").lower()
        trigrams.append(word_trigrams(text))

    keep = [True] * len(entries)
    dupe_count = 0

    for j in range(1, len(entries)):
        if not keep[j]:
            continue
        trig_b = trigrams[j]
        for k in range(j):
            if not keep[k]:
                continue
            trig_a = trigrams[k]
            if jaccard_similarity(trig_a, trig_b) >= threshold:
                keep[j] = False
                dupe_count += 1
                break

    return [e for i, e in enumerate(entries) if keep[i]], dupe_count


def run_dedup_pipeline(
    entries: List[Dict],
    threshold: float = 0.6,
    prompt_key: str = "prompt",
) -> Tuple[List[Dict], int, int]:
    deduped, exact = exact_dedup(entries, prompt_key)
    if exact:
        logger.info(f"Exact dedup: removed {exact} duplicates")

    deduped, semantic = semantic_dedup(deduped, threshold, prompt_key)
    if semantic:
        logger.info(f"Semantic dedup: removed {semantic} duplicates (threshold={threshold})")

    total = exact + semantic
    logger.info(f"Dedup total: {len(entries)} → {len(deduped)} ({total} removed)")
    return deduped, exact, semantic


def dedup_file(
    input_path: Path,
    output_path: Optional[Path] = None,
    threshold: float = 0.6,
) -> Path:
    entries = []
    with open(input_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    logger.warning(f"Skipping invalid JSON line: {line[:80]}")

    if not entries:
        logger.warning("No valid entries found for dedup")
        return input_path

    logger.info(f"Loaded {len(entries)} entries from {input_path}")
    deduped, _, _ = run_dedup_pipeline(entries, threshold)

    out = output_path or input_path
    with open(out, "w", encoding="utf-8") as f:
        for entry in deduped:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    logger.info(f"Wrote {len(deduped)} deduplicated entries to {out}")
    return out
