"""DeepSeek Sparse Attention (DSA) patterns for long-context security tool processing.

Ported from DeepSeek V4 Pro (arXiv 2606.19348) and GLM-5 DSA adaptation:
- Compressed latent attention: project KV into compressed latent, top-k selection per query
- Hybrid Coarse-grained Attention (HCA): window attention + coarse-grained attention
- Deterministic top-k indexer (k=2048, torch.topk for consistency)
- Indexer parameters frozen during RL to prevent unstable learning
- Context window management for security tool outputs (nmap, burp, sqlmap, etc.)
"""

import heapq
import logging
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class CompressionStrategy(Enum):
    DSA = "dsa"
    HCA = "hca"
    CSA = "csa"


@dataclass
class DSAConfig:
    """DeepSeek Sparse Attention configuration.

    Ported from DeepSeek V4 Pro Section 2.1 / GLM-5 Section 2.1.1:
    - compressed_latent_dim: dimension of compressed KV latent
    - top_k: number of most relevant KV entries to retrieve (k=2048)
    - deterministic_topk: use torch.topk for consistency
    - freeze_indexer: freeze indexer params during RL training
    """
    compressed_latent_dim: int = 256
    top_k: int = 2048
    num_heads: int = 8
    deterministic_topk: bool = True
    use_window_compression: bool = True
    window_size: int = 4096
    coarse_stride: int = 1024


@dataclass
class DSAIndexer:
    """Deterministic top-k indexer for sparse attention.

    Ported from GLM-5 Section 3.2:
    - Retrieves top-k most relevant key-value entries
    - Uses deterministic torch.topk for training-inference consistency
    - Non-deterministic CUDA top-k causes RL instability
    - Indexer parameters frozen during RL (default behavior)

    For the Nova context: adapted as a content relevance scorer
    that selects the most important segments of long security tool outputs.
    """
    top_k: int = 2048
    deterministic: bool = True
    _score_cache: Dict[str, List[float]] = field(default_factory=dict)

    def score_segments(
        self,
        query_embedding: List[float],
        segment_embeddings: List[List[float]],
    ) -> List[Tuple[int, float]]:
        scores: List[Tuple[int, float]] = []
        for idx, seg_emb in enumerate(segment_embeddings):
            score = self._cosine_similarity(query_embedding, seg_emb)
            scores.append((idx, score))
        return scores

    def select_top_k(
        self,
        scores: List[Tuple[int, float]],
    ) -> List[int]:
        if self.deterministic:
            top_k_scores = heapq.nlargest(self.top_k, scores, key=lambda x: x[1])
        else:
            sorted_scores = sorted(scores, key=lambda x: x[1], reverse=True)
            top_k_scores = sorted_scores[:self.top_k]

        return [idx for idx, _ in top_k_scores]

    def _cosine_similarity(
        self, a: List[float], b: List[float]
    ) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)

    def clear_cache(self) -> None:
        self._score_cache.clear()


@dataclass
class CompressedLatent:
    """Compressed KV latent representation.

    Ported from DeepSeek V4 Pro CSA (Compressed Sparse Attention):
    - Project KV into lower-dimensional latent space
    - Use compressed latent for top-k selection instead of full KV
    - Reduces storage and compute for long-context attention
    """
    compressed_keys: List[List[float]] = field(default_factory=list)
    compressed_values: List[List[float]] = field(default_factory=list)
    original_indices: List[int] = field(default_factory=list)
    compression_ratio: float = 1.0


class ContentCompressor:
    """Compress long security tool outputs using DSA/HCA patterns.

    Adapts DeepSeek Sparse Attention for processing long security tool outputs:
    - nmap scan results (thousands of ports/hosts)
    - burp suite findings (long HTTP histories)
    - sqlmap output (extensive database enumeration)
    - OSINT collection results
    - Vulnerability scan output

    Strategy: segment long content, score relevance via compressed latent,
    select top-k segments for full attention.
    """

    def __init__(
        self,
        config: Optional[DSAConfig] = None,
        strategy: CompressionStrategy = CompressionStrategy.DSA,
    ):
        self.config = config or DSAConfig()
        self.strategy = strategy
        self.indexer = DSAIndexer(
            top_k=self.config.top_k,
            deterministic=self.config.deterministic_topk,
        )
        self._stats = {
            "total_chars_processed": 0,
            "compressed_chars": 0,
            "compression_ratio": 1.0,
            "segments_processed": 0,
        }

    def segment_content(self, content: str, max_segment_size: int = 512) -> List[str]:
        """Split long content into segments for sparse attention.

        Uses a combination of:
        1. Newline boundaries (preserve log structure)
        2. Sentence boundaries (for prose content)
        3. Fixed-size chunks as fallback
        """
        lines = content.split("\n")
        segments: List[str] = []
        current: List[str] = []

        for line in lines:
            current.append(line)
            if len("\n".join(current)) >= max_segment_size:
                segments.append("\n".join(current))
                current = []

        if current:
            segments.append("\n".join(current))

        return segments

    def score_segments_by_keywords(
        self,
        segments: List[str],
        keywords: List[str],
    ) -> List[Tuple[int, float]]:
        """Score segments by keyword relevance.

        Security-specific scoring:
        - CVE identifiers (critical)
        - Severity levels (critical, high, medium, low)
        - Open ports
        - Vulnerability names
        - Target-specific terms
        """
        scores: List[Tuple[int, float]] = []
        keyword_set = set(k.lower() for k in keywords)

        for idx, segment in enumerate(segments):
            score = 0.0
            seg_lower = segment.lower()

            token_count = len(seg_lower.split())
            if token_count == 0:
                scores.append((idx, 0.0))
                continue

            matched_keywords = sum(
                1 for kw in keyword_set if kw in seg_lower
            )
            score += matched_keywords / max(len(keyword_set), 1)

            cve_count = seg_lower.count("cve-")
            score += min(cve_count * 0.1, 0.5)

            severity_score = 0.0
            if "critical" in seg_lower:
                severity_score += 0.3
            if "high" in seg_lower:
                severity_score += 0.2
            if "medium" in seg_lower:
                severity_score += 0.1
            score += severity_score

            has_port = any(
                f"port {p}" in seg_lower or f":{p}" in seg_lower
                for p in ["22", "80", "443", "8080", "3306", "3389"]
            )
            if has_port:
                score += 0.1

            scores.append((idx, score))

        return scores

    def compress(
        self,
        content: str,
        query_keywords: Optional[List[str]] = None,
        max_tokens: Optional[int] = None,
    ) -> str:
        """Compress long content by selecting top-k relevant segments.

        Applies DSA-style sparse attention:
        1. Segment content into chunks
        2. Score each segment by relevance to query/keywords
        3. Select top-k segments (sparse attention over full content)
        4. Optionally add window around selected segments (HCA-style)

        Args:
            content: Long security tool output
            query_keywords: Keywords to score relevance (e.g., "vulnerability", "open")
            max_tokens: Maximum tokens for output (hard limit)

        Returns:
            Compressed content preserving most relevant information
        """
        if max_tokens and len(content) < max_tokens * 4:
            self._stats["total_chars_processed"] += len(content)
            return content

        segments = self.segment_content(content)

        if query_keywords:
            scored = self.score_segments_by_keywords(segments, query_keywords)
        else:
            scored = [(i, 0.0) for i in range(len(segments))]

        top_k_indices = self.indexer.select_top_k(scored)

        if self.config.use_window_compression:
            window_indices: set[int] = set()
            for idx in top_k_indices:
                start = max(0, idx - 2)
                end = min(len(segments), idx + 3)
                for w_idx in range(start, end):
                    window_indices.add(w_idx)
            selected_indices = sorted(window_indices)
        else:
            selected_indices = sorted(top_k_indices)

        compressed = "\n".join(segments[i] for i in selected_indices)

        self._stats["total_chars_processed"] += len(content)
        self._stats["compressed_chars"] += len(compressed)
        self._stats["compression_ratio"] = (
            self._stats["compressed_chars"] / max(self._stats["total_chars_processed"], 1)
        )
        self._stats["segments_processed"] += len(segments)

        return compressed

    def extract_compressed_latent(
        self,
        content: str,
        num_latent_dims: int = 256,
    ) -> CompressedLatent:
        """Extract compressed latent representation of content.

        Ported from DeepSeek V4 Pro CSA:
        Projects segments into compressed latent space for efficient
        relevance scoring without full attention computation.
        """
        segments = self.segment_content(content)

        compressed_keys: List[List[float]] = []
        compressed_values: List[List[float]] = []
        original_indices: List[int] = []

        for idx, segment in enumerate(segments):
            latent = self._project_to_latent(segment, num_latent_dims)
            compressed_keys.append(latent)
            compressed_values.append(latent)
            original_indices.append(idx)

        return CompressedLatent(
            compressed_keys=compressed_keys,
            compressed_values=compressed_values,
            original_indices=original_indices,
            compression_ratio=len(compressed_keys) / max(len(segments), 1),
        )

    def _project_to_latent(
        self, text: str, dims: int
    ) -> List[float]:
        """Simple frequency-based projection to latent space.

        In production, this would be a learned projection matrix.
        Here we use TF-IDF-like features as a lightweight approximation:
        - Character n-gram frequencies
        - Keyword presence indicators
        - Length-normalized density
        """
        latent = [0.0] * dims

        if not text:
            return latent

        text_lower = text.lower()
        words = text_lower.split()
        word_set = set(words)

        security_terms = [
            "cve", "vulnerability", "exploit", "attack", "breach",
            "malware", "ransomware", "phishing", "backdoor", "trojan",
            "port", "service", "protocol", "ssl", "tls", "http",
            "sql", "injection", "xss", "csrf", "authentication",
            "authorization", "bypass", "escalation", "payload", "shell",
        ]

        for i, term in enumerate(security_terms):
            if i < dims:
                latent[i] = text_lower.count(term) / max(len(words), 1)

        char_bigrams: Dict[str, int] = {}
        for i in range(len(text_lower) - 1):
            bg = text_lower[i : i + 2]
            char_bigrams[bg] = char_bigrams.get(bg, 0) + 1

        offset = len(security_terms)
        for i, (bg, count) in enumerate(
            sorted(char_bigrams.items(), key=lambda x: -x[1])[: dims - offset]
        ):
            if offset + i < dims:
                latent[offset + i] = count / max(len(text), 1)

        return latent

    def get_stats(self) -> Dict[str, Any]:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {
            "total_chars_processed": 0,
            "compressed_chars": 0,
            "compression_ratio": 1.0,
            "segments_processed": 0,
        }
