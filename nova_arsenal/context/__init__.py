"""Context processing utilities for long-context security tool outputs.

DeepSeek Sparse Attention (DSA) patterns adapted for Nova:
- Compressed latent attention for relevance scoring
- Top-k segment selection (sparse attention over full content)
- Window + coarse-grained attention (HCA-style)
- Deterministic indexer for consistent training-inference
"""
from nova_arsenal.context.compression import (
    CompressionStrategy,
    CompressedLatent,
    ContentCompressor,
    DSAConfig,
    DSAIndexer,
)

__all__ = [
    "ContentCompressor",
    "DSAConfig",
    "DSAIndexer",
    "CompressedLatent",
    "CompressionStrategy",
]
