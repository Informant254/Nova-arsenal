"""Model architecture components for Nova.

Ported from DeepSeek V4 Pro architectural innovations:
- Manifold-Constrained Hyper-Connections (mHC, nhc=4, sinkhorn tmax=20)
- Anticipatory Routing for MoE load balancing
- Multimodal projection for dense fusion
- Reference transformer block builder
"""
from nova_arsenal.arch.mhc import (
    AnticipatoryRouter,
    ManifoldConstrainedHyperConnection,
    MultimodalProjection,
    build_deepseek_v4_block,
    sinkhorn_knopp,
)

__all__ = [
    "ManifoldConstrainedHyperConnection",
    "AnticipatoryRouter",
    "MultimodalProjection",
    "build_deepseek_v4_block",
    "sinkhorn_knopp",
]
