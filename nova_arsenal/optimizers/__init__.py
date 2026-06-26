"""Optimizers for Nova training pipeline.

Ported from DeepSeek V4 Pro training innovations:
- Muon: Newton-Schulz orthogonalization optimizer for 2D weight matrices
- MuonAdamW: Recommended hybrid (Muon for weights, AdamW for biases/norms)
"""
from nova_arsenal.optimizers.muon import Muon, MuonAdamW, newton_schulz

__all__ = [
    "Muon",
    "MuonAdamW",
    "newton_schulz",
]
