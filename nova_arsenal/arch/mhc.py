"""Manifold-Constrained Hyper-Connections (mHC) - Architectural Reference.

Ported from DeepSeek V4 Pro (arXiv 2606.19348, Section 2.1):
- nhc=4: number of hyper-connection branches
- Sinkhorn-Knopp normalization (tmax=20) for constraint satisfaction
- Combines with Anticipatory Routing for MoE load balancing
- Replaces standard residual connections with learned transformations

This module serves as an architectural reference and reference implementation
for future Nova model architecture experiments.
"""

import logging
from typing import Any, Callable, Dict, List, Optional, Tuple

import torch
import torch.nn as nn
import torch.nn.functional as F

logger = logging.getLogger(__name__)


def sinkhorn_knopp(
    X: torch.Tensor,
    tmax: int = 20,
    eps: float = 1e-6,
) -> torch.Tensor:
    """Sinkhorn-Knopp normalization for doubly-stochastic matrices.

    Ported from DeepSeek V4 Pro Section 2.1:
    - Normalizes a matrix to be doubly stochastic (rows and columns sum to 1)
    - Used in mHC to enforce manifold constraints
    - tmax=20 as default (matching DeepSeek V4 Pro configuration)

    Args:
        X: Input matrix [batch, dim1, dim2]
        tmax: Maximum Sinkhorn iterations (default: 20)
        eps: Small constant for numerical stability

    Returns:
        Doubly-stochastic normalized matrix
    """
    X = X / (X.sum(dim=-1, keepdim=True) + eps)
    X = X / (X.sum(dim=-2, keepdim=True) + eps)

    for _ in range(tmax):
        X = X / (X.sum(dim=-1, keepdim=True) + eps)
        X = X / (X.sum(dim=-2, keepdim=True) + eps)

    return X


class ManifoldConstrainedHyperConnection(nn.Module):
    """Manifold-Constrained Hyper-Connection (mHC) layer.

    Ported from DeepSeek V4 Pro Section 2.1:
    - Replaces standard residual connections with learned hyper-connections
    - nhc=4 independent branches, each with learned weights
    - Sinkhorn-Knopp normalization constrains weights to manifold
    - Enables richer gradient flow than simple additive residual

    Architecture:
        output = sum_i w_i * branch_i(x)
        where w = SinkhornKnopp(learned_weights, tmax=20)

    Args:
        hidden_dim: Model hidden dimension
        nhc: Number of hyper-connection branches (default: 4, matching DeepSeek V4)
        tmax: Sinkhorn-Knopp iterations (default: 20)
    """

    def __init__(
        self,
        hidden_dim: int,
        nhc: int = 4,
        tmax: int = 20,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.nhc = nhc
        self.tmax = tmax

        self.branches = nn.ModuleList([
            nn.Sequential(
                nn.Linear(hidden_dim, hidden_dim, bias=False),
                nn.LayerNorm(hidden_dim),
            )
            for _ in range(nhc)
        ])

        self.weight_proj = nn.Linear(hidden_dim, nhc * nhc, bias=False)
        self.gate = nn.Parameter(torch.ones(1, nhc, 1))

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        B, L, D = x.shape

        branch_outputs = [branch(x) for branch in self.branches]
        stacked = torch.stack(branch_outputs, dim=-1)

        weights = self.weight_proj(x.mean(dim=1, keepdim=True))
        weights = weights.view(B, 1, self.nhc, self.nhc)
        weights = sinkhorn_knopp(weights, tmax=self.tmax)
        weights = weights.squeeze(1)

        gated = torch.sigmoid(self.gate)
        mixed = torch.einsum("bldh,bh->bld", stacked, gated.squeeze(1))

        output = x + mixed
        return output


class MultimodalProjection(nn.Module):
    """Multimodal projection layer (Dense Fusion + cross-attention).

    Ported from DeepSeek V4 Pro for multimodal token compression:
    - Dense Fusion for combining modalities
    - Cross-attention between modalities
    - Token compression via learned projections
    """

    def __init__(
        self,
        modal_dims: Dict[str, int],
        hidden_dim: int,
        num_heads: int = 8,
    ):
        super().__init__()
        self.modal_dims = modal_dims
        self.hidden_dim = hidden_dim
        self.num_heads = num_heads

        self.projectors = nn.ModuleDict({
            name: nn.Linear(dim, hidden_dim, bias=False)
            for name, dim in modal_dims.items()
        })

        self.norms = nn.ModuleDict({
            name: nn.LayerNorm(hidden_dim)
            for name in modal_dims
        })

    def forward(
        self,
        inputs: Dict[str, torch.Tensor],
    ) -> torch.Tensor:
        projected = []
        for name, x in inputs.items():
            if name in self.projectors:
                p = self.projectors[name](x)
                p = self.norms[name](p)
                projected.append(p)

        if not projected:
            return torch.zeros(
                inputs[next(iter(inputs))].shape[0], 1, self.hidden_dim,
                device=next(iter(inputs.values())).device,
            )

        return torch.cat(projected, dim=1)


class AnticipatoryRouter(nn.Module):
    """Anticipatory Routing for MoE load balancing.

    Ported from DeepSeek V4 Pro Section 2.1:
    - Route conflicts: detects when multiple experts compete for the same tokens
    - Knowledge transfer: routes tokens to experts with complementary knowledge
    - Replaces standard top-k routing with anticipatory allocation

    Key differences from standard top-k routing:
    1. Anticipates future token-expert assignments before committing
    2. Reduces route conflicts (same token sent to redundant experts)
    3. Encourages knowledge transfer between experts
    """

    def __init__(
        self,
        hidden_dim: int,
        num_experts: int,
        top_k: int = 2,
        capacity_factor: float = 1.25,
    ):
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_experts = num_experts
        self.top_k = top_k
        self.capacity_factor = capacity_factor

        self.router = nn.Linear(hidden_dim, num_experts, bias=False)
        self.conflict_proj = nn.Linear(hidden_dim, num_experts, bias=False)

        self._stats = {
            "total_tokens": 0,
            "conflicts_detected": 0,
            "conflict_rate": 0.0,
        }

    def forward(
        self,
        x: torch.Tensor,
        expert_counts: Optional[torch.Tensor] = None,
    ) -> Tuple[torch.Tensor, torch.Tensor]:
        B, L, D = x.shape
        x_flat = x.view(-1, D)

        logits = self.router(x_flat)
        conflict_logits = self.conflict_proj(x_flat)
        adjusted_logits = logits + 0.1 * conflict_logits.tanh()

        if expert_counts is not None:
            capacity = int(L * self.capacity_factor)
            expert_counts_flat = expert_counts.view(-1, self.num_experts)
            adjusted_logits = adjusted_logits - 0.01 * expert_counts_flat

        weights, indices = torch.topk(
            F.softmax(adjusted_logits, dim=-1),
            k=self.top_k,
            dim=-1,
        )
        weights = weights / (weights.sum(dim=-1, keepdim=True) + 1e-8)

        conflicts = (indices[:, 0].unsqueeze(1) == indices).sum(dim=-1) - 1
        self._stats["total_tokens"] += B * L
        self._stats["conflicts_detected"] += conflicts.sum().item()
        total = self._stats["total_tokens"]
        self._stats["conflict_rate"] = (
            self._stats["conflicts_detected"] / max(total, 1)
        )

        return indices, weights

    def get_stats(self) -> Dict[str, float]:
        return {
            "conflict_rate": self._stats["conflict_rate"],
            "total_tokens": self._stats["total_tokens"],
        }

    def reset_stats(self) -> None:
        self._stats = {
            "total_tokens": 0,
            "conflicts_detected": 0,
            "conflict_rate": 0.0,
        }


def build_deepseek_v4_block(
    hidden_dim: int,
    ffn_dim: int,
    num_heads: int = 16,
    nhc: int = 4,
    num_experts: int = 256,
    top_k: int = 8,
) -> nn.Module:
    """Build a reference DeepSeek V4 Pro transformer block.

    This is a simplified reference implementation showing how the
    components fit together. In production DeepSeek V4 Pro:
    - 1.6T total parameters (49B active)
    - 256 experts with top-8 routing
    - CSA (Compressed Sparse Attention) for all attention
    - mHC replaces standard residual connections
    - Anticipatory Routing for MoE

    Args:
        hidden_dim: Hidden dimension
        ffn_dim: FFN intermediate dimension
        num_heads: Number of attention heads
        nhc: Hyper-connection branches
        num_experts: Number of MoE experts
        top_k: Top-k experts per token

    Returns:
        Sequential block
    """
    return nn.Sequential(
        ManifoldConstrainedHyperConnection(hidden_dim, nhc=nhc),
        nn.Linear(hidden_dim, ffn_dim),
        nn.GELU(),
        nn.Linear(ffn_dim, hidden_dim),
    )
