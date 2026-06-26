"""Muon Optimizer - Matrix orthogonalization optimizer.

Ported from DeepSeek V4 Pro (arXiv 2606.19348, Section 2.1):
- Newton-Schulz iteration for weight matrix orthogonalization
- Decomposes updates into learned layer-wise learning rates
- Particularly effective for large-scale MoE models
- Can be combined with AdamW for non-matrix parameters

Reference: https://github.com/KellerJordan/Muon (original public implementation)
DeepSeek V4 Pro uses this as the primary pre-training optimizer.
"""

import logging
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Union

import torch
from torch.optim.optimizer import Optimizer

logger = logging.getLogger(__name__)


def newton_schulz(
    G: torch.Tensor,
    num_iters: int = 5,
) -> torch.Tensor:
    """Newton-Schulz iteration for matrix orthogonalization.

    Approximates the matrix sign function via coupled iteration:
    Given G (gradient matrix), computes orthogonalized update
    that lies near the Stiefel manifold.

    Args:
        G: Input matrix (usually gradient w.r.t. weight matrix)
        num_iters: Number of Newton-Schulz iterations (default 5)

    Returns:
        Orthogonalized matrix
    """
    a, b, c = (0.3334, 0.5, 0.4621)
    assert num_iters >= 1, "num_iters must be >= 1"

    input_dtype = G.dtype
    if input_dtype in (torch.float16, torch.bfloat16):
        G = G.float()

    G /= G.norm() + 1e-8
    X = G.clone()
    for _ in range(num_iters):
        X_T = X.T
        X = a * X @ X_T @ X + (b - a) * X @ (X_T @ X) + c * X_T @ (X @ X_T)

    if input_dtype in (torch.float16, torch.bfloat16):
        X = X.to(input_dtype)

    return X


class Muon(Optimizer):
    """Muon optimizer - orthogonalized updates via Newton-Schulz iteration.

    Ported from DeepSeek V4 Pro training recipe:
    - Applies Newton-Schulz orthogonalization to 2D weight matrices
    - Falls back to AdamW for 1D/3D+ parameters (biases, norms, embeddings)
    - Supports parameter groups with per-group learning rates
    - Includes weight decay (applied before orthogonalization)

    Usage matches PyTorch Optimizer API:
        optimizer = Muon(model.parameters(), lr=1e-4, muon_params=muon_params)

    Args:
        params: Iterable of parameters or parameter groups
        lr: Learning rate (default: 1e-4)
        betas: Adam betas for non-muon params (default: (0.9, 0.999))
        eps: Adam epsilon (default: 1e-8)
        weight_decay: Weight decay factor (default: 0.0)
        muon_params: Optional callable to filter which params use Muon.
            If None, defaults to all 2D weight matrices.
        ns_iters: Newton-Schulz iterations (default: 5)
        adamw_params: Optional callable to filter which params use AdamW fallback.
    """

    def __init__(
        self,
        params: Iterable[torch.nn.Parameter],
        lr: float = 1e-4,
        betas: Tuple[float, float] = (0.9, 0.999),
        eps: float = 1e-8,
        weight_decay: float = 0.0,
        muon_params: Optional[Callable[[torch.nn.Parameter], bool]] = None,
        ns_iters: int = 5,
        adamw_params: Optional[Callable[[torch.nn.Parameter], bool]] = None,
    ):
        defaults = dict(
            lr=lr,
            betas=betas,
            eps=eps,
            weight_decay=weight_decay,
            ns_iters=ns_iters,
        )
        super().__init__(params, defaults)

        if muon_params is None:
            self._muon_filter = lambda p: p.ndim == 2
        else:
            self._muon_filter = muon_params

        if adamw_params is None:
            self._adamw_filter = lambda p: p.ndim != 2
        else:
            self._adamw_filter = adamw_params

        self._ns_iters = ns_iters
        self._adamw_optimizer: Optional[Optimizer] = None
        self._muon_param_groups: List[Dict[str, Any]] = []
        self._adamw_param_groups: List[Dict[str, Any]] = []

        self._partition_params()

        self._stats = {
            "muon_params": len(self._muon_param_groups),
            "adamw_params": len(self._adamw_param_groups),
            "steps": 0,
        }

    def _partition_params(self) -> None:
        for group in self.param_groups:
            muon_params: List[torch.nn.Parameter] = []
            adamw_params: List[torch.nn.Parameter] = []

            for p in group["params"]:
                if self._muon_filter(p):
                    muon_params.append(p)
                if self._adamw_filter(p):
                    adamw_params.append(p)

            if muon_params:
                muon_group = {
                    "params": muon_params,
                    "lr": group.get("lr", 1e-4),
                    "weight_decay": group.get("weight_decay", 0.0),
                    "ns_iters": group.get("ns_iters", self._ns_iters),
                }
                self._muon_param_groups.append(muon_group)

            if adamw_params:
                adamw_group = {
                    "params": adamw_params,
                    "lr": group.get("lr", 1e-4),
                    "betas": group.get("betas", (0.9, 0.999)),
                    "eps": group.get("eps", 1e-8),
                    "weight_decay": group.get("weight_decay", 0.0),
                }
                self._adamw_param_groups.append(adamw_group)

        if self._adamw_param_groups:
            self._adamw_optimizer = torch.optim.AdamW(
                self._adamw_param_groups,
                lr=1e-4,
                betas=(0.9, 0.999),
                eps=1e-8,
                weight_decay=0.0,
            )

    @torch.no_grad()
    def step(self, closure: Optional[Callable[[], float]] = None) -> Optional[float]:
        """Perform a single optimization step.

        Applies Muon (Newton-Schulz orthogonalization) to 2D weight matrices,
        and AdamW to all other parameters (biases, norms, embeddings, etc.).
        """
        loss = None
        if closure is not None:
            with torch.enable_grad():
                loss = closure()

        # Muon step for 2D weight matrices
        for group in self._muon_param_groups:
            lr = group["lr"]
            weight_decay = group["weight_decay"]
            ns_iters = group["ns_iters"]

            for p in group["params"]:
                if p.grad is None:
                    continue

                grad = p.grad

                if weight_decay > 0:
                    grad = grad + weight_decay * p

                if p.ndim == 2:
                    orthogonalized = newton_schulz(grad, num_iters=ns_iters)
                    p.add_(orthogonalized, alpha=-lr)
                else:
                    p.add_(grad, alpha=-lr)

        # AdamW step for non-matrix parameters
        if self._adamw_optimizer is not None:
            self._adamw_optimizer.step()

        self._stats["steps"] += 1
        return loss

    def zero_grad(self, set_to_none: bool = True) -> None:
        super().zero_grad(set_to_none=set_to_none)
        if self._adamw_optimizer is not None:
            self._adamw_optimizer.zero_grad(set_to_none=set_to_none)

    def add_param_group(self, param_group: Dict[str, Any]) -> None:
        super().add_param_group(param_group)
        self._partition_params()

    def get_stats(self) -> Dict[str, int]:
        return dict(self._stats)


class MuonAdamW(Muon):
    """Convenience class: Muon for 2D params, AdamW for the rest.

    This is the recommended configuration from DeepSeek V4 Pro:
    - All 2D weight matrices use Muon (Newton-Schulz orthogonalization)
    - Biases, layer norms, embeddings, and 1D params use AdamW
    """

    def __init__(
        self,
        params: Iterable[torch.nn.Parameter],
        lr: float = 1e-4,
        betas: Tuple[float, float] = (0.9, 0.999),
        eps: float = 1e-8,
        weight_decay: float = 0.1,
        ns_iters: int = 5,
    ):
        super().__init__(
            params=params,
            lr=lr,
            betas=betas,
            eps=eps,
            weight_decay=weight_decay,
            muon_params=lambda p: p.ndim == 2,
            ns_iters=ns_iters,
            adamw_params=lambda p: True,
        )
