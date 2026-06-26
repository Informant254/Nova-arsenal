"""
Tests for Nova-Arsenal Muon Optimizer and mHC Architecture.
These tests require PyTorch. Skip if not installed.
"""

import pytest

try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False

# ── Muon Optimizer Tests ──────────────────────────────────────────────────────

@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestMuonOptimizer:
    def test_newton_schulz_exists(self):
        from nova_arsenal.optimizers.muon import newton_schulz
        assert callable(newton_schulz)

    def test_muon_exists(self):
        from nova_arsenal.optimizers.muon import Muon
        assert Muon is not None

    def test_muon_adamw_exists(self):
        from nova_arsenal.optimizers.muon import MuonAdamW
        assert MuonAdamW is not None


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestNewtonSchulz:
    def test_identity_matrix(self):
        from nova_arsenal.optimizers.muon import newton_schulz

        eye = torch.eye(4)
        result = newton_schulz(eye, num_iters=5)
        assert result.shape == (4, 4)
        # Should be close to identity for identity input
        assert torch.allclose(result, eye, atol=1e-5)

    def test_random_matrix(self):
        from nova_arsenal.optimizers.muon import newton_schulz

        mat = torch.randn(8, 8)
        result = newton_schulz(mat, num_iters=5)
        assert result.shape == (8, 8)
        # Result should be orthogonal (approx)
        ortho = result @ result.T
        assert torch.allclose(ortho, torch.eye(8), atol=1e-3)

    def test_2d_only(self):
        from nova_arsenal.optimizers.muon import newton_schulz

        # 3D tensor should raise
        with pytest.raises(ValueError):
            newton_schulz(torch.randn(2, 2, 2))


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestMuonAdamW:
    def test_creation(self):
        from nova_arsenal.optimizers.muon import MuonAdamW

        model = torch.nn.Linear(10, 5)
        opt = MuonAdamW(model.parameters(), lr=1e-3)
        assert opt is not None

    def test_step(self):
        from nova_arsenal.optimizers.muon import MuonAdamW

        model = torch.nn.Linear(10, 5)
        opt = MuonAdamW(model.parameters(), lr=1e-3)
        loss = model(torch.randn(2, 10)).sum()
        loss.backward()
        opt.step()
        opt.zero_grad()


# ── mHC Architecture Tests ───────────────────────────────────────────────────

@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestManifoldConstrainedHyperConnection:
    def test_initialization(self):
        from nova_arsenal.arch.mhc import ManifoldConstrainedHyperConnection

        mhc = ManifoldConstrainedHyperConnection(hidden_dim=256, nhc=4)
        assert mhc.nhc == 4
        assert mhc.hidden_dim == 256

    def test_forward(self):
        from nova_arsenal.arch.mhc import ManifoldConstrainedHyperConnection

        mhc = ManifoldConstrainedHyperConnection(hidden_dim=128, nhc=4)
        x = torch.randn(2, 10, 128)  # batch=2, seq=10, dim=128
        out = mhc(x)
        assert out.shape == x.shape

    def test_sinkhorn_knopp(self):
        from nova_arsenal.arch.mhc import sinkhorn_knopp

        mat = torch.rand(4, 4)
        result = sinkhorn_knopp(mat, num_iters=20)
        # Should be doubly stochastic (rows and cols sum to ~1)
        assert torch.allclose(result.sum(dim=1), torch.ones(4), atol=1e-3)
        assert torch.allclose(result.sum(dim=0), torch.ones(4), atol=1e-3)


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestAnticipatoryRouter:
    def test_initialization(self):
        from nova_arsenal.arch.mhc import AnticipatoryRouter

        router = AnticipatoryRouter(num_experts=8)
        assert router.num_experts == 8

    def test_route(self):
        from nova_arsenal.arch.mhc import AnticipatoryRouter

        router = AnticipatoryRouter(num_experts=4)
        x = torch.randn(2, 10, 64)
        routing_weights, expert_indices = router(x)
        assert routing_weights.shape[0] == 2
        assert expert_indices.shape[0] == 2


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestMultimodalProjection:
    def test_initialization(self):
        from nova_arsenal.arch.mhc import MultimodalProjection

        proj = MultimodalProjection(text_dim=256, image_dim=512, output_dim=256)
        assert proj.output_dim == 256

    def test_forward(self):
        from nova_arsenal.arch.mhc import MultimodalProjection

        proj = MultimodalProjection(text_dim=128, image_dim=256, output_dim=128)
        text = torch.randn(2, 10, 128)
        image = torch.randn(2, 5, 256)
        out = proj(text, image)
        assert out.shape[0] == 2
        assert out.shape[2] == 128


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestBlockBuilder:
    def test_build_block(self):
        from nova_arsenal.arch.mhc import build_deepseek_v4_block

        block = build_deepseek_v4_block(
            hidden_dim=128,
            num_heads=4,
            num_experts=8,
            top_k=2,
        )
        assert block is not None
