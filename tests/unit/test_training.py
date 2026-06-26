"""
Tests for Nova-Arsenal Training Pipeline (GRPO, Agentic RL, Distillation).
"""

import pytest


# ── GRPO Config Tests ────────────────────────────────────────────────────────

class TestGRPOConfig:
    def test_default_config(self):
        from nova_arsenal.training.config import GRPOConfig

        cfg = GRPOConfig()
        assert cfg.batch_size == 32
        assert cfg.rollout_repeat_n == 8
        assert cfg.rollout_temperature == 1.0
        assert cfg.clip_ratio == 0.2

    def test_custom_config(self):
        from nova_arsenal.training.config import GRPOConfig

        cfg = GRPOConfig(batch_size=16, clip_ratio=0.1, rollout_temperature=0.8)
        assert cfg.batch_size == 16
        assert cfg.clip_ratio == 0.1
        assert cfg.rollout_temperature == 0.8


# ── Trajectory Pool Tests ────────────────────────────────────────────────────

class TestTrajectoryPool:
    def test_trajectory_creation(self):
        from nova_arsenal.training.trajectory_pool import Trajectory, TrajectoryStep

        step = TrajectoryStep(tokens=[1, 2, 3], log_probs=[-0.5, -0.3, -0.1])
        traj = Trajectory(prompt="test prompt", prompt_tokens=[10, 11], steps=[step], total_reward=0.5)
        assert traj.prompt == "test prompt"
        assert len(traj.steps) == 1
        assert traj.total_reward == 0.5
        assert traj.length == 1

    def test_compute_group_advantages(self):
        from nova_arsenal.training.trajectory_pool import Trajectory, TrajectoryPool

        pool = TrajectoryPool()
        group = [
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.8),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.2),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.6),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.4),
        ]
        advantages = pool.compute_group_advantages(group)
        assert len(advantages) == 4
        assert abs(sum(advantages)) < 1e-6  # should sum to ~0

    def test_advantages_positive_for_high_reward(self):
        from nova_arsenal.training.trajectory_pool import Trajectory, TrajectoryPool

        pool = TrajectoryPool()
        group = [
            Trajectory(prompt="p", prompt_tokens=[], total_reward=1.0),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.0),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.0),
            Trajectory(prompt="p", prompt_tokens=[], total_reward=0.0),
        ]
        advantages = pool.compute_group_advantages(group)
        assert advantages[0] > 0  # highest reward gets positive advantage
        assert advantages[1] < 0  # lower rewards get negative

    def test_pool_add_and_get(self):
        from nova_arsenal.training.trajectory_pool import Trajectory, TrajectoryPool

        pool = TrajectoryPool(batch_size=2)
        for _ in range(5):
            pool.add(Trajectory(prompt="p", prompt_tokens=[], total_reward=0.5))
        assert pool.size == 5
        batch = pool.get_batch()
        assert len(batch) == 2
        assert pool.size == 3


# ── GLM Agentic RL Tests ─────────────────────────────────────────────────────

class TestGLMAgenticRL:
    def test_tito_gateway_exists(self):
        from nova_arsenal.training.glm_agentic_rl import TITOGateway

        gw = TITOGateway()
        assert hasattr(gw, "record_fragment")

    def test_importance_sampling_exists(self):
        from nova_arsenal.training.glm_agentic_rl import DoubledSidedImportanceSampling

        sampler = DoubledSidedImportanceSampling()
        assert hasattr(sampler, "compute_clipped_ratio")

    def test_off_policy_dropper_exists(self):
        from nova_arsenal.training.glm_agentic_rl import OffPolicySampleDropper

        dropper = OffPolicySampleDropper()
        assert hasattr(dropper, "advance_version")
        assert dropper.current_version == 0

    def test_dp_aware_router_exists(self):
        from nova_arsenal.training.glm_agentic_rl import DPAwareRouter

        router = DPAwareRouter()
        assert hasattr(router, "get_rank")
        assert hasattr(router, "rebalance")

    def test_task_service_exists(self):
        from nova_arsenal.training.glm_agentic_rl import TaskService

        svc = TaskService(
            task_type="test",
            rollout_fn=lambda x: x,
            reward_fn=lambda x, y: 0.5,
        )
        assert svc.task_type == "test"

    def test_multi_task_orchestrator_exists(self):
        from nova_arsenal.training.glm_agentic_rl import MultiTaskRolloutOrchestrator

        orch = MultiTaskRolloutOrchestrator()
        assert hasattr(orch, "register_service")


# ── Cross-Stage Distillation Tests ───────────────────────────────────────────

class TestCrossStageDistillation:
    def test_rl_stage_enum(self):
        from nova_arsenal.training.cross_stage_distillation import RLStage

        assert RLStage.REASONING.value == "reasoning"
        assert RLStage.AGENTIC.value == "agentic"
        assert RLStage.GENERAL.value == "general"

    def test_teacher_snapshot_exists(self):
        from nova_arsenal.training.cross_stage_distillation import RLStage, TeacherSnapshot

        snap = TeacherSnapshot(stage=RLStage.REASONING, model_name="test-model")
        assert snap.model_name == "test-model"
        assert snap.stage == RLStage.REASONING
        assert snap.sampling_weight == 1.0

    def test_teacher_logit_cache_exists(self):
        from nova_arsenal.training.cross_stage_distillation import TeacherLogitCache

        cache = TeacherLogitCache()
        assert hasattr(cache, "get")
        assert hasattr(cache, "put")


# ── Training Config Tests ────────────────────────────────────────────────────

class TestTrainingConfig:
    def test_opd_config(self):
        from nova_arsenal.training.config import OPDConfig

        cfg = OPDConfig()
        assert cfg.batch_size == 32
        assert cfg.distillation_coeff == 1.0

    def test_training_config(self):
        from nova_arsenal.training.config import TrainingConfig

        cfg = TrainingConfig()
        assert cfg.experiment_name == "nova-grpo-experiment"
        assert cfg.log_freq == 10
