"""
Nova Training Pipeline - GRPO-based reinforcement learning for security agents.

Ported from NexRL's self-hosted GRPO recipe and GLM-5 agentic RL innovations:
- GRPO with group-relative advantages (NexRL recipe)
- Asynchronous Agentic RL with TITO + Double-sided IS + off-policy dropping (GLM-5)
- On-Policy Cross-Stage Distillation for multi-stage RL (GLM-5)
- SWE/Terminal/Search environment abstractions (GLM-5)
"""
from nova_arsenal.training.config import GRPOConfig, OPDConfig, TrainingConfig
from nova_arsenal.training.cross_stage_distillation import (
    CrossStageDistillationConfig,
    CrossStageDistillationTrainer,
    RLStage,
    TeacherSnapshot,
    compute_cross_stage_advantage,
)
from nova_arsenal.training.glm_agentic_rl import (
    AgenticTaskType,
    AsyncAgenticRLTrainer,
    DPAwareRouter,
    DoubledSidedImportanceSampling,
    MultiTaskRolloutOrchestrator,
    OffPolicySampleDropper,
    SWEEnvironment,
    SearchEnvironment,
    TerminalEnvironment,
    TITOGateway,
)
from nova_arsenal.training.grpo_trainer import GRPOTrainer, compute_group_advantage
from nova_arsenal.training.trajectory_pool import TrajectoryPool, Trajectory

__all__ = [
    "GRPOConfig", "OPDConfig", "TrainingConfig",
    "GRPOTrainer", "compute_group_advantage",
    "TrajectoryPool", "Trajectory",
    "TITOGateway", "DoubledSidedImportanceSampling",
    "OffPolicySampleDropper", "DPAwareRouter",
    "MultiTaskRolloutOrchestrator", "AsyncAgenticRLTrainer",
    "AgenticTaskType", "SWEEnvironment", "TerminalEnvironment",
    "SearchEnvironment",
    "CrossStageDistillationConfig", "CrossStageDistillationTrainer",
    "RLStage", "TeacherSnapshot", "compute_cross_stage_advantage",
]
