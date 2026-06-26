"""Training configurations ported from NexRL recipe system."""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class GRPOConfig:
    """GRPO training hyperparameters.

    Ported from NexRL's self_hosted.yaml and common.yaml recipes.
    """
    total_train_steps: int = 200
    save_freq: int = 0

    batch_size: int = 32
    rollout_repeat_n: int = 8
    max_prompt_length: int = 4096
    max_response_length: int = 8192
    max_sequence_length: int = 12288

    num_rollout_workers: int = 256
    rollout_temperature: float = 1.0

    trajectory_pool_batch_size: int = 256
    trajectory_group_size: int = 1

    ppo_mini_batch_size: int = 28
    ppo_micro_batch_size: int = 4
    ppo_epochs: int = 1
    grad_clip: float = 1.0
    clip_ratio: float = 0.2
    learning_rate: float = 2e-6
    lr_warmup_steps_ratio: float = 0.0
    warmup_style: str = "constant"
    ulysses_sequence_parallel_size: int = 4
    ppo_max_token_len_per_gpu: int = 16384

    use_kl_in_reward: bool = False
    kl_penalty: str = "kl"
    kl_coef: float = 0.001
    kl_reward_coef: float = 0.001
    entropy_coeff: float = 1e-4

    inference_backend: str = "openrouter"
    inference_replicas: int = 4
    inference_gpus_per_replica: int = 0


@dataclass
class OPDConfig:
    """On-Policy Distillation configuration.

    Ported from NexRL's self_hosted_opd and weaver_opd recipes.
    """
    total_train_steps: int = 1000
    save_freq: int = 100

    batch_size: int = 32
    rollout_repeat_n: int = 1
    max_prompt_length: int = 4096
    max_response_length: int = 8192
    max_sequence_length: int = 12288

    num_rollout_workers: int = 32
    rollout_temperature: float = 0.6

    distillation_coeff: float = 1.0
    entropy_coeff: float = 0.00
    loss_agg_mode: str = "token-mean"
    distillation_epochs: int = 1

    student_learning_rate: float = 1e-6
    teacher_model: str = ""
    student_model: str = ""

    ppo_mini_batch_size: int = 32
    ppo_micro_batch_size: int = 4
    grad_clip: float = 1.0
    ppo_epochs: int = 1
    ulysses_sequence_parallel_size: int = 2


@dataclass
class TrainingConfig:
    """Top-level training configuration."""
    grpo: GRPOConfig = field(default_factory=GRPOConfig)
    opd: OPDConfig = field(default_factory=OPDConfig)
    experiment_name: str = "nova-grpo-experiment"
    data_path: str = ""
    data_files: List[str] = field(default_factory=list)
    judge_mode: str = "rule"
    output_dir: str = "/workspace/training"
    log_freq: int = 10
    seed: int = 42
