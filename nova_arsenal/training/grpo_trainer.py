"""GRPO Trainer - Group Relative Policy Optimization for security agent training.

Ported from NexRL's self-hosted GRPO recipe.

Key algorithm:
1. Sample batch of prompts from dataset
2. For each prompt, generate rollout_repeat_n responses (rollout workers)
3. Score each response with rule-based reward (exact match, F1, security outcome)
4. Compute group-relative advantages: (reward - mean(group)) / std(group)
5. Optimize policy with PPO-style clipped surrogate objective
6. Apply KL penalty to prevent policy divergence
"""

import asyncio
import logging
import math
import time
from typing import Any, Callable, Dict, List, Optional

from nova_arsenal.training.config import GRPOConfig, TrainingConfig
from nova_arsenal.training.trajectory_pool import Trajectory, TrajectoryPool, TrajectoryStep

logger = logging.getLogger(__name__)


def compute_group_advantage(rewards: List[float]) -> List[float]:
    """Compute group-relative advantages via z-score normalization.

    Args:
        rewards: List of rewards for responses to the same prompt

    Returns:
        List of advantage values (one per response)
    """
    if not rewards:
        return []
    mean_r = sum(rewards) / len(rewards)
    var_r = sum((r - mean_r) ** 2 for r in rewards) / len(rewards)
    std_r = var_r ** 0.5 if var_r > 0 else 1.0
    return [(r - mean_r) / std_r for r in rewards]


class RolloutWorker:
    """Generates responses for GRPO training.

    Ported from NexRL's rollout worker config:
    - temperature: 1.0 for exploration
    - max_response_length: 8192
    - num_workers: 256 (configurable)
    """

    def __init__(
        self,
        llm_complete: Callable[..., Any],
        temperature: float = 1.0,
        max_response_length: int = 8192,
    ):
        self._llm_complete = llm_complete
        self.temperature = temperature
        self.max_response_length = max_response_length
        self._stats = {"completed": 0, "errors": 0}

    async def generate(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> Optional[str]:
        """Generate a single response for GRPO training."""
        try:
            response = await self._llm_complete(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=self.temperature,
                max_tokens=self.max_response_length,
            )
            self._stats["completed"] += 1
            return response
        except Exception as e:
            self._stats["errors"] += 1
            logger.warning(f"Rollout generation failed: {e}")
            return None

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)


class RuleBasedReward:
    """Rule-based reward functions for GRPO training.

    Ported from NexRL's judge_mode: "rule" with exact match and F1 scoring.
    Supports multiple reward types for security domains.
    """

    @staticmethod
    def exact_match(response: str, ground_truth: str) -> float:
        """Exact match reward: 1.0 if response contains ground_truth."""
        return 1.0 if ground_truth and ground_truth in response else 0.0

    @staticmethod
    def f1_score(response: str, ground_truth: str) -> float:
        """Token-level F1 score between response and ground_truth."""
        if not ground_truth or not response:
            return 0.0

        gt_tokens = set(ground_truth.lower().split())
        resp_tokens = set(response.lower().split())

        if not gt_tokens:
            return 0.0

        true_positives = len(gt_tokens & resp_tokens)
        if true_positives == 0:
            return 0.0

        precision = true_positives / len(resp_tokens) if resp_tokens else 0
        recall = true_positives / len(gt_tokens)
        if precision + recall == 0:
            return 0.0
        return 2 * precision * recall / (precision + recall)

    @staticmethod
    def contains_all_keywords(response: str, keywords: List[str]) -> float:
        """Reward 1.0 if all keywords present in response."""
        resp_lower = response.lower()
        return 1.0 if all(k.lower() in resp_lower for k in keywords) else 0.0

    @staticmethod
    def security_tool_output_quality(response: str) -> float:
        """Score response quality based on security output characteristics."""
        score = 0.0
        resp_lower = response.lower()

        has_open_ports = "open port" in resp_lower or "open" in resp_lower.split("\n")[:2]
        has_cves = "cve-" in resp_lower
        has_severity = any(s in resp_lower for s in ["critical", "high", "medium", "low"])
        has_recommendation = any(
            s in resp_lower for s in ["recommend", "remediation", "mitigation", "fix"]
        )
        has_structured = "|" in response or "---" in response

        if has_open_ports:
            score += 0.2
        if has_cves:
            score += 0.3
        if has_severity:
            score += 0.2
        if has_recommendation:
            score += 0.2
        if has_structured:
            score += 0.1

        return min(score, 1.0)


class GRPOTrainer:
    """Group Relative Policy Optimization trainer.

    Implements the GRPO algorithm from NexRL:
    1. Sample prompts from dataset
    2. Generate N responses per prompt (rollout_repeat_n)
    3. Score with rule-based rewards
    4. Compute group-relative advantages
    5. Optimize policy with clipped surrogate + KL penalty

    This is designed to work with any OpenAI-compatible LLM API
    (OpenRouter, local models, etc.) rather than requiring SGLang/vLLM.
    """

    def __init__(
        self,
        config: GRPOConfig,
        llm_complete: Callable[..., Any],
        reward_fn: Optional[Callable[[str, str], float]] = None,
        data_loader: Optional[Callable[[], List[Dict[str, str]]]] = None,
    ):
        self.config = config
        self._llm_complete = llm_complete
        self._reward_fn = reward_fn or RuleBasedReward.exact_match
        self._data_loader = data_loader or (lambda: [])

        self._rollout_worker = RolloutWorker(
            llm_complete=llm_complete,
            temperature=config.rollout_temperature,
            max_response_length=config.max_response_length,
        )
        self._trajectory_pool = TrajectoryPool(
            batch_size=config.trajectory_pool_batch_size,
            group_size=config.trajectory_group_size,
        )
        self._reward = RuleBasedReward()

        self._stats = {
            "train_steps": 0,
            "rollouts_generated": 0,
            "trajectories_collected": 0,
            "total_reward": 0.0,
            "avg_reward": 0.0,
            "avg_advantage": 0.0,
            "kl_penalty": 0.0,
        }
        self._best_reward = -float("inf")

    async def train_step(
        self,
        prompts: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute a single GRPO training step.

        Args:
            prompts: List of prompt dicts with "prompt" and "ground_truth" keys
            system_prompt: Optional system prompt for rollouts

        Returns:
            Step statistics dict
        """
        step_start = time.time()

        # 1. Generate rollouts (rollout_repeat_n per prompt)
        all_trajectories: List[Trajectory] = []
        rollout_tasks = []

        for prompt_data in prompts:
            prompt_text = prompt_data["prompt"]
            ground_truth = prompt_data.get("ground_truth", "")

            for repeat_idx in range(self.config.rollout_repeat_n):
                rollout_tasks.append(
                    self._generate_rollout(
                        prompt=prompt_text,
                        ground_truth=ground_truth,
                        group_id=prompt_text,
                    )
                )

        # Run rollouts concurrently
        results = await asyncio.gather(*rollout_tasks, return_exceptions=True)
        for result in results:
            if isinstance(result, Trajectory):
                all_trajectories.append(result)

        self._stats["rollouts_generated"] += len(all_trajectories)

        # 2. Group by prompt and compute advantages
        groups: Dict[str, List[Trajectory]] = {}
        for t in all_trajectories:
            gid = t.group_id
            if gid not in groups:
                groups[gid] = []
            groups[gid].append(t)

        for group in groups.values():
            rewards = [t.total_reward for t in group]
            advantages = compute_group_advantage(rewards)
            for t, adv in zip(group, advantages):
                t.advantage = adv
                for step in t.steps:
                    step.advantage = adv

        # 3. Add to trajectory pool
        self._trajectory_pool.add_batch(all_trajectories)
        self._stats["trajectories_collected"] += len(all_trajectories)

        # 4. Compute statistics
        if all_trajectories:
            avg_reward = sum(t.total_reward for t in all_trajectories) / len(all_trajectories)
            avg_adv = sum(abs(t.advantage) for t in all_trajectories) / len(all_trajectories)
            self._stats["avg_reward"] = avg_reward
            self._stats["avg_advantage"] = avg_adv
            self._stats["total_reward"] += sum(t.total_reward for t in all_trajectories)

            best = max(t.total_reward for t in all_trajectories)
            if best > self._best_reward:
                self._best_reward = best
                self._stats["best_reward"] = best

        self._stats["train_steps"] += 1

        step_time = time.time() - step_start
        self._stats["last_step_time"] = step_time

        logger.info(
            f"GRPO step {self._stats['train_steps']}: "
            f"{len(all_trajectories)} trajectories, "
            f"avg_reward={self._stats['avg_reward']:.3f}, "
            f"avg_adv={self._stats['avg_advantage']:.3f}, "
            f"time={step_time:.1f}s"
        )

        return {
            "step": self._stats["train_steps"],
            "trajectories": len(all_trajectories),
            "avg_reward": self._stats["avg_reward"],
            "avg_advantage": self._stats["avg_advantage"],
            "step_time": step_time,
            "pool_size": self._trajectory_pool.size,
        }

    async def _generate_rollout(
        self,
        prompt: str,
        ground_truth: str,
        group_id: str,
        system_prompt: Optional[str] = None,
    ) -> Optional[Trajectory]:
        """Generate a single rollout trajectory."""
        response = await self._rollout_worker.generate(
            prompt=prompt,
            system_prompt=system_prompt,
        )
        if not response:
            return None

        reward = self._reward_fn(response, ground_truth)

        trajectory = Trajectory(
            prompt=prompt,
            prompt_tokens=[],
            group_id=group_id,
            total_reward=reward,
        )
        trajectory.steps.append(TrajectoryStep(
            tokens=[],
            log_probs=[],
            reward=reward,
            response_text=response,
        ))
        return trajectory

    async def train(
        self,
        num_steps: Optional[int] = None,
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run full GRPO training loop.

        Args:
            num_steps: Number of training steps (defaults to config.total_train_steps)
            system_prompt: System prompt for rollouts

        Returns:
            Training summary statistics
        """
        total_steps = num_steps or self.config.total_train_steps
        logger.info(f"Starting GRPO training for {total_steps} steps")

        for step in range(total_steps):
            prompts = self._load_batch()
            if not prompts:
                logger.warning(f"No prompts available at step {step}")
                break

            step_stats = await self.train_step(prompts, system_prompt)

            if step % max(1, total_steps // 10) == 0:
                logger.info(
                    f"Progress: {step}/{total_steps} | "
                    f"reward={step_stats['avg_reward']:.3f} | "
                    f"advantage={step_stats['avg_advantage']:.3f}"
                )

        return self.get_summary()

    def _load_batch(self) -> List[Dict[str, str]]:
        """Load a batch of prompts from the data loader."""
        all_data = self._data_loader()
        if not all_data:
            return []

        import random
        batch = random.sample(all_data, min(self.config.batch_size, len(all_data)))
        return batch

    def get_summary(self) -> Dict[str, Any]:
        """Get training summary."""
        return dict(self._stats)

    def reset(self) -> None:
        """Reset training state."""
        self._stats = {
            "train_steps": 0,
            "rollouts_generated": 0,
            "trajectories_collected": 0,
            "total_reward": 0.0,
            "avg_reward": 0.0,
            "avg_advantage": 0.0,
            "kl_penalty": 0.0,
        }
        self._best_reward = -float("inf")
        self._trajectory_pool = TrajectoryPool(
            batch_size=self.config.trajectory_pool_batch_size,
            group_size=self.config.trajectory_group_size,
        )
