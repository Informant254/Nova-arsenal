"""Trajectory pool for GRPO training - ported from NexRL trajectory pool.

Stores rollout trajectories and computes group-relative advantages.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class TrajectoryStep:
    """A single step within a trajectory."""
    tokens: List[int]
    log_probs: List[float]
    reward: float = 0.0
    advantage: float = 0.0
    response_text: str = ""


@dataclass
class Trajectory:
    """A complete rollout trajectory (prompt + response + reward).

    Group-relative advantages are computed across trajectories
    that share the same prompt (rollout_repeat_n per prompt).
    """
    prompt: str
    prompt_tokens: List[int]
    steps: List[TrajectoryStep] = field(default_factory=list)
    total_reward: float = 0.0
    advantage: float = 0.0
    run_id: str = ""
    group_id: str = ""

    @property
    def response_text(self) -> str:
        return "".join(s.response_text for s in self.steps) if self.steps else ""

    @property
    def length(self) -> int:
        return len(self.steps)


class TrajectoryPool:
    """Collects and manages training trajectories.

    Batches trajectories into groups for group-relative advantage computation.
    Each group corresponds to rollout_repeat_n responses for the same prompt.
    """

    def __init__(self, batch_size: int = 256, group_size: int = 1):
        self.batch_size = batch_size
        self.group_size = group_size
        self._trajectories: List[Trajectory] = []
        self._stats = {"added": 0, "batched": 0, "groups_computed": 0}

    def add(self, trajectory: Trajectory) -> None:
        self._trajectories.append(trajectory)
        self._stats["added"] += 1

    def add_batch(self, trajectories: List[Trajectory]) -> None:
        self._trajectories.extend(trajectories)
        self._stats["added"] += len(trajectories)

    def get_batch(self) -> List[Trajectory]:
        """Get a batch of trajectories and remove them from the pool."""
        batch = self._trajectories[:self.batch_size]
        self._trajectories = self._trajectories[self.batch_size:]
        self._stats["batched"] += len(batch)
        return batch

    def group_trajectories(self, trajectories: List[Trajectory]) -> Dict[str, List[Trajectory]]:
        """Group trajectories by their group_id (same prompt, different rollouts)."""
        groups: Dict[str, List[Trajectory]] = {}
        for t in trajectories:
            gid = t.group_id
            if gid not in groups:
                groups[gid] = []
            groups[gid].append(t)
        self._stats["groups_computed"] += len(groups)
        return groups

    def compute_group_advantages(
        self, group: List[Trajectory]
    ) -> List[float]:
        """Compute group-relative advantages using z-score normalization.

        Ported from NexRL's compute_grpo_advantage_for_trajectories.
        Advantage = (reward - mean(group_rewards)) / std(group_rewards)
        """
        rewards = [t.total_reward for t in group]
        if not rewards:
            return []

        mean_r = sum(rewards) / len(rewards)
        var_r = sum((r - mean_r) ** 2 for r in rewards) / len(rewards)
        std_r = var_r ** 0.5 if var_r > 0 else 1.0

        advantages = [(r - mean_r) / std_r for r in rewards]
        return advantages

    def flush(self) -> List[Trajectory]:
        """Return all remaining trajectories."""
        remaining = self._trajectories.copy()
        self._trajectories.clear()
        return remaining

    @property
    def size(self) -> int:
        return len(self._trajectories)

    @property
    def stats(self) -> Dict[str, int]:
        return dict(self._stats)

    def reset_stats(self) -> None:
        self._stats = {"added": 0, "batched": 0, "groups_computed": 0}
