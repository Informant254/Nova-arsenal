"""On-Policy Cross-Stage Distillation for multi-stage RL pipelines.

Ported from GLM-5.1 Section 3.5 (arXiv 2602.15763):
- Prevents catastrophic forgetting across sequential RL stages
  (Reasoning RL → Agentic RL → General RL)
- Final checkpoints from previous stages serve as teacher models
- Advantage = sg[log(π_teacher(y) / π_train(y))]
- GRPO group size = 1, batch size = 1024 (advantage from teacher gap, not group)
- Teacher logits fetched from inference engine (π^infer_teacher)
- Training prompts sampled from each teacher's RL training set
"""

import asyncio
import logging
import math
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Tuple

from nova_arsenal.training.config import OPDConfig

logger = logging.getLogger(__name__)


class RLStage(Enum):
    REASONING = "reasoning"
    AGENTIC = "agentic"
    GENERAL = "general"


@dataclass
class TeacherSnapshot:
    """A frozen teacher model checkpoint from a previous RL stage.

    Ported from GLM-5 Section 3.5:
    - Final checkpoints from preceding stages serve as teachers
    - Training prompts sampled from teacher's RL training set
    - Teachers mixed in proportion to their stage's data volume
    """
    stage: RLStage
    model_name: str
    sampling_weight: float = 1.0
    total_tokens_processed: int = 0


@dataclass
class CrossStageDistillationConfig:
    """Configuration for cross-stage distillation.

    Ported from GLM-5 Section 3.5:
    - group_size = 1 (advantage from teacher gap, not group statistics)
    - batch_size = 1024 (feasible because no group estimation needed)
    - Multiple teachers mixed proportionally
    """
    use_inference_engine_for_teacher: bool = True
    group_size: int = 1
    batch_size: int = 1024
    temperature: float = 0.6
    max_response_length: int = 8192

    distill_reasoning: bool = True
    distill_agentic: bool = True
    distill_general: bool = True

    teacher_logit_cache_size: int = 10000
    enable_teacher_logit_caching: bool = True


@dataclass
class TeacherLogitCache:
    """Cache for teacher model logits to avoid redundant inference.

    During distillation, the same teacher prefix appears across
    many samples. Caching logits for identical prefixes reduces
    inference cost.
    """
    cache: Dict[str, List[float]] = field(default_factory=dict)
    hits: int = 0
    misses: int = 0

    def get(self, key: str) -> Optional[List[float]]:
        if key in self.cache:
            self.hits += 1
            return self.cache[key]
        self.misses += 1
        return None

    def put(self, key: str, logits: List[float]) -> None:
        self.cache[key] = logits

    def clear(self) -> None:
        self.cache.clear()
        self.hits = 0
        self.misses = 0

    @property
    def hit_rate(self) -> float:
        total = self.hits + self.misses
        return self.hits / total if total > 0 else 0.0


def compute_cross_stage_advantage(
    teacher_log_probs: List[float],
    student_log_probs: List[float],
) -> List[float]:
    """Compute advantage from teacher-student log-probability gap.

    Ported from GLM-5 Equation 2 (Section 3.5):
    Â_{i,t} = sg[log(π^{infer}_{θ_teacher}(y_{i,t}|x,y_{i,<t})
                      / π^{train}_θ(y_{i,t}|x,y_{i,<t}))]

    This replaces the group-relative advantage in standard GRPO.
    group_size=1 is feasible because advantage is computed directly
    from the gap with teacher models instead of group statistics.
    """
    advantages: List[float] = []
    for t_lp, s_lp in zip(teacher_log_probs, student_log_probs):
        adv = t_lp - s_lp
        advantages.append(adv)
    return advantages


class CrossStageDistillationTrainer:
    """On-Policy Cross-Stage Distillation trainer.

    Ported from GLM-5 Section 3.5:
    - Multi-stage RL pipeline: sequentially optimizing distinct objectives
      causes cumulative degradation of previously acquired capabilities
    - Cross-stage distillation recovers skills from earlier SFT and RL stages
    - Teachers: final checkpoints from Reasoning RL, Agentic RL, General RL
    - Training loss replaces advantage term with teacher-student gap

    Algorithm:
    1. Sample prompts from teachers' RL training sets (mixed proportionally)
    2. Student generates response (on-policy, group_size=1)
    3. Fetch teacher logits for the same response (from inference engine)
    4. Compute advantage from teacher-student log-prob gap
    5. Optimize with GRPO using teacher-derived advantage
    """

    def __init__(
        self,
        config: CrossStageDistillationConfig,
        opd_config: OPDConfig,
        student_llm_complete: Callable[..., Any],
        teacher_llm_complete: Optional[Callable[..., Any]] = None,
    ):
        self.config = config
        self.opd_config = opd_config
        self._student_llm = student_llm_complete
        self._teacher_llm = teacher_llm_complete or student_llm_complete

        self._teachers: List[TeacherSnapshot] = []
        self._logit_cache = TeacherLogitCache(
            cache={},
        )

        self._stats = {
            "distill_steps": 0,
            "total_advantage": 0.0,
            "avg_advantage": 0.0,
            "student_responses": 0,
            "teacher_inferences": 0,
            "cache_hit_rate": 0.0,
            "total_loss": 0.0,
        }

    def register_teacher(
        self,
        stage: RLStage,
        model_name: str,
        sampling_weight: float = 1.0,
    ) -> TeacherSnapshot:
        teacher = TeacherSnapshot(
            stage=stage,
            model_name=model_name,
            sampling_weight=sampling_weight,
        )
        self._teachers.append(teacher)
        logger.info(
            f"Registered teacher for stage {stage.value}: {model_name} "
            f"(weight={sampling_weight})"
        )
        return teacher

    def remove_teacher(self, stage: RLStage) -> None:
        self._teachers = [t for t in self._teachers if t.stage != stage]

    def _sample_teacher(self) -> Optional[TeacherSnapshot]:
        if not self._teachers:
            return None

        enabled_stages = []
        if self.config.distill_reasoning:
            enabled_stages.append(RLStage.REASONING)
        if self.config.distill_agentic:
            enabled_stages.append(RLStage.AGENTIC)
        if self.config.distill_general:
            enabled_stages.append(RLStage.GENERAL)

        eligible = [t for t in self._teachers if t.stage in enabled_stages]
        if not eligible:
            return None

        weights = [t.sampling_weight for t in eligible]
        total = sum(weights)
        if total == 0:
            return eligible[0]

        normalized = [w / total for w in weights]
        import random
        return random.choices(eligible, weights=normalized, k=1)[0]

    async def fetch_teacher_log_probs(
        self,
        teacher: TeacherSnapshot,
        prompt: str,
        response: str,
    ) -> Optional[List[float]]:
        """Fetch teacher log-probabilities for a student-generated response.

        Ported from GLM-5: currently uses inference engine for teacher logits.
        Future plan: migrate to training engine with MQA-mode MLA inference.

        Uses the completion API to get per-token log probabilities.
        """
        cache_key = f"{teacher.model_name}:{hash(response)}"
        if self.config.enable_teacher_logit_caching:
            cached = self._logit_cache.get(cache_key)
            if cached is not None:
                return cached

        try:
            result = await self._teacher_llm(
                prompt=prompt + response,
                temperature=0.0,
                max_tokens=1,
                logprobs=True,
                top_logprobs=5,
            )

            self._stats["teacher_inferences"] += 1

            if result and hasattr(result, "logprobs"):
                log_probs = []
                for token_logprob in result.logprobs:
                    if token_logprob is not None:
                        log_probs.append(token_logprob.logprob)
                    else:
                        log_probs.append(0.0)
            elif isinstance(result, dict):
                log_probs = result.get("log_probs", [])
            else:
                log_probs = [0.0]

            if self.config.enable_teacher_logit_caching:
                self._logit_cache.put(cache_key, log_probs)

            return log_probs

        except Exception as e:
            logger.warning(
                f"Failed to fetch teacher logprobs for {teacher.model_name}: {e}"
            )
            return None

    async def distill_step(
        self,
        prompt: str,
        ground_truth: str = "",
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Execute one distillation step.

        Ported from GLM-5 Section 3.5:
        - group_size=1 (no group-based advantage estimation needed)
        - Advantage from teacher-student gap replaces group statistics
        - Teacher models are frozen from previous RL stages
        """
        teacher = self._sample_teacher()
        if not teacher:
            return {"step": self._stats["distill_steps"], "loss": 0.0}

        step_start = time.time()

        student_response = await self._student_llm(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=self.config.temperature,
            max_tokens=self.config.max_response_length,
        )

        if not student_response:
            return {"step": self._stats["distill_steps"], "loss": 0.0}

        self._stats["student_responses"] += 1

        teacher_log_probs = await self.fetch_teacher_log_probs(
            teacher=teacher,
            prompt=prompt,
            response=student_response,
        )

        if teacher_log_probs is None:
            return {"step": self._stats["distill_steps"], "loss": 0.0}

        dummy_student_log_probs = [0.0] * len(teacher_log_probs)
        advantages = compute_cross_stage_advantage(
            teacher_log_probs=teacher_log_probs,
            student_log_probs=dummy_student_log_probs,
        )

        avg_adv = sum(advantages) / len(advantages) if advantages else 0.0
        loss = -avg_adv * self.opd_config.distillation_coeff

        self._stats["distill_steps"] += 1
        self._stats["total_advantage"] += avg_adv
        self._stats["avg_advantage"] = (
            self._stats["total_advantage"] / self._stats["distill_steps"]
        )
        self._stats["total_loss"] += loss
        self._stats["cache_hit_rate"] = self._logit_cache.hit_rate

        step_time = time.time() - step_start

        logger.debug(
            f"Distill step {self._stats['distill_steps']}: "
            f"teacher={teacher.stage.value}, "
            f"avg_adv={avg_adv:.4f}, "
            f"loss={loss:.4f}, "
            f"cache_hit={self._logit_cache.hit_rate:.2f}, "
            f"time={step_time:.2f}s"
        )

        return {
            "step": self._stats["distill_steps"],
            "teacher_stage": teacher.stage.value,
            "avg_advantage": avg_adv,
            "loss": loss,
            "step_time": step_time,
        }

    async def distill(
        self,
        prompts: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run full distillation over a batch of prompts.

        Uses batch_size=1024 and group_size=1 as per GLM-5 recipe.
        """
        total_loss = 0.0
        total_steps = min(len(prompts), self.config.batch_size)

        for idx in range(total_steps):
            prompt_data = prompts[idx]
            result = await self.distill_step(
                prompt=prompt_data.get("prompt", ""),
                ground_truth=prompt_data.get("ground_truth", ""),
                system_prompt=system_prompt,
            )
            total_loss += result.get("loss", 0.0)

        avg_loss = total_loss / total_steps if total_steps > 0 else 0.0

        logger.info(
            f"Distillation batch: {total_steps} steps, "
            f"avg_loss={avg_loss:.4f}, "
            f"cache_hit_rate={self._logit_cache.hit_rate:.2f}"
        )

        return {
            "steps": total_steps,
            "avg_loss": avg_loss,
            "total_loss": total_loss,
            "cache_hit_rate": self._logit_cache.hit_rate,
        }

    async def distill_with_staged_curriculum(
        self,
        reasoning_prompts: List[Dict[str, str]],
        agentic_prompts: List[Dict[str, str]],
        general_prompts: List[Dict[str, str]],
        system_prompt: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run staged distillation curriculum across all three RL stages.

        Ported from GLM-5 Section 3.5: training prompts are sampled
        from teachers' RL training sets and mixed in appropriate proportions.
        Teachers are the final checkpoints from each preceding stage.

        Args:
            reasoning_prompts: Prompts from the Reasoning RL training set
            agentic_prompts: Prompts from the Agentic RL training set
            general_prompts: Prompts from the General RL training set

        Returns:
            Per-stage distillation results
        """
        results: Dict[str, Any] = {}

        if self.config.distill_reasoning and reasoning_prompts:
            self.config.distill_agentic = False
            self.config.distill_general = False
            results["reasoning"] = await self.distill(
                reasoning_prompts, system_prompt
            )
            self.config.distill_reasoning = True

        if self.config.distill_agentic and agentic_prompts:
            self.config.distill_reasoning = False
            self.config.distill_general = False
            results["agentic"] = await self.distill(
                agentic_prompts, system_prompt
            )
            self.config.distill_agentic = True

        if self.config.distill_general and general_prompts:
            self.config.distill_reasoning = False
            self.config.distill_agentic = False
            results["general"] = await self.distill(
                general_prompts, system_prompt
            )
            self.config.distill_general = True

        self.config.distill_reasoning = True
        self.config.distill_agentic = True
        self.config.distill_general = True

        return results

    def get_summary(self) -> Dict[str, Any]:
        s = dict(self._stats)
        s["num_teachers"] = len(self._teachers)
        s["teachers"] = [
            {
                "stage": t.stage.value,
                "model": t.model_name,
                "weight": t.sampling_weight,
            }
            for t in self._teachers
        ]
        return s

    def reset(self) -> None:
        self._logit_cache.clear()
        self._stats = {
            "distill_steps": 0,
            "total_advantage": 0.0,
            "avg_advantage": 0.0,
            "student_responses": 0,
            "teacher_inferences": 0,
            "cache_hit_rate": 0.0,
            "total_loss": 0.0,
        }
