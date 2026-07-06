"""
Nova Self-Evolution Loop - Self-optimizing intelligence engine.

Analyzes agent trajectories in real-time to detect:
1. Tool failures and suggesting alternatives.
2. Recursive logic loops and breaking them.
3. Successful patterns and promoting them to 'skills'.
4. Token-usage inefficiencies and optimizing prompts.
"""

import logging
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

@dataclass
class OptimizationSuggestion:
    type: str  # tool_swap, strategy_shift, loop_break, skill_draft
    reasoning: str
    action: str
    confidence: float
    metadata: Dict[str, Any] = field(default_factory=dict)

class SelfOptimizer:
    """
    Analyzes agent actions and results to evolve the agent's strategy.

    Powers the 'Nova Self-Evolution Loop'.
    """

    def __init__(self):
        self.history: List[Dict[str, Any]] = []
        self.success_patterns: List[str] = []
        self.failure_patterns: List[str] = []

    def analyze_trajectory(self, actions: List[Any]) -> List[OptimizationSuggestion]:
        """Analyze a list of AgentActions and suggest improvements."""
        suggestions = []

        if not actions:
            return suggestions

        # 1. Detect command failure patterns
        failed_commands = [a for a in actions if a.result and a.result.exit_code != 0]
        if len(failed_commands) >= 2:
            suggestions.append(OptimizationSuggestion(
                type="strategy_shift",
                reasoning=f"Detected {len(failed_commands)} consecutive command failures. Switching from direct exploitation to deep reconnaissance.",
                action="RECON_FOCUS",
                confidence=0.8
            ))

        # 2. Detect tool-specific issues
        for a in actions:
            if a.result and "not found" in (a.result.stderr or "").lower():
                suggestions.append(OptimizationSuggestion(
                    type="tool_swap",
                    reasoning=f"Tool '{a.command.split()[0]}' not found in environment.",
                    action=f"USE_ALTERNATIVE_FOR_{a.command.split()[0]}",
                    confidence=0.9,
                    metadata={"missing_tool": a.command.split()[0]}
                ))

        # 3. Detect infinite loops (same command repeated)
        if len(actions) > 3:
            recent_cmds = [a.command for a in actions[-3:] if a.command]
            if len(set(recent_cmds)) == 1 and recent_cmds[0]:
                suggestions.append(OptimizationSuggestion(
                    type="loop_break",
                    reasoning="Infinite loop detected: same command repeated 3 times with no change in state.",
                    action="DIVERSIFY_ATTACK",
                    confidence=1.0
                ))

        # 4. Successful pattern detection (Potential Skill)
        successful_exploits = [a for a in actions if a.phase.value == "exploitation" and a.result and a.result.exit_code == 0]
        if successful_exploits:
            suggestions.append(OptimizationSuggestion(
                type="skill_draft",
                reasoning="Successful exploitation pattern detected. Candidate for self-authored skill.",
                action="DRAFT_SKILL",
                confidence=0.7,
                metadata={"exploit_steps": [a.command for a in successful_exploits]}
            ))

        return suggestions

    async def evolve_strategy(self, current_strategy: Dict[str, Any], suggestions: List[OptimizationSuggestion]) -> Dict[str, Any]:
        """Update the agent's strategy based on optimization suggestions."""
        new_strategy = current_strategy.copy()

        for sug in suggestions:
            if sug.type == "strategy_shift":
                new_strategy["primary_vector"] = "reconnaissance"
                new_strategy["reasoning"] += f" | EVOLVED: {sug.reasoning}"
            elif sug.type == "loop_break":
                new_strategy["diversify"] = True
                new_strategy["force_new_tool"] = True

        return new_strategy
