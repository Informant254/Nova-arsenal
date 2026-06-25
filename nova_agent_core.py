"""
Nova Agent Core - Autonomous security research agent with full agentic loop.

This module provides both:
- The NovaAgent class (used by existing tests)
- The AgentRunner integration for full autonomous operation
"""

import os
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional


@dataclass
class AgentState:
    """Current state of the agent during execution."""

    step: int = 0
    findings: List[Dict[str, Any]] = field(default_factory=list)
    actions_taken: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class NovaAgent:
    """
    Autonomous security research agent.
    
    Can operate in two modes:
    1. Basic mode (existing): plan/step/reflect for manual use
    2. Autonomous mode: delegates to AgentRunner for full autonomy
    """

    def __init__(
        self,
        target: str,
        objective: str = "Find and exploit all critical vulnerabilities",
        max_steps: int = 40,
        model: str = "deepseek-r1",
        workspace: Optional[str] = None,
    ) -> None:
        self.target = target
        self.objective = objective
        self.max_steps = max_steps
        self.model = model
        self.workspace = workspace or os.path.join(
            os.path.expanduser("~"), "nova_workspace", target.replace(".", "_")
        )
        self.state = AgentState()
        self._history: List[Dict[str, Any]] = []
        self._runner: Optional[Any] = None

    def plan(self) -> List[str]:
        """Generate a plan of attack for the target."""
        return [
            f"Reconnaissance: enumerate services on {self.target}",
            f"Vulnerability scanning: identify weaknesses",
            f"Exploitation: attempt to exploit found vulnerabilities",
            f"Post-exploitation: assess impact and extract data",
            f"Reporting: compile findings for {self.target}",
        ]

    def step(self, action: str, result: str) -> None:
        """Record an agent step."""
        self.state.step += 1
        self.state.actions_taken.append(action)
        self._history.append({
            "step": self.state.step,
            "action": action,
            "result": result,
        })

    def add_finding(self, finding: Dict[str, Any]) -> None:
        """Record a security finding."""
        self.state.findings.append(finding)

    def reflect(self) -> str:
        """Reflect on current progress and adjust strategy."""
        completed = self.state.step
        findings_count = len(self.state.findings)
        return (
            f"Step {completed}/{self.max_steps}. "
            f"Found {findings_count} findings so far. "
            f"Objective: {self.objective}"
        )

    def get_history(self) -> List[Dict[str, Any]]:
        """Return the action history."""
        return list(self._history)

    def summary(self) -> Dict[str, Any]:
        """Return a summary of the agent session."""
        return {
            "target": self.target,
            "objective": self.objective,
            "steps_taken": self.state.step,
            "max_steps": self.max_steps,
            "findings": len(self.state.findings),
            "errors": len(self.state.errors),
            "model": self.model,
        }

    # ── Autonomous Mode ─────────────────────────────────────────────────────

    async def run_autonomous(
        self,
        scope: Optional[List[str]] = None,
        llm_complete: Optional[Callable[..., Coroutine[Any, Any, str]]] = None,
        on_event: Optional[Callable[..., Coroutine[Any, Any, None]]] = None,
        sandbox_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Run the fully autonomous agent loop.
        
        This delegates to AgentRunner for the complete cycle:
        LLM reasoning → tool selection → command execution → result analysis → iteration
        """
        from nova_arsenal.agent_runner import create_runner

        self._runner = create_runner(
            target=self.target,
            objective=self.objective,
            max_steps=self.max_steps,
            scope=scope or [self.target],
            llm_complete=llm_complete,
            on_event=on_event,
            sandbox_mode=sandbox_mode,
        )

        result = await self._runner.run()

        # Sync findings back to the basic state
        self.state.findings = result.get("findings", [])
        self.state.step = result.get("steps_taken", 0)

        return result

    async def step_once(
        self,
        instruction: str = "",
        scope: Optional[List[str]] = None,
        llm_complete: Optional[Callable[..., Coroutine[Any, Any, str]]] = None,
    ) -> Dict[str, Any]:
        """Execute a single step in autonomous mode."""
        from nova_arsenal.agent_runner import create_runner

        if not self._runner:
            self._runner = create_runner(
                target=self.target,
                objective=self.objective,
                max_steps=self.max_steps,
                scope=scope or [self.target],
                llm_complete=llm_complete,
            )

        action = await self._runner.step_once(instruction)
        return action.to_dict()

    def get_runner(self) -> Optional[Any]:
        """Get the underlying AgentRunner instance."""
        return self._runner

    def stop(self) -> None:
        """Stop the autonomous agent."""
        if self._runner:
            self._runner.stop()
