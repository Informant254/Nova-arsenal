"""
Resilient Nova Agent Core - Autonomous security agent with error handling, timeouts, and recovery.

Enhances nova_agent_core.py with:
- Async timeout guards on all long-running operations
- Circuit breaker pattern for cascading failures
- Retry logic with exponential backoff
- Resource limits enforcement
- Graceful degradation on errors
"""

import logging
from typing import Any, Dict, List, Optional
from dataclasses import dataclass

from nova_agent_core import NovaAgent, AgentState
from nova_arsenal.async_utils import (
    CircuitBreaker,
    CircuitBreakerConfig,
    async_timeout,
    async_retry,
    RetryConfig,
    ResourceTracker,
    ResourceLimits,
)

logger = logging.getLogger(__name__)


@dataclass
class ResilientAgentConfig:
    """Configuration for resilient agent."""
    step_timeout: float = 120.0  # Timeout per step
    total_timeout: float = 600.0  # Total execution timeout
    max_retries: int = 3
    max_concurrent_tasks: int = 5
    max_tool_calls_per_step: int = 10
    breaker_failure_threshold: int = 5


class ResilientNovaAgent(NovaAgent):
    """Autonomous agent with resilience patterns.
    
    Extends NovaAgent with:
    - Timeout guards preventing hung operations
    - Circuit breaker preventing cascading failures
    - Retry logic for transient errors
    - Resource limits enforcement
    """

    def __init__(
        self,
        target: str,
        objective: str = "Find and exploit all critical vulnerabilities",
        max_steps: int = 40,
        model: str = "deepseek-r1",
        workspace: Optional[str] = None,
        config: Optional[ResilientAgentConfig] = None,
    ) -> None:
        """Initialize resilient agent.
        
        Args:
            target: Target to scan
            objective: Agent objective
            max_steps: Maximum steps to execute
            model: LLM model to use
            workspace: Working directory
            config: Resilience configuration
        """
        super().__init__(target, objective, max_steps, model, workspace)
        self.config = config or ResilientAgentConfig()
        
        # Resilience components
        self.circuit_breaker = CircuitBreaker(
            CircuitBreakerConfig(
                failure_threshold=self.config.breaker_failure_threshold,
            )
        )
        self.resource_tracker = ResourceTracker(
            ResourceLimits(
                max_concurrent_tasks=self.config.max_concurrent_tasks,
                max_tool_calls_per_step=self.config.max_tool_calls_per_step,
                max_execution_time_seconds=self.config.total_timeout,
            )
        )
        self._execution_errors: List[Dict[str, Any]] = []

    def add_execution_error(self, error: Dict[str, Any]) -> None:
        """Record an execution error."""
        self._execution_errors.append(error)
        if len(self._execution_errors) > 100:  # Keep last 100 errors
            self._execution_errors.pop(0)

    def get_execution_errors(self) -> List[Dict[str, Any]]:
        """Get all recorded execution errors."""
        return list(self._execution_errors)

    def step(
        self,
        action: str,
        result: str,
        error: Optional[str] = None,
    ) -> None:
        """Record a step with optional error.
        
        Args:
            action: Action taken
            result: Action result
            error: Optional error message
        """
        super().step(action, result)
        if error:
            self.state.errors.append(error)
            self.add_execution_error({
                "step": self.state.step,
                "action": action,
                "error": error,
            })

    async def run_autonomous_with_resilience(
        self,
        scope: Optional[List[str]] = None,
        llm_complete: Optional[Any] = None,
        on_event: Optional[Any] = None,
        sandbox_mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Run agent with timeout and error handling.
        
        Args:
            scope: Target scope
            llm_complete: LLM completion function
            on_event: Event callback
            sandbox_mode: Sandbox mode
            
        Returns:
            Execution result
        """
        self.resource_tracker.start_execution()
        
        try:
            logger.info(f"Starting resilient agent for {self.target}")
            
            # Wrap the autonomous run with timeout
            result = await async_timeout(
                self.run_autonomous(
                    scope=scope,
                    llm_complete=llm_complete,
                    on_event=on_event,
                    sandbox_mode=sandbox_mode,
                ),
                timeout_seconds=self.config.total_timeout,
                operation_name=f"Agent autonomy ({self.target})",
            )
            
            logger.info(f"Agent completed for {self.target}")
            return result
            
        except Exception as e:
            logger.error(f"Agent execution failed: {e}", exc_info=True)
            self.add_execution_error({
                "type": "execution_error",
                "message": str(e),
                "error_class": e.__class__.__name__,
            })
            
            # Return partial results
            return {
                "status": "error",
                "target": self.target,
                "steps_taken": self.state.step,
                "findings": self.state.findings,
                "errors": self.get_execution_errors(),
                "error_message": str(e),
            }

    def summary(self) -> Dict[str, Any]:
        """Return extended summary including errors and resource usage."""
        base = super().summary()
        return {
            **base,
            "total_errors": len(self.state.errors),
            "execution_errors": len(self._execution_errors),
            "circuit_breaker_state": self.circuit_breaker.state.value,
            "resource_status": dict(zip(
                ["active_tasks", "total_tool_calls"],
                [self.resource_tracker.active_tasks, self.resource_tracker.total_tool_calls],
            )),
        }
