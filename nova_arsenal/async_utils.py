"""
Async utilities for Nova agent with timeout guards and error handling.

Provides safe async execution patterns with built-in timeouts,
circuit breakers, and retry budgets.
"""

import asyncio
import logging
from typing import Any, Callable, Optional, TypeVar, Coroutine, Dict
from dataclasses import dataclass
from enum import Enum


logger = logging.getLogger(__name__)

T = TypeVar("T")


class CircuitBreakerState(Enum):
    """Circuit breaker state machine."""
    CLOSED = "closed"        # Normal operation
    OPEN = "open"            # Failing, reject requests
    HALF_OPEN = "half_open"  # Testing recovery


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5  # Failures before opening
    recovery_timeout: float = 30.0  # Seconds before half-open
    success_threshold: int = 2  # Successes to close


class CircuitBreaker:
    """Circuit breaker for preventing cascading failures."""

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitBreakerState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[float] = None

    async def call(
        self,
        func: Callable[..., Coroutine[Any, Any, T]],
        *args: Any,
        **kwargs: Any,
    ) -> T:
        """Execute function with circuit breaker protection."""
        if self.state == CircuitBreakerState.OPEN:
            # Check if recovery timeout has passed
            import time
            if self.last_failure_time and time.time() - self.last_failure_time > self.config.recovery_timeout:
                self.state = CircuitBreakerState.HALF_OPEN
                self.success_count = 0
                logger.info("Circuit breaker entering HALF_OPEN state")
            else:
                raise RuntimeError("Circuit breaker is OPEN")

        try:
            result = await func(*args, **kwargs)
            self._on_success()
            return result
        except Exception as e:
            self._on_failure()
            raise

    def _on_success(self) -> None:
        """Handle successful call."""
        self.failure_count = 0
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.success_count += 1
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitBreakerState.CLOSED
                self.success_count = 0
                logger.info("Circuit breaker CLOSED")

    def _on_failure(self) -> None:
        """Handle failed call."""
        import time
        self.last_failure_time = time.time()
        self.failure_count += 1
        if self.failure_count >= self.config.failure_threshold:
            self.state = CircuitBreakerState.OPEN
            logger.warning(f"Circuit breaker OPEN after {self.failure_count} failures")
        if self.state == CircuitBreakerState.HALF_OPEN:
            self.state = CircuitBreakerState.OPEN
            logger.warning("Circuit breaker OPEN during recovery")


class AsyncTimeoutError(Exception):
    """Raised when an async operation exceeds timeout."""
    pass


async def async_timeout(
    coro: Coroutine[Any, Any, T],
    timeout_seconds: float,
    operation_name: str = "operation",
) -> T:
    """Execute coroutine with timeout guard.
    
    Args:
        coro: Coroutine to execute
        timeout_seconds: Maximum execution time
        operation_name: Name for logging
        
    Returns:
        Result of coroutine
        
    Raises:
        AsyncTimeoutError: If timeout exceeded
    """
    try:
        logger.debug(f"Starting {operation_name} with {timeout_seconds}s timeout")
        result = await asyncio.wait_for(coro, timeout=timeout_seconds)
        logger.debug(f"Completed {operation_name}")
        return result
    except asyncio.TimeoutError:
        logger.error(f"{operation_name} timed out after {timeout_seconds}s")
        raise AsyncTimeoutError(
            f"{operation_name} exceeded {timeout_seconds}s timeout"
        ) from None


@dataclass
class RetryConfig:
    """Retry policy configuration."""
    max_retries: int = 3
    backoff_base: float = 2.0  # Exponential backoff multiplier
    initial_delay: float = 1.0  # First retry delay in seconds
    max_delay: float = 30.0  # Max delay between retries


async def async_retry(
    func: Callable[..., Coroutine[Any, Any, T]],
    config: Optional[RetryConfig] = None,
    operation_name: str = "operation",
    *args: Any,
    **kwargs: Any,
) -> T:
    """Execute async function with retry logic.
    
    Args:
        func: Async function to execute
        config: Retry configuration
        operation_name: Name for logging
        *args: Positional arguments for func
        **kwargs: Keyword arguments for func
        
    Returns:
        Result of function
        
    Raises:
        Last exception if all retries exhausted
    """
    config = config or RetryConfig()
    last_exception = None

    for attempt in range(config.max_retries + 1):
        try:
            logger.debug(f"Attempt {attempt + 1}/{config.max_retries + 1} for {operation_name}")
            return await func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < config.max_retries:
                delay = min(
                    config.initial_delay * (config.backoff_base ** attempt),
                    config.max_delay,
                )
                logger.warning(
                    f"{operation_name} failed (attempt {attempt + 1}), retrying in {delay:.1f}s: {e}"
                )
                await asyncio.sleep(delay)
            else:
                logger.error(f"{operation_name} failed after {config.max_retries + 1} attempts")

    raise last_exception


@dataclass
class ResourceLimits:
    """Resource limits for agent execution."""
    max_concurrent_tasks: int = 5
    max_memory_mb: int = 512
    max_execution_time_seconds: float = 600.0
    max_tool_calls_per_step: int = 10


class ResourceTracker:
    """Track resource usage during agent execution."""

    def __init__(self, limits: Optional[ResourceLimits] = None):
        self.limits = limits or ResourceLimits()
        self.active_tasks = 0
        self.total_tool_calls = 0
        self.start_time: Optional[float] = None

    def start_execution(self) -> None:
        """Mark execution start."""
        import time
        self.start_time = time.time()
        self.total_tool_calls = 0
        self.active_tasks = 0

    def check_limits(self) -> tuple:
        """Check if any resource limits exceeded.
        
        Returns:
            (is_within_limits, message)
        """
        if self.active_tasks >= self.limits.max_concurrent_tasks:
            return False, f"Max concurrent tasks ({self.limits.max_concurrent_tasks}) reached"

        if self.total_tool_calls > self.limits.max_tool_calls_per_step:
            return False, f"Tool call budget exceeded"

        if self.start_time:
            import time
            elapsed = time.time() - self.start_time
            if elapsed > self.limits.max_execution_time_seconds:
                return False, f"Execution time exceeded ({elapsed:.1f}s > {self.limits.max_execution_time_seconds}s)"

        return True, "Within limits"

    def record_tool_call(self) -> None:
        """Record a tool invocation."""
        self.total_tool_calls += 1

    def record_task_started(self) -> None:
        """Record task start."""
        self.active_tasks += 1

    def record_task_completed(self) -> None:
        """Record task completion."""
        self.active_tasks = max(0, self.active_tasks - 1)
