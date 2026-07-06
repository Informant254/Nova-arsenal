"""
Unit tests for async utilities (timeouts, circuit breaker, retry logic).
"""

import asyncio
import sys
from pathlib import Path

import pytest

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from nova_arsenal.async_utils import (
    CircuitBreaker,
    CircuitBreakerConfig,
    CircuitBreakerState,
    async_timeout,
    AsyncTimeoutError,
    async_retry,
    RetryConfig,
    ResourceTracker,
    ResourceLimits,
)


class TestCircuitBreaker:
    """Test circuit breaker pattern."""

    @pytest.mark.asyncio
    async def test_circuit_breaker_closed_on_success(self):
        """Test circuit breaker remains CLOSED on success."""
        breaker = CircuitBreaker()
        assert breaker.state == CircuitBreakerState.CLOSED

        async def success_func():
            return "ok"

        result = await breaker.call(success_func)
        assert result == "ok"
        assert breaker.state == CircuitBreakerState.CLOSED

    @pytest.mark.asyncio
    async def test_circuit_breaker_opens_on_failures(self):
        """Test circuit breaker OPENS after threshold failures."""
        config = CircuitBreakerConfig(failure_threshold=2)
        breaker = CircuitBreaker(config)

        async def failing_func():
            raise ValueError("Test error")

        # First failure
        with pytest.raises(ValueError):
            await breaker.call(failing_func)
        assert breaker.state == CircuitBreakerState.CLOSED

        # Second failure -> should open
        with pytest.raises(ValueError):
            await breaker.call(failing_func)
        assert breaker.state == CircuitBreakerState.OPEN

    @pytest.mark.asyncio
    async def test_circuit_breaker_rejects_when_open(self):
        """Test circuit breaker rejects calls when OPEN."""
        config = CircuitBreakerConfig(failure_threshold=1)
        breaker = CircuitBreaker(config)

        async def failing_func():
            raise ValueError("Test error")

        # Open the breaker
        with pytest.raises(ValueError):
            await breaker.call(failing_func)
        assert breaker.state == CircuitBreakerState.OPEN

        # Further calls should be rejected immediately
        with pytest.raises(RuntimeError, match="Circuit breaker is OPEN"):
            await breaker.call(failing_func)

    @pytest.mark.asyncio
    async def test_circuit_breaker_half_open_recovery(self):
        """Test circuit breaker attempts recovery in HALF_OPEN state."""
        config = CircuitBreakerConfig(
            failure_threshold=1,
            recovery_timeout=0.1,
            success_threshold=1,
        )
        breaker = CircuitBreaker(config)

        async def failing_func():
            raise ValueError("Test error")

        # Open the breaker
        with pytest.raises(ValueError):
            await breaker.call(failing_func)
        assert breaker.state == CircuitBreakerState.OPEN

        # Wait for recovery timeout
        await asyncio.sleep(0.2)

        # Next call should transition to HALF_OPEN
        with pytest.raises(ValueError):
            await breaker.call(failing_func)
        assert breaker.state == CircuitBreakerState.HALF_OPEN or breaker.state == CircuitBreakerState.OPEN


class TestAsyncTimeout:
    """Test async timeout functionality."""

    @pytest.mark.asyncio
    async def test_timeout_allows_fast_operation(self):
        """Test timeout allows operations faster than limit."""
        async def fast_op():
            await asyncio.sleep(0.01)
            return "ok"

        result = await async_timeout(fast_op(), timeout_seconds=1.0)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_timeout_raises_on_slow_operation(self):
        """Test timeout raises when operation exceeds limit."""
        async def slow_op():
            await asyncio.sleep(1.0)
            return "should not reach"

        with pytest.raises(AsyncTimeoutError):
            await async_timeout(slow_op(), timeout_seconds=0.1)

    @pytest.mark.asyncio
    async def test_timeout_includes_operation_name(self):
        """Test timeout error message includes operation name."""
        async def slow_op():
            await asyncio.sleep(1.0)

        with pytest.raises(AsyncTimeoutError, match="test_operation"):
            await async_timeout(
                slow_op(),
                timeout_seconds=0.05,
                operation_name="test_operation",
            )


class TestAsyncRetry:
    """Test retry logic with backoff."""

    @pytest.mark.asyncio
    async def test_retry_succeeds_immediately(self):
        """Test retry returns on first success."""
        async def success_func():
            return "ok"

        result = await async_retry(success_func)
        assert result == "ok"

    @pytest.mark.asyncio
    async def test_retry_retries_on_failure(self):
        """Test retry attempts multiple times on failure."""
        call_count = 0

        async def failing_then_success():
            nonlocal call_count
            call_count += 1
            if call_count < 2:
                raise ValueError("Temporary error")
            return "ok"

        config = RetryConfig(max_retries=3, initial_delay=0.01)
        result = await async_retry(failing_then_success, config=config)
        assert result == "ok"
        assert call_count == 2

    @pytest.mark.asyncio
    async def test_retry_exhausts_attempts(self):
        """Test retry raises after exhausting all attempts."""
        async def always_fail():
            raise ValueError("Always fails")

        config = RetryConfig(max_retries=2, initial_delay=0.01)
        with pytest.raises(ValueError, match="Always fails"):
            await async_retry(always_fail, config=config)

    @pytest.mark.asyncio
    async def test_retry_with_args_kwargs(self):
        """Test retry passes through args and kwargs."""
        async def func_with_args(a, b, c=None):
            return f"{a}-{b}-{c}"

        result = await async_retry(func_with_args, None, "op", 1, 2, c=3)
        assert result == "1-2-3"


class TestResourceTracker:
    """Test resource limit tracking."""

    def test_resource_tracker_initialization(self):
        """Test resource tracker initializes correctly."""
        tracker = ResourceTracker()
        assert tracker.active_tasks == 0
        assert tracker.total_tool_calls == 0

    def test_resource_tracker_within_limits(self):
        """Test tracker reports within limits initially."""
        tracker = ResourceTracker()
        tracker.start_execution()
        is_ok, msg = tracker.check_limits()
        assert is_ok is True

    def test_resource_tracker_task_concurrency_limit(self):
        """Test tracker enforces concurrent task limit."""
        limits = ResourceLimits(max_concurrent_tasks=2)
        tracker = ResourceTracker(limits)
        tracker.start_execution()

        tracker.record_task_started()
        is_ok, msg = tracker.check_limits()
        assert is_ok is True

        tracker.record_task_started()
        is_ok, msg = tracker.check_limits()
        assert is_ok is True

        tracker.record_task_started()
        is_ok, msg = tracker.check_limits()
        assert is_ok is False
        assert "concurrent tasks" in msg

    def test_resource_tracker_tool_call_budget(self):
        """Test tracker enforces tool call budget."""
        limits = ResourceLimits(max_tool_calls_per_step=3)
        tracker = ResourceTracker(limits)
        tracker.start_execution()

        tracker.record_tool_call()
        tracker.record_tool_call()
        tracker.record_tool_call()
        is_ok, msg = tracker.check_limits()
        assert is_ok is True

        tracker.record_tool_call()
        is_ok, msg = tracker.check_limits()
        assert is_ok is False
        assert "budget" in msg.lower()

    def test_resource_tracker_execution_timeout(self):
        """Test tracker enforces execution timeout."""
        import time
        limits = ResourceLimits(max_execution_time_seconds=0.05)
        tracker = ResourceTracker(limits)
        tracker.start_execution()

        is_ok, msg = tracker.check_limits()
        assert is_ok is True

        # Wait for timeout
        time.sleep(0.1)
        is_ok, msg = tracker.check_limits()
        assert is_ok is False
        assert "exceeded" in msg.lower()
