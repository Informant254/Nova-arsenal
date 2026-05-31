#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  🔁 NOVA RETRY v1.0 — Retry, Backoff & Circuit Breaker                     ║
║                                                                              ║
║  Production-grade retry infrastructure for all Nova network calls.          ║
║                                                                              ║
║  Features:                                                                   ║
║    • Exponential backoff with configurable jitter                           ║
║    • Per-exception-type retry policies                                       ║
║    • Circuit breaker (per service / per host)                               ║
║    • Timeout enforcement                                                     ║
║    • Retry budget (total time limit across all attempts)                    ║
║    • @retry decorator for easy use                                           ║
╚══════════════════════════════════════════════════════════════════════════════╝

Usage:
    from nova_retry import retry, RetryPolicy, CircuitBreaker

    @retry(max_attempts=5, base_delay=1.0, max_delay=30.0)
    def fetch_url(url):
        ...

    # Or explicit policy
    policy = RetryPolicy(max_attempts=3, base_delay=2.0, jitter=True)
    result = policy.execute(my_function, arg1, arg2)

    # Circuit breaker
    cb = CircuitBreaker("nuclei", threshold=3, reset_after=60)
    if cb.is_open():
        print("nuclei is down, skipping")
"""

import random
import time
import traceback
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple, Type


# ── Exception categories ───────────────────────────────────────────────────────

# These are always retried
RETRIABLE_EXCEPTIONS: Tuple[Type[Exception], ...] = (
    ConnectionError,
    TimeoutError,
    OSError,
)

# These are never retried
TERMINAL_EXCEPTIONS: Tuple[Type[Exception], ...] = (
    KeyboardInterrupt,
    SystemExit,
    MemoryError,
)


# ── Retry policy ───────────────────────────────────────────────────────────────

@dataclass
class RetryPolicy:
    max_attempts:  int   = 3
    base_delay:    float = 1.0       # seconds before first retry
    max_delay:     float = 60.0      # cap on per-retry delay
    multiplier:    float = 2.0       # exponential base
    jitter:        bool  = True      # add random jitter to avoid thundering herd
    budget_secs:   float = 300.0     # total wall-clock budget for all attempts
    reraise:       bool  = True      # re-raise on final failure
    on_retry:      Optional[Callable[[int, Exception, float], None]] = field(
                       default=None, repr=False)  # callback(attempt, exc, delay)

    def _delay(self, attempt: int) -> float:
        delay = min(self.base_delay * (self.multiplier ** attempt), self.max_delay)
        if self.jitter:
            delay *= (0.5 + random.random())   # ±50%
        return delay

    def execute(self, fn: Callable, *args, **kwargs) -> Any:
        t_start   = time.monotonic()
        last_exc: Optional[Exception] = None

        for attempt in range(self.max_attempts):
            # Budget check
            elapsed = time.monotonic() - t_start
            if elapsed > self.budget_secs:
                raise TimeoutError(
                    f"Retry budget of {self.budget_secs}s exhausted after {attempt} attempts.")

            try:
                return fn(*args, **kwargs)
            except TERMINAL_EXCEPTIONS:
                raise
            except Exception as exc:
                last_exc = exc
                if attempt == self.max_attempts - 1:
                    break  # final attempt failed

                delay = self._delay(attempt)
                # Ensure we don't exceed budget
                remaining = self.budget_secs - (time.monotonic() - t_start)
                delay     = min(delay, max(0, remaining - 0.1))

                if self.on_retry:
                    try:
                        self.on_retry(attempt + 1, exc, delay)
                    except Exception:
                        pass
                else:
                    print(f"  ↩️  Attempt {attempt + 1}/{self.max_attempts} failed: "
                          f"{type(exc).__name__}: {exc}. Retrying in {delay:.1f}s…")

                if delay > 0:
                    time.sleep(delay)

        if self.reraise and last_exc is not None:
            raise last_exc
        return None


# ── Decorator ──────────────────────────────────────────────────────────────────

def retry(
    max_attempts: int   = 3,
    base_delay:   float = 1.0,
    max_delay:    float = 60.0,
    multiplier:   float = 2.0,
    jitter:       bool  = True,
    budget_secs:  float = 300.0,
    on_retry:     Optional[Callable] = None,
) -> Callable:
    """
    Decorator factory. Wraps a function with retry logic.

    @retry(max_attempts=5, base_delay=2.0)
    def call_api(url):
        ...
    """
    policy = RetryPolicy(max_attempts=max_attempts, base_delay=base_delay,
                         max_delay=max_delay, multiplier=multiplier, jitter=jitter,
                         budget_secs=budget_secs, on_retry=on_retry)

    def decorator(fn: Callable) -> Callable:
        def wrapper(*args, **kwargs):
            return policy.execute(fn, *args, **kwargs)
        wrapper.__name__ = fn.__name__
        wrapper.__doc__  = fn.__doc__
        wrapper._retry_policy = policy
        return wrapper
    return decorator


# ── Circuit breaker ────────────────────────────────────────────────────────────

class CircuitBreaker:
    """
    Per-service circuit breaker.
    States: CLOSED (normal) → OPEN (failing) → HALF_OPEN (testing recovery).
    """

    CLOSED    = "CLOSED"
    OPEN      = "OPEN"
    HALF_OPEN = "HALF_OPEN"

    def __init__(self, name: str = "default", threshold: int = 3,
                 reset_after: float = 60.0, half_open_calls: int = 1):
        self.name            = name
        self.threshold       = threshold
        self.reset_after     = reset_after
        self.half_open_calls = half_open_calls

        self._failures    = 0
        self._state       = self.CLOSED
        self._opened_at:  Optional[float] = None
        self._half_probes = 0

    @property
    def state(self) -> str:
        if self._state == self.OPEN:
            if time.monotonic() - (self._opened_at or 0) > self.reset_after:
                self._state       = self.HALF_OPEN
                self._half_probes = 0
        return self._state

    def is_open(self) -> bool:
        return self.state == self.OPEN

    def allow_request(self) -> bool:
        s = self.state
        if s == self.CLOSED:
            return True
        if s == self.HALF_OPEN and self._half_probes < self.half_open_calls:
            self._half_probes += 1
            return True
        return False

    def record_success(self):
        self._failures = 0
        self._state    = self.CLOSED

    def record_failure(self):
        self._failures += 1
        if self._failures >= self.threshold:
            self._state     = self.OPEN
            self._opened_at = time.monotonic()
            print(f"  🔴 Circuit breaker '{self.name}' OPENED after "
                  f"{self._failures} failures.")

    def __call__(self, fn: Callable) -> Callable:
        """Use as decorator: @cb"""
        def wrapper(*args, **kwargs):
            if not self.allow_request():
                raise RuntimeError(f"Circuit breaker '{self.name}' is OPEN. "
                                   f"Skipping call to {fn.__name__}.")
            try:
                result = fn(*args, **kwargs)
                self.record_success()
                return result
            except Exception as exc:
                self.record_failure()
                raise
        wrapper.__name__ = fn.__name__
        return wrapper

    def info(self) -> Dict:
        return {
            "name":      self.name,
            "state":     self.state,
            "failures":  self._failures,
            "threshold": self.threshold,
        }


# ── Composite: retry + circuit breaker ────────────────────────────────────────

class ResilientCaller:
    """
    Combines retry logic and circuit breaker for maximum resilience.
    Use for all external tool / API calls.
    """

    def __init__(self, name: str, policy: Optional[RetryPolicy] = None,
                 cb_threshold: int = 3, cb_reset: float = 60.0):
        self._policy = policy or RetryPolicy()
        self._cb     = CircuitBreaker(name=name, threshold=cb_threshold, reset_after=cb_reset)

    def call(self, fn: Callable, *args, **kwargs) -> Any:
        if not self._cb.allow_request():
            raise RuntimeError(f"Circuit breaker open for '{self._cb.name}'")
        try:
            result = self._policy.execute(fn, *args, **kwargs)
            self._cb.record_success()
            return result
        except Exception:
            self._cb.record_failure()
            raise

    def info(self) -> Dict:
        return {"circuit_breaker": self._cb.info()}


# ── Global registry ────────────────────────────────────────────────────────────

_callers: Dict[str, ResilientCaller] = {}

def get_caller(name: str, **kwargs) -> ResilientCaller:
    if name not in _callers:
        _callers[name] = ResilientCaller(name=name, **kwargs)
    return _callers[name]


# ── CLI test ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys

    attempt_counter = [0]

    @retry(max_attempts=4, base_delay=0.2, jitter=False)
    def flaky_function():
        attempt_counter[0] += 1
        if attempt_counter[0] < 3:
            raise ConnectionError(f"Simulated failure #{attempt_counter[0]}")
        return f"Success on attempt {attempt_counter[0]}"

    print("Testing retry decorator:")
    result = flaky_function()
    print(f"  Result: {result}\n")

    print("Testing circuit breaker:")
    cb = CircuitBreaker("test_service", threshold=2, reset_after=5.0)
    for i in range(5):
        print(f"  State: {cb.state}, allow: {cb.allow_request()}")
        cb.record_failure()

    time.sleep(5.5)
    print(f"  After reset: state = {cb.state}")
    cb.record_success()
    print(f"  After success: state = {cb.state}")
