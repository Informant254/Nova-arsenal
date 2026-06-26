"""
Nova-Arsenal Rate Limiting Middleware

In-memory token-bucket rate limiter for API endpoints.
Configurable per-route and global limits.
"""

import asyncio
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response


@dataclass
class TokenBucket:
    capacity: int
    refill_rate: float  # tokens per second
    tokens: float = field(init=False)
    last_refill: float = field(init=False)

    def __post_init__(self):
        self.tokens = float(self.capacity)
        self.last_refill = time.monotonic()

    def consume(self, now: float = None) -> bool:
        if now is None:
            now = time.monotonic()
        elapsed = now - self.last_refill
        self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

    def retry_after(self) -> float:
        if self.tokens >= 1.0:
            return 0.0
        return max(0.0, (1.0 - self.tokens) / self.refill_rate)


class RateLimitConfig:
    def __init__(
        self,
        global_per_second: float = 50.0,
        global_burst: int = 100,
        auth_per_second: float = 5.0,
        auth_burst: int = 10,
        api_key_per_second: float = 20.0,
        api_key_burst: int = 40,
    ):
        self.global_per_second = global_per_second
        self.global_burst = global_burst
        self.auth_per_second = auth_per_second
        self.auth_burst = auth_burst
        self.api_key_per_second = api_key_per_second
        self.api_key_burst = api_key_burst


class RateLimitMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, config: Optional[RateLimitConfig] = None):
        super().__init__(app)
        self.config = config or RateLimitConfig()
        self._buckets: dict[str, TokenBucket] = {}
        self._lock = asyncio.Lock()

    def _get_bucket(self, key: str, capacity: int, refill_rate: float) -> TokenBucket:
        if key not in self._buckets:
            self._buckets[key] = TokenBucket(capacity=capacity, refill_rate=refill_rate)
        return self._buckets[key]

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        now = time.monotonic()
        client_ip = request.client.host if request.client else "unknown"

        # Global rate limit per IP
        global_key = f"global:{client_ip}"
        global_bucket = self._get_bucket(
            global_key, self.config.global_burst, self.config.global_per_second
        )
        if not global_bucket.consume(now):
            retry = global_bucket.retry_after()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded. Retry in {retry:.1f}s",
                headers={"Retry-After": str(int(retry) + 1)},
            )

        # Stricter limit for auth endpoints
        path = request.url.path
        if path.startswith("/api/auth/"):
            auth_key = f"auth:{client_ip}"
            auth_bucket = self._get_bucket(
                auth_key, self.config.auth_burst, self.config.auth_per_second
            )
            if not auth_bucket.consume(now):
                retry = auth_bucket.retry_after()
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Auth rate limit exceeded. Retry in {retry:.1f}s",
                    headers={"Retry-After": str(int(retry) + 1)},
                )

        response = await call_next(request)
        return response
