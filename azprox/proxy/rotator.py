"""
Rotator — endpoint selection strategies for the local proxy.

Manages the pool of active Azure Function endpoints and selects which
one to use for each outgoing request.
"""
from __future__ import annotations

import asyncio
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class EndpointStats:
    """Per-endpoint tracking."""

    url: str
    total_requests: int = 0
    total_errors: int = 0
    last_used: float = 0.0
    last_error: float = 0.0
    is_healthy: bool = True
    consecutive_errors: int = 0

    # Mark unhealthy after this many consecutive errors
    ERROR_THRESHOLD: int = 3
    # Re-check unhealthy endpoints after this many seconds
    RECOVERY_INTERVAL: float = 60.0


class EndpointRotator:
    """
    Manages endpoint selection with health tracking.

    Strategies:
    - round-robin: Cycle through endpoints sequentially
    - random: Pick a random endpoint per request

    Health tracking:
    - After ERROR_THRESHOLD consecutive errors, mark endpoint unhealthy
    - Unhealthy endpoints are skipped
    - Periodically re-try unhealthy endpoints (every RECOVERY_INTERVAL seconds)
    - If ALL endpoints are unhealthy, use them anyway (best-effort)
    """

    def __init__(
        self,
        endpoints: list[str],
        strategy: str = "round-robin",
        auth_key: str = "",
    ):
        self.strategy = strategy
        self.auth_key = auth_key
        self._stats: dict[str, EndpointStats] = {
            url: EndpointStats(url=url) for url in endpoints
        }
        self._index = 0
        self._lock = asyncio.Lock()

    @property
    def all_endpoints(self) -> list[str]:
        return list(self._stats.keys())

    @property
    def healthy_endpoints(self) -> list[str]:
        now = time.monotonic()
        healthy = []
        for url, stats in self._stats.items():
            if stats.is_healthy:
                healthy.append(url)
            elif (now - stats.last_error) > EndpointStats.RECOVERY_INTERVAL:
                # Give unhealthy endpoint another chance
                healthy.append(url)
        return healthy or self.all_endpoints  # fallback: use all if none healthy

    async def next(self) -> str:
        """Select the next endpoint based on strategy."""
        async with self._lock:
            pool = self.healthy_endpoints

            if self.strategy == "round-robin":
                endpoint = pool[self._index % len(pool)]
                self._index += 1
            elif self.strategy == "random":
                endpoint = random.choice(pool)
            else:
                endpoint = pool[0]

            self._stats[endpoint].total_requests += 1
            self._stats[endpoint].last_used = time.monotonic()
            return endpoint

    def report_success(self, endpoint: str) -> None:
        """Mark a successful request to an endpoint."""
        if endpoint in self._stats:
            stats = self._stats[endpoint]
            stats.consecutive_errors = 0
            stats.is_healthy = True

    def report_error(self, endpoint: str) -> None:
        """Mark a failed request to an endpoint."""
        if endpoint in self._stats:
            stats = self._stats[endpoint]
            stats.total_errors += 1
            stats.consecutive_errors += 1
            stats.last_error = time.monotonic()
            if stats.consecutive_errors >= EndpointStats.ERROR_THRESHOLD:
                stats.is_healthy = False

    def get_stats(self) -> dict[str, EndpointStats]:
        """Return stats for all endpoints."""
        return dict(self._stats)
