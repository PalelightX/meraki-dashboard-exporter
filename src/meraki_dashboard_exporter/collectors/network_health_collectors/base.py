"""Base network health collector with common functionality."""

from __future__ import annotations

import asyncio
import random
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any

from ...core.logging import get_logger

if TYPE_CHECKING:
    from meraki import DashboardAPI

    from ...core.config import Settings
    from ..network_health import NetworkHealthCollector

logger = get_logger(__name__)


class BaseNetworkHealthCollector:
    """Base class for network health sub-collectors."""

    _RATE_LIMIT_PATTERNS: tuple[str, ...] = (
        "429",
        "too many requests",
        "rate limit",
        "throttled",
    )
    _COOLDOWN_BASE_SECONDS = 60.0
    _COOLDOWN_MAX_SECONDS = 1800.0
    _COOLDOWN_JITTER_RATIO = 0.2

    def __init__(self, parent: NetworkHealthCollector) -> None:
        """Initialize base network health collector.

        Parameters
        ----------
        parent : NetworkHealthCollector
            Parent NetworkHealthCollector instance that has metrics defined.

        """
        self.parent = parent
        self.api: DashboardAPI = parent.api
        self.settings: Settings = parent.settings
        self._init_rate_limit_state()

    def _init_rate_limit_state(self) -> None:
        """Initialize shared rate-limit state on parent collector."""
        if not hasattr(self.parent, "_nh_rl_lock"):
            self.parent._nh_rl_lock = asyncio.Lock()
        if not hasattr(self.parent, "_nh_endpoint_semaphores"):
            self.parent._nh_endpoint_semaphores = {}
        if not hasattr(self.parent, "_nh_endpoint_cooldown_until"):
            self.parent._nh_endpoint_cooldown_until = {}
        if not hasattr(self.parent, "_nh_network_cooldown_until"):
            self.parent._nh_network_cooldown_until = {}
        if not hasattr(self.parent, "_nh_rate_limit_hits"):
            self.parent._nh_rate_limit_hits = {}

    async def _get_endpoint_semaphore(self, endpoint: str) -> asyncio.Semaphore:
        """Get or create endpoint-specific semaphore (serial execution)."""
        async with self.parent._nh_rl_lock:
            semaphore = self.parent._nh_endpoint_semaphores.get(endpoint)
            if semaphore is None:
                semaphore = asyncio.Semaphore(1)
                self.parent._nh_endpoint_semaphores[endpoint] = semaphore
            return semaphore

    @staticmethod
    def _is_rate_limit_error(exc: Exception) -> bool:
        error = str(exc).lower()
        return any(pattern in error for pattern in BaseNetworkHealthCollector._RATE_LIMIT_PATTERNS)

    def _compute_cooldown_seconds(self, hit_count: int) -> float:
        """Compute exponential cooldown with jitter."""
        exponent = max(0, hit_count - 1)
        cooldown = min(
            self._COOLDOWN_MAX_SECONDS,
            self._COOLDOWN_BASE_SECONDS * float(2**exponent),
        )
        jitter = random.uniform(0.0, cooldown * self._COOLDOWN_JITTER_RATIO)
        return cooldown + jitter

    async def _is_in_cooldown(self, endpoint: str, org_id: str, network_id: str) -> tuple[bool, float]:
        """Check whether endpoint or network call is in cooldown window."""
        now = time.monotonic()
        async with self.parent._nh_rl_lock:
            endpoint_until = self.parent._nh_endpoint_cooldown_until.get((org_id, endpoint), 0.0)
            network_until = self.parent._nh_network_cooldown_until.get(
                (org_id, network_id, endpoint), 0.0
            )
        cooldown_until = max(endpoint_until, network_until)
        if cooldown_until <= now:
            return False, 0.0
        return True, cooldown_until - now

    async def _record_rate_limit(
        self,
        endpoint: str,
        org_id: str,
        network_id: str,
    ) -> float:
        """Record a 429 event and update cooldown windows."""
        now = time.monotonic()
        async with self.parent._nh_rl_lock:
            key = (org_id, endpoint)
            hit_count = int(self.parent._nh_rate_limit_hits.get(key, 0)) + 1
            self.parent._nh_rate_limit_hits[key] = min(hit_count, 8)
            cooldown = self._compute_cooldown_seconds(hit_count)
            until = now + cooldown
            self.parent._nh_endpoint_cooldown_until[key] = until
            self.parent._nh_network_cooldown_until[(org_id, network_id, endpoint)] = until
        return cooldown

    async def _record_success(self, endpoint: str, org_id: str) -> None:
        """Decay rate-limit streak on successful call."""
        async with self.parent._nh_rl_lock:
            key = (org_id, endpoint)
            prev = int(self.parent._nh_rate_limit_hits.get(key, 0))
            if prev > 1:
                self.parent._nh_rate_limit_hits[key] = prev - 1
            elif key in self.parent._nh_rate_limit_hits:
                del self.parent._nh_rate_limit_hits[key]

    async def _execute_with_rate_limit_guard(
        self,
        endpoint: str,
        org_id: str,
        network_id: str,
        api_call: Callable[[], Awaitable[Any]],
    ) -> Any | None:
        """Execute a guarded API call with cooldown and endpoint serialization."""
        in_cooldown, wait_seconds = await self._is_in_cooldown(endpoint, org_id, network_id)
        if in_cooldown:
            logger.debug(
                "Skipping API call due to network health cooldown",
                endpoint=endpoint,
                org_id=org_id,
                network_id=network_id,
                wait_seconds=round(wait_seconds, 2),
            )
            return None

        endpoint_semaphore = await self._get_endpoint_semaphore(endpoint)
        async with endpoint_semaphore:
            in_cooldown, wait_seconds = await self._is_in_cooldown(endpoint, org_id, network_id)
            if in_cooldown:
                logger.debug(
                    "Skipping API call due to network health cooldown",
                    endpoint=endpoint,
                    org_id=org_id,
                    network_id=network_id,
                    wait_seconds=round(wait_seconds, 2),
                )
                return None

            try:
                result = await api_call()
                await self._record_success(endpoint, org_id)
                return result
            except Exception as exc:
                if self._is_rate_limit_error(exc):
                    cooldown = await self._record_rate_limit(endpoint, org_id, network_id)
                    logger.warning(
                        "Activated network health endpoint cooldown",
                        endpoint=endpoint,
                        org_id=org_id,
                        network_id=network_id,
                        cooldown_seconds=round(cooldown, 2),
                    )
                raise

    def _track_api_call(self, method_name: str) -> None:
        """Track API call in parent collector.

        Parameters
        ----------
        method_name : str
            Name of the API method being called.

        """
        if hasattr(self.parent, "_track_api_call"):
            self.parent._track_api_call(method_name)

    def _set_metric_value(
        self, metric_name: str, labels: dict[str, str], value: float | None
    ) -> None:
        """Safely set a metric value with validation.

        Parameters
        ----------
        metric_name : str
            Name of the metric attribute.
        labels : dict[str, str]
            Labels to apply to the metric.
        value : float | None
            Value to set. If None, the metric will not be updated.

        """
        if hasattr(self.parent, "_set_metric_value"):
            self.parent._set_metric_value(metric_name, labels, value)
