"""Tests for network health rate-limit guard behavior."""

from __future__ import annotations

import time
from typing import Any

import pytest

from meraki_dashboard_exporter.collectors.network_health_collectors.base import (
    BaseNetworkHealthCollector,
)


class _DummyParent:
    """Minimal parent stub for BaseNetworkHealthCollector tests."""

    def __init__(self) -> None:
        self.api: Any = object()
        self.settings: Any = object()


class _DummyCollector(BaseNetworkHealthCollector):
    pass


class TestNetworkHealthRateLimitGuard:
    async def test_activates_cooldown_and_skips_immediate_retry(self) -> None:
        """A 429 should open cooldown and suppress immediate retries."""
        collector = _DummyCollector(_DummyParent())
        org_id = "594159"
        network_id = "N_123"
        endpoint = "getNetworkBluetoothClients"
        call_count = 0

        async def rate_limited_call() -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            raise RuntimeError("429 Too Many Requests")

        with pytest.raises(RuntimeError):
            await collector._execute_with_rate_limit_guard(
                endpoint=endpoint,
                org_id=org_id,
                network_id=network_id,
                api_call=rate_limited_call,
            )

        assert call_count == 1

        async def success_call() -> dict[str, Any]:
            nonlocal call_count
            call_count += 1
            return {"ok": True}

        skipped = await collector._execute_with_rate_limit_guard(
            endpoint=endpoint,
            org_id=org_id,
            network_id=network_id,
            api_call=success_call,
        )
        assert skipped is None
        assert call_count == 1

    async def test_runs_again_after_cooldown_window_passes(self) -> None:
        """Calls should resume when cooldown windows have elapsed."""
        collector = _DummyCollector(_DummyParent())
        org_id = "594159"
        network_id = "N_456"
        endpoint = "getNetworkWirelessDataRateHistory"

        # Simulate stale cooldown state.
        collector.parent._nh_endpoint_cooldown_until[(org_id, endpoint)] = time.monotonic() - 1
        collector.parent._nh_network_cooldown_until[(org_id, network_id, endpoint)] = (
            time.monotonic() - 1
        )

        async def success_call() -> dict[str, Any]:
            return {"ok": True}

        result = await collector._execute_with_rate_limit_guard(
            endpoint=endpoint,
            org_id=org_id,
            network_id=network_id,
            api_call=success_call,
        )
        assert result == {"ok": True}

