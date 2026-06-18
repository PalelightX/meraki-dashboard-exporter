"""Tests for metrics payload diagnostics."""

from __future__ import annotations

from pydantic import SecretStr

from meraki_dashboard_exporter.app import ExporterApp
from meraki_dashboard_exporter.core.config import Settings
from meraki_dashboard_exporter.core.config_models import MerakiSettings


def _settings() -> Settings:
    return Settings(
        meraki=MerakiSettings(
            api_key=SecretStr("test_api_key_at_least_30_characters_long"),
            org_id="123456",
        )
    )


def test_summarize_metrics_payload_distinguishes_prefixes_and_representative_metrics() -> None:
    """Metrics diagnostics should reflect the actual exposed payload."""
    exporter = ExporterApp(_settings())
    payload = b"""
# HELP meraki_device_up Device online status
# TYPE meraki_device_up gauge
meraki_device_up{serial="Q2XX"} 1
# HELP meraki_exporter_collector_success_timestamp_seconds Collector success
# TYPE meraki_exporter_collector_success_timestamp_seconds gauge
meraki_exporter_collector_success_timestamp_seconds{collector="DeviceCollector"} 123
# HELP meraki_webhook_events_processed_total Webhook events
# TYPE meraki_webhook_events_processed_total counter
meraki_webhook_events_processed_total{alert_type="foo"} 5
"""

    summary = exporter._summarize_metrics_payload(payload)

    assert summary["payload_bytes"] == len(payload)
    assert summary["metric_family_count"] == 3
    assert summary["sample_count"] == 3
    assert summary["series_by_prefix"] == {
        "meraki": 1,
        "meraki_exporter": 1,
        "meraki_webhook": 1,
    }
    assert summary["series_with_collector_label_by_collector"] == {
        "DeviceCollector": 1,
    }
    assert summary["representative_metric_series_counts"]["meraki_device_up"] == 1
    assert summary["representative_metric_series_counts"][
        "meraki_exporter_collector_success_timestamp_seconds"
    ] == 1
    assert summary["representative_metric_series_counts"][
        "meraki_webhook_events_processed_total"
    ] == 1
    assert summary["representative_metrics_present"]["meraki_device_up"] is True
    assert summary["representative_metrics_present"]["meraki_client_status"] is False


def test_metric_expiration_stats_include_metric_names_and_last_cleanup_summary() -> None:
    """Expiration diagnostics should expose tracked metric names and cleanup details."""
    exporter = ExporterApp(_settings())
    manager = exporter.expiration_manager

    manager.track_metric_update(
        collector_name="DeviceCollector",
        metric_name="meraki_device_up",
        label_values={"org_id": "123", "serial": "Q2XX"},
    )
    manager.track_metric_update(
        collector_name="DeviceCollector",
        metric_name="meraki_mr_packet_loss_total_percent",
        label_values={"org_id": "123", "serial": "Q2YY"},
    )

    stats = manager.get_stats()

    assert stats["total_tracked"] == 2
    assert stats["by_collector"]["DeviceCollector"] == 2
    assert stats["tracked_metric_names_by_collector"]["DeviceCollector"] == {
        "meraki_device_up": 1,
        "meraki_mr_packet_loss_total_percent": 1,
    }
    assert stats["last_cleanup_summary"]["total_expired"] == 0
    assert stats["last_cleanup_summary"]["sample_expired_metrics"] == []
