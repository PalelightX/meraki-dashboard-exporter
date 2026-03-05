"""Tests for webhook receiver functionality (Phase 4.2)."""

from __future__ import annotations

from datetime import UTC, datetime

import pytest
from fastapi.testclient import TestClient
from pydantic import SecretStr

from meraki_dashboard_exporter.app import ExporterApp
from meraki_dashboard_exporter.core.config import Settings
from meraki_dashboard_exporter.core.config_models import MerakiSettings, WebhookSettings
from meraki_dashboard_exporter.core.discovery import DiscoveryService


@pytest.fixture
def webhook_enabled_settings() -> Settings:
    """Create settings with webhooks enabled."""
    return Settings(
        meraki=MerakiSettings(
            api_key=SecretStr("test_api_key_at_least_30_characters_long"),
            org_id="123456",
        ),
        webhooks=WebhookSettings(
            enabled=True,
            shared_secret=SecretStr("test_secret"),
            require_secret=True,
        ),
    )


@pytest.fixture
def webhook_disabled_settings() -> Settings:
    """Create settings with webhooks disabled."""
    return Settings(
        meraki=MerakiSettings(
            api_key=SecretStr("test_api_key_at_least_30_characters_long"),
            org_id="123456",
        ),
        webhooks=WebhookSettings(
            enabled=False,
        ),
    )

@pytest.fixture
def webhook_only_settings() -> Settings:
    """Create settings for webhook-only mode."""
    return Settings(
        meraki=MerakiSettings(
            api_key=SecretStr("test_api_key_at_least_30_characters_long"),
            org_id="123456",
        ),
        webhooks=WebhookSettings(
            enabled=True,
            shared_secret=SecretStr("test_secret"),
            require_secret=True,
            webhook_only_mode=True,
        ),
    )


@pytest.fixture
def valid_webhook_payload() -> dict:
    """Create a valid webhook payload for testing."""
    return {
        "version": "1.0",
        "sharedSecret": "test_secret",
        "sentAt": datetime.now(UTC).isoformat(),
        "organizationId": "123456",
        "organizationName": "Test Org",
        "organizationUrl": "https://dashboard.meraki.com/o/123456",
        "networkId": "N_123456",
        "networkName": "Test Network",
        "networkUrl": "https://dashboard.meraki.com/o/123456/n/N_123456",
        "deviceSerial": "Q2XX-XXXX-XXXX",
        "deviceMac": "00:11:22:33:44:55",
        "deviceName": "Test Device",
        "deviceUrl": "https://dashboard.meraki.com/o/123456/n/N_123456/manage/nodes/Q2XX-XXXX-XXXX",
        "alertId": "alert_001",
        "alertType": "settings_changed",
        "alertTypeId": "settings_changed",
        "alertLevel": "warning",
        "occurredAt": datetime.now(UTC).isoformat(),
        "alertData": {
            "setting": "ssid_enabled",
            "old_value": "false",
            "new_value": "true",
        },
    }


def test_webhook_endpoint_disabled(webhook_disabled_settings: Settings) -> None:
    """Test webhook endpoint returns 404 when disabled."""
    exporter = ExporterApp(webhook_disabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    response = client.post(
        "/api/webhooks/meraki",
        json={"test": "data"},
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 404
    assert "not enabled" in response.json()["detail"].lower()


def test_webhook_endpoint_invalid_content_type(
    webhook_enabled_settings: Settings, valid_webhook_payload: dict
) -> None:
    """Test webhook endpoint rejects invalid content type."""
    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    response = client.post(
        "/api/webhooks/meraki",
        content="not json",
        headers={"Content-Type": "text/plain"},
    )

    assert response.status_code == 400
    assert "content-type" in response.json()["detail"].lower()


def test_webhook_endpoint_invalid_json(webhook_enabled_settings: Settings) -> None:
    """Test webhook endpoint rejects invalid JSON."""
    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    response = client.post(
        "/api/webhooks/meraki",
        content="not valid json",
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 400
    assert "invalid json" in response.json()["detail"].lower()


def test_webhook_endpoint_payload_too_large(
    webhook_enabled_settings: Settings, valid_webhook_payload: dict
) -> None:
    """Test webhook endpoint rejects payload that is too large."""
    # Set max payload size to 100 bytes
    webhook_enabled_settings.webhooks.max_payload_size = 100

    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    # Create large payload
    large_payload = valid_webhook_payload.copy()
    large_payload["alertData"] = {"data": "x" * 10000}  # Make it large

    response = client.post(
        "/api/webhooks/meraki",
        json=large_payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 413
    assert "too large" in response.json()["detail"].lower()


def test_webhook_endpoint_invalid_secret(
    webhook_enabled_settings: Settings,
    valid_webhook_payload: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test webhook endpoint rejects invalid shared secret."""
    called = {"value": False}

    def fake_emit(*args: object, **kwargs: object) -> None:
        called["value"] = True

    monkeypatch.setattr("meraki_dashboard_exporter.app.emit_webhook_event_log", fake_emit)

    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    # Use wrong shared secret
    payload = valid_webhook_payload.copy()
    payload["sharedSecret"] = "wrong_secret"

    response = client.post(
        "/api/webhooks/meraki",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401
    assert "validation failed" in response.json()["detail"].lower()
    assert called["value"] is False


def test_webhook_endpoint_valid_payload(
    webhook_enabled_settings: Settings,
    valid_webhook_payload: dict,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Test webhook endpoint processes valid payload successfully."""
    captured: dict[str, object] = {}

    def fake_emit(
        payload: dict,
        *,
        enabled: bool,
        include_alert_data: bool,
        drop_fields: list[str],
    ) -> None:
        captured["payload"] = payload
        captured["enabled"] = enabled
        captured["include_alert_data"] = include_alert_data
        captured["drop_fields"] = drop_fields

    monkeypatch.setattr("meraki_dashboard_exporter.app.emit_webhook_event_log", fake_emit)

    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    response = client.post(
        "/api/webhooks/meraki",
        json=valid_webhook_payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"
    assert "processed" in response.json()["message"].lower()
    assert captured["payload"] == valid_webhook_payload
    assert captured["enabled"] is True
    assert captured["include_alert_data"] is True
    assert captured["drop_fields"] == ["sharedSecret"]


def test_webhook_endpoint_no_secret_validation(
    webhook_enabled_settings: Settings, valid_webhook_payload: dict
) -> None:
    """Test webhook endpoint accepts payload when secret validation disabled."""
    # Disable secret validation
    webhook_enabled_settings.webhooks.require_secret = False

    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    # Don't include shared secret
    payload = valid_webhook_payload.copy()
    del payload["sharedSecret"]

    response = client.post(
        "/api/webhooks/meraki",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 200
    assert response.json()["status"] == "success"


def test_webhook_endpoint_missing_required_fields(
    webhook_enabled_settings: Settings,
) -> None:
    """Test webhook endpoint rejects payload with missing required fields."""
    exporter = ExporterApp(webhook_enabled_settings)
    app = exporter.create_app()
    client = TestClient(app)

    # Minimal payload missing required fields
    payload = {
        "version": "1.0",
        "sharedSecret": "test_secret",
        # Missing sentAt, organizationId, organizationName, organizationUrl
    }

    response = client.post(
        "/api/webhooks/meraki",
        json=payload,
        headers={"Content-Type": "application/json"},
    )

    assert response.status_code == 401
    # Validation should fail due to missing required fields
def test_webhook_only_mode_skips_discovery(
    webhook_only_settings: Settings, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Test webhook-only mode does not run discovery at startup."""

    async def _should_not_run(self: DiscoveryService) -> dict:  # pragma: no cover
        raise AssertionError("Discovery should not run in webhook-only mode")

    monkeypatch.setattr(DiscoveryService, "run_discovery", _should_not_run)

    exporter = ExporterApp(webhook_only_settings)
    app = exporter.create_app()

    with TestClient(app) as client:
        response = client.get("/health")

    assert response.status_code == 200

