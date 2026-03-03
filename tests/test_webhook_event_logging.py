"""Tests for webhook event logging utilities."""

from __future__ import annotations

import json

from pytest import CaptureFixture

from meraki_dashboard_exporter.core.webhook_event_logging import (
    WEBHOOK_EVENT_LOG_TYPE,
    build_webhook_log_object,
    emit_webhook_event_log,
)


def test_build_webhook_log_object_removes_secret_and_keeps_alert_data() -> None:
    payload = {
        "organizationId": "123456",
        "alertData": {"reason": "offline"},
        "sharedSecret": "secret",
    }

    log_obj = build_webhook_log_object(payload)

    assert log_obj["organizationId"] == "123456"
    assert log_obj["logType"] == WEBHOOK_EVENT_LOG_TYPE
    assert log_obj["alertData"] == {"reason": "offline"}
    assert "sharedSecret" not in log_obj


def test_build_webhook_log_object_drops_alert_data_when_disabled() -> None:
    payload = {
        "organizationId": "123456",
        "alertData": {"reason": "offline"},
        "sharedSecret": "secret",
    }

    log_obj = build_webhook_log_object(payload, include_alert_data=False)

    assert "alertData" not in log_obj
    assert "sharedSecret" not in log_obj


def test_build_webhook_log_object_does_not_mutate_input() -> None:
    payload = {
        "organizationId": "123456",
        "alertData": {"reason": "offline"},
        "sharedSecret": "secret",
    }

    _ = build_webhook_log_object(payload, include_alert_data=False)

    assert "sharedSecret" in payload
    assert "alertData" in payload


def test_emit_webhook_event_log_outputs_one_line_json(capsys: CaptureFixture[str]) -> None:
    payload = {
        "organizationId": "123456",
        "alertData": {"reason": "offline"},
        "sharedSecret": "secret",
    }

    emit_webhook_event_log(payload)
    captured = capsys.readouterr()

    output = captured.out.strip()
    assert "\n" not in output
    parsed = json.loads(output)
    assert parsed["organizationId"] == "123456"
    assert parsed["logType"] == WEBHOOK_EVENT_LOG_TYPE
    assert parsed["alertData"] == {"reason": "offline"}
    assert "sharedSecret" not in parsed


def test_emit_webhook_event_log_disabled_outputs_nothing(capsys: CaptureFixture[str]) -> None:
    payload = {
        "organizationId": "123456",
        "alertData": {"reason": "offline"},
        "sharedSecret": "secret",
    }

    emit_webhook_event_log(payload, enabled=False)
    captured = capsys.readouterr()
    assert captured.out == ""
