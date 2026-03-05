"""Webhook event logging utilities."""

from __future__ import annotations

import json
from collections.abc import Mapping
from typing import Any

from pydantic import BaseModel

WEBHOOK_EVENT_LOG_TYPE = "meraki_webhook_event"
DEFAULT_LOG_SEVERITY = "DEFAULT"
_ALERT_LEVEL_TO_SEVERITY = {
    "critical": "CRITICAL",
    "warning": "WARNING",
    "informational": "INFO",
}


def _to_payload_dict(payload: Mapping[str, Any] | BaseModel) -> dict[str, Any]:
    """Convert payload into a mutable dict."""
    if isinstance(payload, BaseModel):
        return payload.model_dump(by_alias=True)
    return dict(payload)


def build_webhook_log_object(
    payload: Mapping[str, Any] | BaseModel,
    include_alert_data: bool = True,
    drop_fields: list[str] | None = None,
) -> dict[str, Any]:
    """Build sanitized payload object for webhook event logging."""
    log_obj = _to_payload_dict(payload)

    alert_level = str(log_obj.get("alertLevel", "")).strip().lower()
    severity = _ALERT_LEVEL_TO_SEVERITY.get(alert_level, DEFAULT_LOG_SEVERITY)

    occurred_at = log_obj.get("occurredAt")
    sent_at = log_obj.get("sentAt")
    alert_type = log_obj.get("alertType")

    log_obj["logType"] = WEBHOOK_EVENT_LOG_TYPE
    log_obj["severity"] = severity
    event_time = occurred_at or sent_at
    if event_time:
        log_obj["time"] = event_time
    if alert_type:
        log_obj["message"] = str(alert_type)

    for field in drop_fields or ["sharedSecret"]:
        log_obj.pop(field, None)

    if not include_alert_data:
        log_obj.pop("alertData", None)

    return log_obj


def emit_webhook_event_log(
    payload: Mapping[str, Any] | BaseModel,
    *,
    enabled: bool = True,
    include_alert_data: bool = True,
    drop_fields: list[str] | None = None,
) -> None:
    """Emit one-line JSON webhook event log to stdout."""
    if not enabled:
        return

    log_obj = build_webhook_log_object(
        payload=payload,
        include_alert_data=include_alert_data,
        drop_fields=drop_fields,
    )
    print(json.dumps(log_obj, ensure_ascii=False, separators=(",", ":")))
