"""Parsers for a bounded subset of Suricata EVE and Zeek JSON events."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Mapping

from .models import NormalizedEvent


class NormalizationError(ValueError):
    """Raised when an event cannot be normalized without guessing."""


def _utc_datetime(value: Any, *, field_name: str) -> datetime:
    try:
        if isinstance(value, bool):
            raise TypeError
        if isinstance(value, (int, float)):
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            candidate = value[:-1] + "+00:00" if value.endswith("Z") else value
            parsed = datetime.fromisoformat(candidate)
        else:
            raise TypeError
    except (OverflowError, TypeError, ValueError) as exc:
        raise NormalizationError(f"{field_name} is not a valid timestamp") from exc

    if parsed.tzinfo is None:
        raise NormalizationError(f"{field_name} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _port(value: Any, *, field_name: str) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise NormalizationError(f"{field_name} must be an integer from 0 to 65535")
    try:
        port = int(value)
    except (TypeError, ValueError) as exc:
        raise NormalizationError(f"{field_name} must be an integer from 0 to 65535") from exc
    if isinstance(value, float) and not value.is_integer():
        raise NormalizationError(f"{field_name} must be an integer from 0 to 65535")
    if not 0 <= port <= 65535:
        raise NormalizationError(f"{field_name} must be an integer from 0 to 65535")
    return port


def _severity(value: Any) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise NormalizationError("alert.severity must be a non-negative integer")
    try:
        severity = int(value)
    except (TypeError, ValueError) as exc:
        raise NormalizationError("alert.severity must be a non-negative integer") from exc
    if isinstance(value, float) and not value.is_integer():
        raise NormalizationError("alert.severity must be a non-negative integer")
    if severity < 0:
        raise NormalizationError("alert.severity must be a non-negative integer")
    return severity


def _text(value: Any) -> str | None:
    return None if value is None else str(value)


def _normalize_suricata(event: Mapping[str, Any]) -> NormalizedEvent:
    event_type = event.get("event_type")
    if not isinstance(event_type, str) or not event_type.strip():
        raise NormalizationError("event_type must be a non-empty string")

    alert = event.get("alert")
    if alert is not None and not isinstance(alert, Mapping):
        raise NormalizationError("alert must be an object when present")

    return NormalizedEvent(
        timestamp=_utc_datetime(event.get("timestamp"), field_name="timestamp"),
        source="suricata",
        event_type=event_type,
        src_ip=_text(event.get("src_ip")),
        src_port=_port(event.get("src_port"), field_name="src_port"),
        dest_ip=_text(event.get("dest_ip")),
        dest_port=_port(event.get("dest_port"), field_name="dest_port"),
        protocol=_text(event.get("proto")),
        severity=_severity(alert.get("severity") if alert else None),
        raw=dict(event),
    )


def _normalize_zeek(event: Mapping[str, Any]) -> NormalizedEvent:
    event_type = event.get("_path") or event.get("log_type") or "connection"
    if not isinstance(event_type, str) or not event_type.strip():
        raise NormalizationError("_path or log_type must be a non-empty string")

    return NormalizedEvent(
        timestamp=_utc_datetime(event.get("ts"), field_name="ts"),
        source="zeek",
        event_type=event_type,
        src_ip=_text(event.get("id.orig_h")),
        src_port=_port(event.get("id.orig_p"), field_name="id.orig_p"),
        dest_ip=_text(event.get("id.resp_h")),
        dest_port=_port(event.get("id.resp_p"), field_name="id.resp_p"),
        protocol=_text(event.get("proto")),
        raw=dict(event),
    )


def normalize_event(event: Mapping[str, Any]) -> NormalizedEvent:
    """Normalize a supported event or fail explicitly for an unknown shape."""

    if not isinstance(event, Mapping):
        raise NormalizationError("event must be a mapping")
    if "timestamp" in event and "event_type" in event:
        return _normalize_suricata(event)
    if "ts" in event and any(key in event for key in ("uid", "id.orig_h", "_path")):
        return _normalize_zeek(event)
    raise NormalizationError("unsupported event shape")
