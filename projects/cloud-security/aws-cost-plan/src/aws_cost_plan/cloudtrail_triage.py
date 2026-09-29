"""Classify a small set of defensive CloudTrail signals from local fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


class CloudTrailTriageError(ValueError):
    """Raised when an event cannot be reviewed without guessing."""


@dataclass(frozen=True, slots=True)
class TriageFinding:
    rule_id: str
    severity: str
    event_name: str
    event_time: str
    message: str

    def to_dict(self) -> dict[str, str]:
        return {"rule_id": self.rule_id, "severity": self.severity,
                "event_name": self.event_name, "event_time": self.event_time,
                "message": self.message}


def _text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CloudTrailTriageError(f"{field} must be a non-empty string")
    return value.strip()


def _time(value: Any) -> str:
    text = _text(value, "eventTime")
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CloudTrailTriageError("eventTime must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise CloudTrailTriageError("eventTime must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def triage_event(value: Mapping[str, Any]) -> tuple[TriageFinding, ...]:
    """Return explainable findings for one locally supplied CloudTrail event."""
    if not isinstance(value, Mapping):
        raise CloudTrailTriageError("event must be an object")
    name = _text(value.get("eventName"), "eventName")
    source = _text(value.get("eventSource"), "eventSource")
    timestamp = _time(value.get("eventTime"))
    identity = value.get("userIdentity")
    if not isinstance(identity, Mapping):
        raise CloudTrailTriageError("userIdentity must be an object")
    identity_type = _text(identity.get("type"), "userIdentity.type")
    findings: list[TriageFinding] = []
    if source == "signin.amazonaws.com" and name == "ConsoleLogin":
        response = value.get("responseElements")
        additional = value.get("additionalEventData", {})
        if not isinstance(response, Mapping) or not isinstance(additional, Mapping):
            raise CloudTrailTriageError("ConsoleLogin needs response and additional data")
        if response.get("ConsoleLogin") == "Failure":
            findings.append(TriageFinding("CT001", "medium", name, timestamp,
                "Console sign-in failed; correlate repeated failures by principal and source"))
        elif response.get("ConsoleLogin") == "Success" and additional.get("MFAUsed") != "Yes":
            findings.append(TriageFinding("CT002", "high", name, timestamp,
                "Console sign-in succeeded without explicit MFA evidence"))
    if source == "cloudtrail.amazonaws.com" and name in {"StopLogging", "DeleteTrail"}:
        findings.append(TriageFinding("CT003", "critical", name, timestamp,
            "CloudTrail logging or trail configuration was disabled"))
    if identity_type == "Root":
        findings.append(TriageFinding("CT004", "high", name, timestamp,
            "Root identity activity requires review even when another rule also matches"))
    return tuple(findings)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Triage local CloudTrail JSON Lines events")
    parser.add_argument("events", type=Path)
    args = parser.parse_args(argv)
    try:
        if "://" in str(args.events):
            raise CloudTrailTriageError("events must be a local path")
        path = args.events.resolve(strict=True)
        findings = []
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not line.strip():
                continue
            try:
                findings.extend(item.to_dict() | {"line": number}
                                for item in triage_event(json.loads(line)))
            except (json.JSONDecodeError, CloudTrailTriageError) as exc:
                raise CloudTrailTriageError(f"line {number}: {exc}") from exc
    except (OSError, CloudTrailTriageError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"findings": findings}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
