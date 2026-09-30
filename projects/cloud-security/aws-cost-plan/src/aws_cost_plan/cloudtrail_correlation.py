"""Correlate repeated failed console sign-ins in bounded local windows."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from .cloudtrail_triage import CloudTrailTriageError, triage_event


class CloudTrailCorrelationError(ValueError):
    """Raised when correlation keys or bounds are incomplete."""


@dataclass(frozen=True, slots=True)
class LoginIncidentCandidate:
    principal: str
    source_ip: str
    first_seen: str
    last_seen: str
    failure_count: int
    window_seconds: int
    event_ids: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "principal": self.principal,
            "source_ip": self.source_ip,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "failure_count": self.failure_count,
            "window_seconds": self.window_seconds,
            "event_ids": list(self.event_ids),
        }


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise CloudTrailCorrelationError("eventTime must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise CloudTrailCorrelationError("eventTime must be ISO 8601") from exc
    if parsed.tzinfo is None:
        raise CloudTrailCorrelationError("eventTime must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _key(event: Mapping[str, Any]) -> tuple[str, str]:
    identity = event.get("userIdentity")
    if not isinstance(identity, Mapping):
        raise CloudTrailCorrelationError("userIdentity must be an object")
    principal = identity.get("userName") or identity.get("principalId")
    source_ip = event.get("sourceIPAddress")
    if not isinstance(principal, str) or not principal.strip():
        raise CloudTrailCorrelationError("failed login needs userName or principalId")
    if not isinstance(source_ip, str) or not source_ip.strip():
        raise CloudTrailCorrelationError("failed login needs sourceIPAddress")
    return principal.strip(), source_ip.strip()


def correlate_failed_logins(
    events: Iterable[Mapping[str, Any]], *, threshold: int = 3, window_seconds: int = 300
) -> tuple[LoginIncidentCandidate, ...]:
    """Emit one candidate per principal and source after a bounded threshold."""
    if type(threshold) is not int or not 2 <= threshold <= 100:
        raise CloudTrailCorrelationError("threshold must be an integer from 2 to 100")
    if type(window_seconds) is not int or not 1 <= window_seconds <= 3600:
        raise CloudTrailCorrelationError("window_seconds must be an integer from 1 to 3600")
    grouped: dict[tuple[str, str], list[tuple[datetime, str | None]]] = defaultdict(list)
    seen_event_ids: set[str] = set()
    for event in events:
        try:
            findings = triage_event(event)
        except CloudTrailTriageError as exc:
            raise CloudTrailCorrelationError(str(exc)) from exc
        if any(item.rule_id == "CT001" for item in findings):
            raw_event_id = event.get("eventID")
            if raw_event_id is not None:
                if not isinstance(raw_event_id, str) or not raw_event_id.strip():
                    raise CloudTrailCorrelationError("eventID must be a non-empty string")
                event_id = raw_event_id.strip()
                if event_id in seen_event_ids:
                    raise CloudTrailCorrelationError("duplicate eventID cannot count twice")
                seen_event_ids.add(event_id)
            else:
                event_id = None
            grouped[_key(event)].append((_timestamp(event.get("eventTime")), event_id))

    candidates = []
    for (principal, source_ip), times in sorted(grouped.items()):
        window: deque[datetime] = deque()
        best: tuple[datetime, datetime, int] | None = None
        for current, event_id in sorted(times, key=lambda item: (item[0], item[1] or "")):
            while window and (current - window[0][0]).total_seconds() > window_seconds:
                window.popleft()
            window.append((current, event_id))
            if len(window) >= threshold and (best is None or len(window) > best[2]):
                best = (window[0][0], current, len(window))
                best_event_ids = tuple(sorted(
                    event for _, event in window if event is not None
                ))
        if best:
            first, last, count = best
            candidates.append(LoginIncidentCandidate(
                principal, source_ip,
                first.isoformat().replace("+00:00", "Z"),
                last.isoformat().replace("+00:00", "Z"), count, window_seconds,
                best_event_ids,
            ))
    return tuple(candidates)
