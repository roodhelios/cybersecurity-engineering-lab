"""Bounded correlation for repeated incomplete connection attempts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import Any, Iterable

from .models import NormalizedEvent


@dataclass(frozen=True, slots=True)
class CorrelationConfig:
    """Thresholds for one non-overlapping correlation window."""

    window_seconds: int = 60
    min_attempts: int = 4
    min_distinct_targets: int = 3

    def __post_init__(self) -> None:
        for field_name in ("window_seconds", "min_attempts", "min_distinct_targets"):
            value = getattr(self, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ValueError(f"{field_name} must be a positive integer")
        if self.min_attempts < 2:
            raise ValueError("min_attempts must be at least 2")
        if self.min_distinct_targets > self.min_attempts:
            raise ValueError("min_distinct_targets cannot exceed min_attempts")


@dataclass(frozen=True, slots=True)
class ConnectionCorrelation:
    """An investigation candidate supported by several source events."""

    source_ip: str
    window_start: str
    window_end: str
    attempt_count: int
    distinct_targets: tuple[str, ...]
    technique_id: str = "T1046"
    technique_name: str = "Network Service Discovery"
    tactic: str = "Discovery"
    confidence: str = "medium"
    rule_id: str = "zeek-repeated-incomplete-syn"

    def to_dict(self) -> dict[str, Any]:
        return {
            "source_ip": self.source_ip,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "attempt_count": self.attempt_count,
            "distinct_targets": list(self.distinct_targets),
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "rule_id": self.rule_id,
        }


def _incomplete_syn(event: NormalizedEvent) -> bool:
    return (
        event.source == "zeek"
        and event.event_type == "conn"
        and event.raw.get("conn_state") == "S0"
        and event.raw.get("history") == "S"
        and bool(event.src_ip)
        and bool(event.dest_ip)
        and event.dest_port is not None
    )


def _target(event: NormalizedEvent) -> str:
    assert event.dest_ip is not None
    assert event.dest_port is not None
    return f"{event.dest_ip}:{event.dest_port}"


def correlate_repeated_attempts(
    events: Iterable[NormalizedEvent],
    *,
    config: CorrelationConfig | None = None,
) -> tuple[ConnectionCorrelation, ...]:
    """Return deterministic, non-overlapping windows of repeated failed SYNs."""

    settings = config or CorrelationConfig()
    by_source: dict[str, list[NormalizedEvent]] = {}
    for event in events:
        if _incomplete_syn(event):
            assert event.src_ip is not None
            by_source.setdefault(event.src_ip, []).append(event)

    findings: list[ConnectionCorrelation] = []
    window_size = timedelta(seconds=settings.window_seconds)
    for source_ip, attempts in sorted(by_source.items()):
        ordered = sorted(
            attempts,
            key=lambda event: (event.timestamp, _target(event)),
        )
        start_index = 0
        while start_index < len(ordered):
            end_index = start_index
            while (
                end_index < len(ordered)
                and ordered[end_index].timestamp - ordered[start_index].timestamp
                <= window_size
            ):
                end_index += 1

            window = ordered[start_index:end_index]
            targets = tuple(sorted({_target(event) for event in window}))
            if (
                len(window) >= settings.min_attempts
                and len(targets) >= settings.min_distinct_targets
            ):
                findings.append(
                    ConnectionCorrelation(
                        source_ip=source_ip,
                        window_start=window[0].timestamp.isoformat(),
                        window_end=window[-1].timestamp.isoformat(),
                        attempt_count=len(window),
                        distinct_targets=targets,
                    )
                )
                start_index = end_index
            else:
                start_index += 1

    return tuple(findings)
