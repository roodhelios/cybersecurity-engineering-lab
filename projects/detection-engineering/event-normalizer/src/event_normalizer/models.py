"""Typed output model for normalized security events."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping


@dataclass(frozen=True, slots=True)
class NormalizedEvent:
    """A small common schema that preserves the original event as evidence."""

    timestamp: datetime
    source: Literal["suricata", "zeek"]
    event_type: str
    src_ip: str | None = None
    src_port: int | None = None
    dest_ip: str | None = None
    dest_port: int | None = None
    protocol: str | None = None
    severity: int | None = None
    raw: Mapping[str, Any] = field(default_factory=dict, repr=False, compare=False)

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable representation without discarding raw evidence."""

        return {
            "timestamp": self.timestamp.isoformat(),
            "source": self.source,
            "event_type": self.event_type,
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "dest_ip": self.dest_ip,
            "dest_port": self.dest_port,
            "protocol": self.protocol,
            "severity": self.severity,
            "raw": dict(self.raw),
        }
