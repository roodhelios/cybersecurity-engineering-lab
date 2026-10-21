"""Review saved ARP observations for recent IP-to-MAC mapping changes."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, Sequence

MAX_LINE_BYTES = 16 * 1024
MAX_RECORDS = 10_000
MAC_PATTERN = re.compile(r"^[0-9a-f]{2}(?::[0-9a-f]{2}){5}$")


class ObservationError(ValueError):
    """Raised when saved observation input is ambiguous or invalid."""


@dataclass(frozen=True)
class Observation:
    timestamp: datetime
    interface: str
    ip: str
    mac: str
    line: int


def _object_without_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ObservationError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _parse_timestamp(value: object) -> datetime:
    if not isinstance(value, str):
        raise ObservationError("timestamp must be a string")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ObservationError("timestamp must be ISO 8601") from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ObservationError("timestamp must include a UTC offset")
    return parsed


def parse_observation(line: str, line_number: int) -> Observation:
    """Parse one strict JSON observation."""
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ObservationError("record exceeds 16384 bytes")
    try:
        raw = json.loads(line, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise ObservationError(f"invalid JSON ({exc.msg})") from exc
    if not isinstance(raw, dict):
        raise ObservationError("record must be a JSON object")
    expected = {"timestamp", "interface", "ip", "mac"}
    missing = expected - raw.keys()
    unknown = raw.keys() - expected
    if missing:
        raise ObservationError(f"missing field: {sorted(missing)[0]}")
    if unknown:
        raise ObservationError(f"unknown field: {sorted(unknown)[0]}")

    timestamp = _parse_timestamp(raw["timestamp"])
    interface = raw["interface"]
    if not isinstance(interface, str) or not interface or len(interface) > 64:
        raise ObservationError("interface must be a non-empty string up to 64 characters")
    ip_value = raw["ip"]
    if not isinstance(ip_value, str):
        raise ObservationError("ip must be a string")
    try:
        ip = str(ipaddress.IPv4Address(ip_value))
    except ipaddress.AddressValueError as exc:
        raise ObservationError("ip must be a canonical IPv4 address") from exc
    if ip != ip_value:
        raise ObservationError("ip must be a canonical IPv4 address")
    mac_value = raw["mac"]
    if not isinstance(mac_value, str):
        raise ObservationError("mac must be a string")
    mac = mac_value.lower()
    if not MAC_PATTERN.fullmatch(mac):
        raise ObservationError("mac must use six colon-separated octets")

    return Observation(timestamp, interface, ip, mac, line_number)


def review_lines(lines: Iterable[str], *, window_seconds: int = 300) -> dict[str, object]:
    """Return mapping-change findings from saved observations."""
    if not 1 <= window_seconds <= 3600:
        raise ObservationError("window must be between 1 and 3600 seconds")
    observations: list[Observation] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(observations) >= MAX_RECORDS:
            raise ObservationError(f"input exceeds {MAX_RECORDS} records")
        try:
            observations.append(parse_observation(line, line_number))
        except ObservationError as exc:
            raise ObservationError(f"line {line_number}: {exc}") from exc

    previous: dict[tuple[str, str], Observation] = {}
    findings: list[dict[str, object]] = []
    for current in observations:
        key = (current.interface, current.ip)
        prior = previous.get(key)
        if prior and current.timestamp < prior.timestamp:
            raise ObservationError(
                f"line {current.line}: timestamps must not move backward for an interface and IP"
            )
        if prior and current.mac != prior.mac:
            age = (current.timestamp - prior.timestamp).total_seconds()
            if age <= window_seconds:
                findings.append(
                    {
                        "type": "ip_mac_mapping_change",
                        "confidence": "medium",
                        "interface": current.interface,
                        "ip": current.ip,
                        "previous_mac": prior.mac,
                        "current_mac": current.mac,
                        "previous_line": prior.line,
                        "current_line": current.line,
                        "elapsed_seconds": int(age),
                    }
                )
        previous[key] = current

    return {
        "schema_version": 1,
        "observation_count": len(observations),
        "finding_count": len(findings),
        "window_seconds": window_seconds,
        "findings": findings,
        "interpretation": (
            "A recent mapping change needs review. It can be caused by failover, replacement, "
            "or address reuse and is not proof of ARP spoofing."
        ),
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="saved JSON Lines observations")
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    try:
        with args.input.open("r", encoding="utf-8") as source:
            report = review_lines(source, window_seconds=args.window_seconds)
    except (OSError, UnicodeError, ObservationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
