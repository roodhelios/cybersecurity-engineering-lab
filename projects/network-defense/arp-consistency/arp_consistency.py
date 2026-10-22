"""Review saved ARP observations for recent IP-to-MAC mapping changes."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import sys
from bisect import bisect_right
from contextlib import ExitStack
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


@dataclass(frozen=True)
class Lease:
    starts_at: datetime
    ends_at: datetime
    interface: str
    ip: str
    mac: str
    line: int


@dataclass(frozen=True)
class ForwardingEntry:
    captured_at: datetime
    interface: str
    mac: str
    port: str
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


def _parse_interface(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ObservationError("interface must be a non-empty string up to 64 characters")
    return value


def _parse_ip(value: object) -> str:
    if not isinstance(value, str):
        raise ObservationError("ip must be a string")
    try:
        parsed = str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError as exc:
        raise ObservationError("ip must be a canonical IPv4 address") from exc
    if parsed != value:
        raise ObservationError("ip must be a canonical IPv4 address")
    return parsed


def _parse_mac(value: object) -> str:
    if not isinstance(value, str):
        raise ObservationError("mac must be a string")
    parsed = value.lower()
    if not MAC_PATTERN.fullmatch(parsed):
        raise ObservationError("mac must use six colon-separated octets")
    return parsed


def _parse_port(value: object) -> str:
    if not isinstance(value, str) or not value or len(value) > 64:
        raise ObservationError("port must be a non-empty string up to 64 characters")
    return value


def _parse_json_object(line: str) -> dict[str, object]:
    if len(line.encode("utf-8")) > MAX_LINE_BYTES:
        raise ObservationError("record exceeds 16384 bytes")
    try:
        raw = json.loads(line, object_pairs_hook=_object_without_duplicates)
    except json.JSONDecodeError as exc:
        raise ObservationError(f"invalid JSON ({exc.msg})") from exc
    if not isinstance(raw, dict):
        raise ObservationError("record must be a JSON object")
    return raw


def _require_fields(raw: dict[str, object], expected: set[str]) -> None:
    missing = expected - raw.keys()
    unknown = raw.keys() - expected
    if missing:
        raise ObservationError(f"missing field: {sorted(missing)[0]}")
    if unknown:
        raise ObservationError(f"unknown field: {sorted(unknown)[0]}")


def parse_observation(line: str, line_number: int) -> Observation:
    """Parse one strict JSON observation."""
    raw = _parse_json_object(line)
    _require_fields(raw, {"timestamp", "interface", "ip", "mac"})
    return Observation(
        _parse_timestamp(raw["timestamp"]),
        _parse_interface(raw["interface"]),
        _parse_ip(raw["ip"]),
        _parse_mac(raw["mac"]),
        line_number,
    )


def parse_lease(line: str, line_number: int) -> Lease:
    """Parse one bounded DHCP lease record."""
    raw = _parse_json_object(line)
    _require_fields(raw, {"starts_at", "ends_at", "interface", "ip", "mac"})
    starts_at = _parse_timestamp(raw["starts_at"])
    ends_at = _parse_timestamp(raw["ends_at"])
    if ends_at < starts_at:
        raise ObservationError("ends_at must not precede starts_at")
    return Lease(
        starts_at,
        ends_at,
        _parse_interface(raw["interface"]),
        _parse_ip(raw["ip"]),
        _parse_mac(raw["mac"]),
        line_number,
    )


def parse_forwarding_entry(line: str, line_number: int) -> ForwardingEntry:
    """Parse one saved switch forwarding-table entry."""
    raw = _parse_json_object(line)
    _require_fields(raw, {"captured_at", "interface", "mac", "port"})
    return ForwardingEntry(
        _parse_timestamp(raw["captured_at"]),
        _parse_interface(raw["interface"]),
        _parse_mac(raw["mac"]),
        _parse_port(raw["port"]),
        line_number,
    )


def _load_leases(lines: Iterable[str]) -> list[Lease]:
    leases: list[Lease] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(leases) >= MAX_RECORDS:
            raise ObservationError(f"lease input exceeds {MAX_RECORDS} records")
        try:
            leases.append(parse_lease(line, line_number))
        except ObservationError as exc:
            raise ObservationError(f"lease line {line_number}: {exc}") from exc
    return leases


def _load_forwarding_entries(lines: Iterable[str]) -> list[ForwardingEntry]:
    entries: list[ForwardingEntry] = []
    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if len(entries) >= MAX_RECORDS:
            raise ObservationError(f"forwarding input exceeds {MAX_RECORDS} records")
        try:
            entries.append(parse_forwarding_entry(line, line_number))
        except ObservationError as exc:
            raise ObservationError(f"forwarding line {line_number}: {exc}") from exc
    return entries


def _index_leases(leases: list[Lease]) -> dict[tuple[str, str, str], list[Lease]]:
    index: dict[tuple[str, str, str], list[Lease]] = {}
    for lease in leases:
        index.setdefault((lease.interface, lease.ip, lease.mac), []).append(lease)
    for schedule in index.values():
        schedule.sort(key=lambda lease: lease.starts_at)
        for prior, current in zip(schedule, schedule[1:]):
            if current.starts_at <= prior.ends_at:
                raise ObservationError(
                    f"lease line {current.line}: overlapping DHCP leases for one mapping"
                )
    return index


def _active_lease(
    index: dict[tuple[str, str, str], list[Lease]], current: Observation
) -> Lease | None:
    schedule = index.get((current.interface, current.ip, current.mac), [])
    position = bisect_right(schedule, current.timestamp, key=lambda lease: lease.starts_at)
    if position:
        candidate = schedule[position - 1]
        if current.timestamp <= candidate.ends_at:
            return candidate
    return None


def _index_forwarding_entries(
    entries: list[ForwardingEntry],
) -> dict[tuple[str, str], list[ForwardingEntry]]:
    index: dict[tuple[str, str], list[ForwardingEntry]] = {}
    for entry in entries:
        index.setdefault((entry.interface, entry.mac), []).append(entry)
    for schedule in index.values():
        schedule.sort(key=lambda entry: entry.captured_at)
        for prior, current in zip(schedule, schedule[1:]):
            if current.captured_at == prior.captured_at:
                raise ObservationError(
                    f"forwarding line {current.line}: duplicate capture time for one mapping"
                )
    return index


def _recent_forwarding_entry(
    index: dict[tuple[str, str], list[ForwardingEntry]],
    current: Observation,
    max_age_seconds: int,
) -> ForwardingEntry | None:
    schedule = index.get((current.interface, current.mac), [])
    position = bisect_right(
        schedule, current.timestamp, key=lambda entry: entry.captured_at
    )
    if position:
        candidate = schedule[position - 1]
        age = (current.timestamp - candidate.captured_at).total_seconds()
        if age <= max_age_seconds:
            return candidate
    return None


def review_lines(
    lines: Iterable[str],
    *,
    window_seconds: int = 300,
    leases: Iterable[str] | None = None,
    forwarding_entries: Iterable[str] | None = None,
    forwarding_max_age_seconds: int = 300,
) -> dict[str, object]:
    """Return mapping-change findings from saved observations."""
    if not 1 <= window_seconds <= 3600:
        raise ObservationError("window must be between 1 and 3600 seconds")
    if not 1 <= forwarding_max_age_seconds <= 3600:
        raise ObservationError("forwarding max age must be between 1 and 3600 seconds")
    lease_records = _load_leases(leases) if leases is not None else None
    lease_index = _index_leases(lease_records) if lease_records is not None else None
    forwarding_records = (
        _load_forwarding_entries(forwarding_entries)
        if forwarding_entries is not None
        else None
    )
    forwarding_index = (
        _index_forwarding_entries(forwarding_records)
        if forwarding_records is not None
        else None
    )
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
                finding: dict[str, object] = {
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
                if lease_index is not None:
                    active_lease = _active_lease(lease_index, current)
                    if active_lease:
                        finding["lease_status"] = "expected_reassignment"
                        finding["lease_line"] = active_lease.line
                    else:
                        finding["lease_status"] = "unexplained_change"
                if forwarding_index is not None:
                    forwarding_entry = _recent_forwarding_entry(
                        forwarding_index, current, forwarding_max_age_seconds
                    )
                    if forwarding_entry:
                        finding["forwarding_status"] = "current_mac_observed"
                        finding["forwarding_line"] = forwarding_entry.line
                        finding["current_port"] = forwarding_entry.port
                    else:
                        finding["forwarding_status"] = "no_recent_current_mac"
                findings.append(finding)
        previous[key] = current

    report: dict[str, object] = {
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
    if lease_records is not None:
        expected = sum(
            finding.get("lease_status") == "expected_reassignment" for finding in findings
        )
        report["lease_reconciliation"] = {
            "lease_count": len(lease_records),
            "expected_reassignments": expected,
            "unexplained_changes": len(findings) - expected,
        }
    if forwarding_records is not None:
        observed = sum(
            finding.get("forwarding_status") == "current_mac_observed"
            for finding in findings
        )
        report["forwarding_reconciliation"] = {
            "entry_count": len(forwarding_records),
            "current_mac_observed": observed,
            "no_recent_current_mac": len(findings) - observed,
            "max_age_seconds": forwarding_max_age_seconds,
        }
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="saved JSON Lines observations")
    parser.add_argument("--leases", type=Path, help="optional saved DHCP lease JSON Lines")
    parser.add_argument(
        "--forwarding-table",
        type=Path,
        help="optional saved switch forwarding-table JSON Lines",
    )
    parser.add_argument("--forwarding-max-age-seconds", type=int, default=300)
    parser.add_argument("--window-seconds", type=int, default=300)
    args = parser.parse_args(argv)
    input_paths = [path.resolve() for path in (args.input, args.leases, args.forwarding_table) if path]
    if len(input_paths) != len(set(input_paths)):
        print("error: observation, lease, and forwarding inputs must be different files", file=sys.stderr)
        return 2
    try:
        with ExitStack() as stack:
            source = stack.enter_context(args.input.open("r", encoding="utf-8"))
            lease_source = (
                stack.enter_context(args.leases.open("r", encoding="utf-8"))
                if args.leases
                else None
            )
            forwarding_source = (
                stack.enter_context(args.forwarding_table.open("r", encoding="utf-8"))
                if args.forwarding_table
                else None
            )
            report = review_lines(
                source,
                window_seconds=args.window_seconds,
                leases=lease_source,
                forwarding_entries=forwarding_source,
                forwarding_max_age_seconds=args.forwarding_max_age_seconds,
            )
    except (OSError, UnicodeError, ObservationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True, indent=2, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
