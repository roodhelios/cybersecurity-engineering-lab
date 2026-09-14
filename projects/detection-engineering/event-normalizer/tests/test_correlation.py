"""Tests for bounded connection-attempt correlation."""

from __future__ import annotations

import sys
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from event_normalizer import CorrelationConfig, NormalizedEvent, correlate_repeated_attempts


BASE_TIME = datetime(2026, 9, 14, 18, 0, tzinfo=timezone.utc)


def attempt(
    offset_seconds: int,
    *,
    source_ip: str = "192.0.2.10",
    destination_ip: str = "198.51.100.20",
    destination_port: int = 80,
    state: str = "S0",
    history: str = "S",
) -> NormalizedEvent:
    return NormalizedEvent(
        timestamp=BASE_TIME + timedelta(seconds=offset_seconds),
        source="zeek",
        event_type="conn",
        src_ip=source_ip,
        src_port=51000,
        dest_ip=destination_ip,
        dest_port=destination_port,
        protocol="tcp",
        raw={"conn_state": state, "history": history},
    )


class CorrelationTests(unittest.TestCase):
    def test_correlates_repeated_attempts_with_distinct_targets(self) -> None:
        events = [
            attempt(0, destination_port=22),
            attempt(10, destination_port=80),
            attempt(20, destination_port=443),
            attempt(30, destination_port=8080),
        ]

        findings = correlate_repeated_attempts(events)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].attempt_count, 4)
        self.assertEqual(findings[0].technique_id, "T1046")
        self.assertEqual(findings[0].confidence, "medium")

    def test_includes_attempt_at_exact_window_boundary(self) -> None:
        events = [
            attempt(0, destination_port=22),
            attempt(20, destination_port=80),
            attempt(40, destination_port=443),
            attempt(60, destination_port=8080),
        ]

        self.assertEqual(len(correlate_repeated_attempts(events)), 1)

    def test_does_not_join_attempts_outside_window(self) -> None:
        events = [
            attempt(0, destination_port=22),
            attempt(20, destination_port=80),
            attempt(40, destination_port=443),
            attempt(61, destination_port=8080),
        ]

        self.assertEqual(correlate_repeated_attempts(events), ())

    def test_keeps_sources_separate(self) -> None:
        events = [
            attempt(0, source_ip="192.0.2.10", destination_port=22),
            attempt(10, source_ip="192.0.2.10", destination_port=80),
            attempt(20, source_ip="192.0.2.11", destination_port=443),
            attempt(30, source_ip="192.0.2.11", destination_port=8080),
        ]

        self.assertEqual(correlate_repeated_attempts(events), ())

    def test_ignores_completed_connections(self) -> None:
        events = [
            attempt(0, destination_port=22),
            attempt(10, destination_port=80),
            attempt(20, destination_port=443),
            attempt(30, destination_port=8080, state="SF", history="ShADadFf"),
        ]

        self.assertEqual(correlate_repeated_attempts(events), ())

    def test_output_is_stable_for_unsorted_input(self) -> None:
        events = [
            attempt(0, destination_port=22),
            attempt(10, destination_port=80),
            attempt(20, destination_port=443),
            attempt(30, destination_port=8080),
        ]

        forward = [item.to_dict() for item in correlate_repeated_attempts(events)]
        reverse = [item.to_dict() for item in correlate_repeated_attempts(reversed(events))]

        self.assertEqual(forward, reverse)

    def test_rejects_impossible_thresholds(self) -> None:
        with self.assertRaisesRegex(ValueError, "cannot exceed"):
            CorrelationConfig(min_attempts=3, min_distinct_targets=4)


if __name__ == "__main__":
    unittest.main()
