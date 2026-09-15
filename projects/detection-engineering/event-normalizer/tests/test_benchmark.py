"""Tests for the deterministic normalization benchmark."""

from __future__ import annotations

import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from event_normalizer.benchmark import (
    benchmark_normalization,
    build_workload,
    synthetic_zeek_event,
)
from event_normalizer.benchmark_cli import main


class FakeTimer:
    def __init__(self, values: list[float]) -> None:
        self.values = iter(values)

    def __call__(self) -> float:
        return next(self.values)


class BenchmarkTests(unittest.TestCase):
    def test_fixture_uses_reserved_addresses_and_stable_fields(self) -> None:
        event = synthetic_zeek_event(3)

        self.assertEqual(event["uid"], "synthetic-00000003")
        self.assertTrue(event["id.orig_h"].startswith("192.0.2."))
        self.assertTrue(event["id.resp_h"].startswith("198.51.100."))

    def test_calculates_rate_from_injected_timer(self) -> None:
        result = benchmark_normalization(
            build_workload(4),
            rounds=2,
            timer=FakeTimer([10.0, 12.0, 20.0, 24.0]),
        )

        self.assertEqual(result.duration_seconds, (2.0, 4.0))
        self.assertEqual(result.events_per_second, (2.0, 1.0))
        self.assertEqual(result.median_events_per_second, 1.5)

    def test_result_states_excluded_work(self) -> None:
        result = benchmark_normalization(
            build_workload(1),
            rounds=1,
            timer=FakeTimer([1.0, 2.0]),
        ).to_dict()

        limitations = " ".join(result["limitations"])
        self.assertIn("JSON decoding", limitations)
        self.assertIn("not a production capacity claim", limitations)

    def test_rejects_unbounded_workload_sizes(self) -> None:
        for value in (0, -1, True, 1_000_001):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    build_workload(value)

    def test_cli_writes_machine_readable_result(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "benchmark.json"

            status = main(["--events", "10", "--rounds", "1", "--output", str(output)])

            result = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual(status, 0)
        self.assertEqual(result["event_count_per_round"], 10)
        self.assertGreater(result["median_events_per_second"], 0)


if __name__ == "__main__":
    unittest.main()
