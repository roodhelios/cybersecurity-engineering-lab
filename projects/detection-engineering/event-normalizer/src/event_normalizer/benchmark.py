"""Deterministic throughput workload for the event normalizer."""

from __future__ import annotations

import os
import platform
import statistics
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping

from .normalizer import normalize_event


MAX_EVENTS = 1_000_000
MAX_ROUNDS = 20


def synthetic_zeek_event(index: int) -> dict[str, Any]:
    """Build one deterministic Zeek record using documentation address ranges."""

    if isinstance(index, bool) or not isinstance(index, int) or index < 0:
        raise ValueError("index must be a non-negative integer")
    return {
        "ts": 1_789_329_600.0 + (index / 1000),
        "uid": f"synthetic-{index:08d}",
        "_path": "conn",
        "id.orig_h": f"192.0.2.{(index % 250) + 1}",
        "id.orig_p": 49152 + (index % 16000),
        "id.resp_h": f"198.51.100.{(index % 250) + 1}",
        "id.resp_p": (22, 53, 80, 443)[index % 4],
        "proto": "tcp",
        "conn_state": "S0",
        "history": "S",
    }


def build_workload(event_count: int) -> tuple[dict[str, Any], ...]:
    """Build the fixture outside the timed section."""

    _validate_size(event_count, "event_count", MAX_EVENTS)
    return tuple(synthetic_zeek_event(index) for index in range(event_count))


def _validate_size(value: int, name: str, maximum: int) -> None:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= maximum
    ):
        raise ValueError(f"{name} must be an integer from 1 to {maximum}")


@dataclass(frozen=True, slots=True)
class BenchmarkResult:
    event_count: int
    rounds: int
    duration_seconds: tuple[float, ...]
    events_per_second: tuple[float, ...]
    median_events_per_second: float
    python_version: str
    python_implementation: str
    operating_system: str
    architecture: str
    logical_cpu_count: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "workload": "synthetic_zeek_normalization",
            "event_count_per_round": self.event_count,
            "rounds": self.rounds,
            "duration_seconds": list(self.duration_seconds),
            "events_per_second": list(self.events_per_second),
            "median_events_per_second": self.median_events_per_second,
            "environment": {
                "python_version": self.python_version,
                "python_implementation": self.python_implementation,
                "operating_system": self.operating_system,
                "architecture": self.architecture,
                "logical_cpu_count": self.logical_cpu_count,
                "execution": "single_process_single_thread",
            },
            "limitations": [
                "The timed section normalizes prebuilt Python mappings.",
                "JSON decoding, file I/O, ATT&CK mapping, and correlation are excluded.",
                "This local measurement is not a production capacity claim.",
            ],
        }


def benchmark_normalization(
    workload: Iterable[Mapping[str, Any]],
    *,
    rounds: int = 5,
    timer: Callable[[], float] = time.perf_counter,
) -> BenchmarkResult:
    """Measure normalization of a materialized, reusable workload."""

    _validate_size(rounds, "rounds", MAX_ROUNDS)
    events = tuple(workload)
    _validate_size(len(events), "event_count", MAX_EVENTS)

    durations: list[float] = []
    rates: list[float] = []
    for _ in range(rounds):
        started = timer()
        normalized_count = sum(1 for event in events if normalize_event(event))
        elapsed = timer() - started
        if normalized_count != len(events):
            raise RuntimeError("benchmark did not normalize every event")
        if elapsed <= 0:
            raise RuntimeError("benchmark timer must advance")
        durations.append(elapsed)
        rates.append(len(events) / elapsed)

    return BenchmarkResult(
        event_count=len(events),
        rounds=rounds,
        duration_seconds=tuple(durations),
        events_per_second=tuple(rates),
        median_events_per_second=statistics.median(rates),
        python_version=platform.python_version(),
        python_implementation=platform.python_implementation(),
        operating_system=platform.system(),
        architecture=platform.machine(),
        logical_cpu_count=os.cpu_count(),
    )
