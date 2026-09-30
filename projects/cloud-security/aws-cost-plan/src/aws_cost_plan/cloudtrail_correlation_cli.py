"""Correlate failed sign-ins from a bounded local CloudTrail JSONL file."""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import Sequence

from .cloudtrail_correlation import CloudTrailCorrelationError, correlate_failed_logins


MAX_INPUT_BYTES = 16 * 1024 * 1024
MAX_LINE_CHARS = 65_536
MAX_EVENTS = 20_000


def _read_events(path: Path) -> list[Mapping[str, object]]:
    if "://" in str(path):
        raise CloudTrailCorrelationError("events must be a local path")
    resolved = path.resolve(strict=True)
    if not resolved.is_file():
        raise CloudTrailCorrelationError("events path must be a regular file")
    if resolved.stat().st_size > MAX_INPUT_BYTES:
        raise CloudTrailCorrelationError("events file exceeds the 16 MiB limit")
    records: list[Mapping[str, object]] = []
    for number, line in enumerate(resolved.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > MAX_LINE_CHARS:
            raise CloudTrailCorrelationError(f"line {number}: record exceeds the line limit")
        try:
            value = json.loads(line)
        except json.JSONDecodeError as exc:
            raise CloudTrailCorrelationError(f"line {number}: invalid JSON") from exc
        if not isinstance(value, Mapping):
            raise CloudTrailCorrelationError(f"line {number}: event must be an object")
        records.append(value)
        if len(records) > MAX_EVENTS:
            raise CloudTrailCorrelationError("events file exceeds the 20000 record limit")
    return records


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Correlate local CloudTrail sign-in failures")
    parser.add_argument("events", type=Path, help="local CloudTrail JSON Lines file")
    parser.add_argument("--threshold", type=int, default=3)
    parser.add_argument("--window-seconds", type=int, default=300)
    parser.add_argument("--output", type=Path, help="new local output path")
    args = parser.parse_args(argv)
    try:
        events_path = args.events.resolve(strict=True)
        events = _read_events(events_path)
        candidates = correlate_failed_logins(
            events, threshold=args.threshold, window_seconds=args.window_seconds
        )
        document = json.dumps(
            {"schema_version": 1, "candidates": [item.to_dict() for item in candidates]},
            allow_nan=False, ensure_ascii=False, indent=2, sort_keys=True,
        ) + "\n"
        if args.output is None:
            print(document, end="")
        else:
            output = args.output.resolve(strict=False)
            if output == events_path:
                raise CloudTrailCorrelationError("output must differ from the input file")
            try:
                with output.open("x", encoding="utf-8", newline="\n") as handle:
                    handle.write(document)
            except FileExistsError as exc:
                raise CloudTrailCorrelationError("output already exists") from exc
    except (OSError, UnicodeError, CloudTrailCorrelationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
