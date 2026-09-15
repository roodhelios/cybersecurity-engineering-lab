"""Command-line entry point for the local normalization benchmark."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .benchmark import benchmark_normalization, build_workload


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Measure a deterministic local event-normalization workload"
    )
    parser.add_argument("--events", type=int, default=50_000)
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--output", "-o", default="-")
    args = parser.parse_args(argv)

    try:
        result = benchmark_normalization(
            build_workload(args.events),
            rounds=args.rounds,
        )
    except (RuntimeError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    rendered = json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"
    try:
        if args.output == "-":
            sys.stdout.write(rendered)
        else:
            Path(args.output).write_text(rendered, encoding="utf-8")
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
