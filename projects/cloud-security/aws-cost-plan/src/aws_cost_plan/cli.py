"""Command line validation for a local AWS cost plan."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .model import CostPlanError, load_cost_plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate an offline AWS cost and teardown plan"
    )
    parser.add_argument("plan", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        if "://" in str(args.plan):
            raise CostPlanError("plan must be a local path")
        plan = args.plan.resolve(strict=True)
        if not plan.is_file():
            raise CostPlanError("plan must be a local file")
        if args.output:
            output = args.output.resolve()
            if output == plan:
                raise CostPlanError("output must differ from the plan")
            if output.exists():
                raise CostPlanError("output already exists")
        rendered = json.dumps(load_cost_plan(plan).to_dict(), indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (CostPlanError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
