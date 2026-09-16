"""Command-line validation for the Aegis threat catalog."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .model import ThreatModelError, load_catalog


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a local Aegis threat catalog and summarize its coverage"
    )
    parser.add_argument("catalog")
    parser.add_argument("--output", "-o", default="-")
    args = parser.parse_args(argv)

    try:
        rendered = json.dumps(load_catalog(args.catalog).summary(), indent=2, sort_keys=True)
        rendered += "\n"
        if args.output == "-":
            sys.stdout.write(rendered)
        else:
            Path(args.output).write_text(rendered, encoding="utf-8")
    except (OSError, ThreatModelError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
