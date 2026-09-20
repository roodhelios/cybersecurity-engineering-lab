"""Run the least-privilege fixture suite through a local OPA executable."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .opa_conformance import OpaConformanceError, run_opa_cases
from .policy import PolicyContractError, load_json, parse_case_suite


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Compare reviewed policy fixtures with local OPA decisions"
    )
    parser.add_argument("--opa", default="opa")
    parser.add_argument("--rego", required=True, type=Path)
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--timeout", default=5.0, type=float)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    if args.output and args.output.resolve() in {
        args.rego.resolve(),
        args.data.resolve(),
        args.cases.resolve(),
    }:
        print("error: output must differ from every input path", file=sys.stderr)
        return 2
    try:
        cases = parse_case_suite(load_json(args.cases))
        report = run_opa_cases(
            cases,
            rego_path=args.rego,
            data_path=args.data,
            opa_binary=args.opa,
            timeout_seconds=args.timeout,
        )
        rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, OpaConformanceError, PolicyContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if not report["mismatches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
