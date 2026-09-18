"""Validate policy fixtures against the local least-privilege oracle."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .policy import (
    PolicyContractError,
    PolicyData,
    check_rego_structure,
    evaluate_cases,
    load_json,
    parse_case_suite,
)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check least-privilege fixtures and Rego contract anchors"
    )
    parser.add_argument("--data", required=True, type=Path)
    parser.add_argument("--cases", required=True, type=Path)
    parser.add_argument("--rego", required=True, type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    try:
        policy = PolicyData.from_dict(load_json(args.data))
        cases = parse_case_suite(load_json(args.cases))
        check_rego_structure(args.rego)
        summary = evaluate_cases(policy, cases)
        summary["rego_structure"] = "checked"
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (OSError, PolicyContractError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0 if not summary["mismatches"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
