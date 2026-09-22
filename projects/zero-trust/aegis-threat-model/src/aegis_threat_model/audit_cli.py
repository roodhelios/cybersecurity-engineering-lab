"""Verify a local JSON Lines authorization audit chain."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .audit_chain import AuditChainError, parse_json_lines, verify_audit_chain


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Verify hash-linked authorization audit records"
    )
    parser.add_argument("records", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)

    if args.output and args.output.resolve() == args.records.resolve():
        print("error: output must differ from the audit input", file=sys.stderr)
        return 2
    try:
        records = parse_json_lines(
            args.records.read_text(encoding="utf-8").splitlines()
        )
        summary = verify_audit_chain(records)
        rendered = json.dumps(summary, indent=2, sort_keys=True) + "\n"
        if args.output:
            args.output.write_text(rendered, encoding="utf-8")
        else:
            print(rendered, end="")
    except (AuditChainError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
