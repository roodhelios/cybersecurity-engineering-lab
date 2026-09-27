"""Run the offline IAM identity policy review."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .iam_policy import IamPolicyError, review_identity_policy


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Review a local IAM identity policy")
    parser.add_argument("policy", type=Path)
    args = parser.parse_args(argv)
    try:
        if "://" in str(args.policy):
            raise IamPolicyError("policy must be a local path")
        path = args.policy.resolve(strict=True)
        if not path.is_file():
            raise IamPolicyError("policy must be a local file")
        policy = json.loads(path.read_text(encoding="utf-8"))
        findings = review_identity_policy(policy)
    except (IamPolicyError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
