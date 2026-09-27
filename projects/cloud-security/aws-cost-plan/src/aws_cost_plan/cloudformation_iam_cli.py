"""Run the offline IAM policy review against a CloudFormation JSON file."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Sequence

from .cloudformation_iam import CloudFormationPolicyError, review_cloudformation_template


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review embedded IAM policies in a local CloudFormation JSON template"
    )
    parser.add_argument("template", type=Path)
    args = parser.parse_args(argv)
    try:
        if "://" in str(args.template):
            raise CloudFormationPolicyError("template must be a local path")
        path = args.template.resolve(strict=True)
        if not path.is_file():
            raise CloudFormationPolicyError("template must be a local file")
        template = json.loads(path.read_text(encoding="utf-8"))
        findings = review_cloudformation_template(template)
    except (CloudFormationPolicyError, OSError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
