"""Run the offline IAM review against a Terraform plan JSON file."""

from __future__ import annotations

import argparse
import json
import stat
import sys
from pathlib import Path
from typing import Sequence

from .terraform_iam import (
    TerraformPolicyError,
    load_terraform_json,
    review_terraform_plan,
)


MAX_PLAN_BYTES = 8 * 1024 * 1024


def _read_plan(path: Path) -> object:
    if "://" in str(path):
        raise TerraformPolicyError("plan must be a local path")
    resolved = path.resolve(strict=True)
    metadata = resolved.stat()
    if not stat.S_ISREG(metadata.st_mode):
        raise TerraformPolicyError("plan must be a regular file")
    if metadata.st_size > MAX_PLAN_BYTES:
        raise TerraformPolicyError("plan exceeds the 8 MiB review limit")
    with resolved.open("rb") as handle:
        payload = handle.read(MAX_PLAN_BYTES + 1)
    if len(payload) > MAX_PLAN_BYTES:
        raise TerraformPolicyError("plan exceeds the 8 MiB review limit")
    try:
        return load_terraform_json(payload)
    except UnicodeDecodeError as exc:
        raise TerraformPolicyError("plan must be UTF-8 JSON") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Review IAM policies in local terraform show -json plan output"
    )
    parser.add_argument("plan", type=Path)
    args = parser.parse_args(argv)
    try:
        plan = _read_plan(args.plan)
        findings = review_terraform_plan(plan)
    except (TerraformPolicyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps({"findings": [item.to_dict() for item in findings]}, indent=2))
    return 1 if findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
