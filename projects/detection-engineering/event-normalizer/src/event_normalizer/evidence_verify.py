"""Reproduce a version 2 correlation report from retained local JSON Lines."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .cli import JsonlInputError
from .correlation_cli import correlate_jsonl

MAX_REPORT_BYTES = 16 * 1024 * 1024


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate report field")
        value[key] = item
    return value


def _canonical(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False,
                      separators=(",", ":"), allow_nan=False)


def verify_report(source, report):
    """Require the entire report, not just its digests, to reproduce exactly."""
    if not isinstance(report, dict) or type(report.get("schema_version")) is not int:
        raise ValueError("expected a version 2 report")
    if report["schema_version"] != 2:
        raise ValueError("expected a version 2 report")
    expected = correlate_jsonl(source, include_evidence=True)
    if _canonical(report) != _canonical(expected):
        raise ValueError("report does not reproduce from retained input")
    return {"schema_version": 1, "status": "reproduced",
            "events_read": expected["events_read"],
            "finding_count": expected["finding_count"],
            "evidence_references": sum(len(item["evidence"]) for item in expected["findings"])}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="retained local JSONL events")
    parser.add_argument("report", type=Path, help="version 2 correlation JSON report")
    args = parser.parse_args(argv)
    try:
        with args.report.open("rb") as handle:
            raw = handle.read(MAX_REPORT_BYTES + 1)
        if len(raw) > MAX_REPORT_BYTES:
            raise ValueError("report exceeds 16 MiB")
        report = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
        with args.input.open(encoding="utf-8") as source:
            result = verify_report(source, report)
    except (OSError, ValueError, UnicodeError, RecursionError, JsonlInputError):
        print("error: correlation report could not be reproduced from retained input", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
