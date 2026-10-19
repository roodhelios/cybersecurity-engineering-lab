"""Correlate a bounded batch of local Suricata and Zeek JSON Lines."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Sequence, TextIO

from .cli import JsonlInputError
from .correlation import correlate_repeated_attempts
from .normalizer import NormalizationError, normalize_event


MAX_LINE_CHARS = 1024 * 1024
MAX_EVENTS = 10000


def correlate_jsonl(
    source: TextIO, *, source_name: str = "<stdin>", include_evidence: bool = False
) -> dict:
    """Validate the complete batch before producing any findings."""
    events = []
    references = []
    line_number = 0
    while True:
        line = source.readline(MAX_LINE_CHARS + 1)
        if not line:
            break
        line_number += 1
        if len(line) > MAX_LINE_CHARS:
            raise JsonlInputError(f"{source_name}:{line_number}: line exceeds 1 Mi characters")
        if not line.strip():
            continue
        if len(events) >= MAX_EVENTS:
            raise JsonlInputError(f"{source_name}:{line_number}: batch exceeds 10000 events")
        try:
            raw = json.loads(line)
            events.append(normalize_event(raw))
            if include_evidence:
                canonical = json.dumps(raw, sort_keys=True, ensure_ascii=False,
                                       separators=(",", ":"), allow_nan=False).encode("utf-8")
                references.append({"line_number": line_number,
                                   "event_sha256": hashlib.sha256(canonical).hexdigest()})
        except (ValueError, NormalizationError, RecursionError) as exc:
            raise JsonlInputError(f"{source_name}:{line_number}: invalid event") from exc
    findings = correlate_repeated_attempts(events)
    rendered = []
    for finding in findings:
        value = finding.to_dict()
        if include_evidence:
            value["evidence"] = [references[index] for index in finding.event_indices]
        rendered.append(value)
    return {
        "schema_version": 2 if include_evidence else 1,
        "events_read": len(events),
        "finding_count": len(findings),
        "findings": rendered,
    }


def main(argv: Sequence[str] | None = None) -> int:
    """Print one JSON report, or return 2 without a partial success report."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", nargs="?", default="-", help="JSONL file, or - for stdin")
    parser.add_argument("--include-evidence", action="store_true",
                        help="emit version 2 with source lines and canonical event digests")
    args = parser.parse_args(argv)
    try:
        if args.input == "-":
            result = correlate_jsonl(sys.stdin, include_evidence=args.include_evidence)
        else:
            with Path(args.input).open(encoding="utf-8") as source:
                result = correlate_jsonl(source, source_name=args.input,
                                         include_evidence=args.include_evidence)
    except (JsonlInputError, OSError, UnicodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
