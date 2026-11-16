"""Reproduce an aligned DNS source review under independently retained byte pins."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from dns_review import MAX_BYTES, _unique, read_input
from dns_sources_review import MAX_SOURCES, review_sources

MAX_REPORT_BYTES = 32 * 1024 * 1024


def _pin(value):
    if not isinstance(value, str) or re.fullmatch("[0-9a-f]{64}", value) is None:
        raise ValueError("independent lowercase SHA-256 pin required")
    return value


def _match(data, expected, limit):
    if type(data) is not bytes or len(data) > limit:
        raise ValueError("bounded original bytes required")
    if hashlib.sha256(data).hexdigest() != _pin(expected):
        raise ValueError("original bytes differ from independent pin")


def _reject_constant(value):
    raise ValueError("non-finite JSON value")


def _canonical(document):
    return json.dumps(document, sort_keys=True, allow_nan=False, separators=(",", ":")).encode("utf-8")


def verify_sources(report_data, snapshots, scope_data, *, expected_report_sha256,
                   expected_input_sha256, expected_scope_sha256):
    """Check every external pin before parsing and compare the complete reproduction."""
    if (not isinstance(snapshots, (list, tuple)) or not 2 <= len(snapshots) <= MAX_SOURCES or
            not isinstance(expected_input_sha256, (list, tuple)) or
            len(snapshots) != len(expected_input_sha256)):
        raise ValueError("two to eight ordered inputs and matching independent pins required")
    _match(report_data, expected_report_sha256, MAX_REPORT_BYTES)
    _match(scope_data, expected_scope_sha256, MAX_BYTES)
    for data, digest in zip(snapshots, expected_input_sha256):
        _match(data, digest, MAX_BYTES)
    document = json.loads(report_data.decode("utf-8"), object_pairs_hook=_unique,
                          parse_constant=_reject_constant)
    expected = review_sources(snapshots, scope_data)
    if _canonical(document) != _canonical(expected):
        raise ValueError("complete source review did not reproduce under current implementation")
    return {"status": "dns_source_review_reproduced", "report_sha256": expected_report_sha256,
            "supplied_input_count": expected["supplied_input_count"],
            "distinct_input_byte_count": expected["distinct_input_byte_count"],
            "status_counts": expected["status_counts"],
            "interpretation": "Complete report reproduced from independently pinned ordered inputs "
                "and scope under the current implementation. Pins require an independently trusted "
                "channel. No collector authenticity, source independence, freshness, DNS truth, "
                "finding, ownership or remediation is established."}


def _read_report(path):
    if os.name != "posix":
        raise ValueError("bounded private reads require POSIX")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_REPORT_BYTES:
            raise ValueError("expected a bounded regular report")
        data = source.read(MAX_REPORT_BYTES + 1)
    if len(data) > MAX_REPORT_BYTES:
        raise ValueError("report exceeds 32 MiB")
    return data


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("report", type=Path)
    parser.add_argument("snapshots", nargs="+", type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--expected-report-sha256", required=True)
    parser.add_argument("--expected-scope-sha256", required=True)
    parser.add_argument("--expected-input-sha256", required=True, action="append",
                        help="repeat in the same order as the snapshot paths")
    args = parser.parse_args(argv)
    try:
        if (os.name != "posix" or not 2 <= len(args.snapshots) <= MAX_SOURCES or
                len(args.snapshots) != len(args.expected_input_sha256)):
            raise ValueError("POSIX and two to eight ordered inputs/pins required")
        for digest in [args.expected_report_sha256, args.expected_scope_sha256, *args.expected_input_sha256]:
            _pin(digest)
        report = _read_report(args.report)
        _match(report, args.expected_report_sha256, MAX_REPORT_BYTES)
        result = verify_sources(report, [read_input(path) for path in args.snapshots], read_input(args.scope),
            expected_report_sha256=args.expected_report_sha256,
            expected_input_sha256=args.expected_input_sha256, expected_scope_sha256=args.expected_scope_sha256)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS source review did not reproduce; check private originals, ordered pins and scope",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
