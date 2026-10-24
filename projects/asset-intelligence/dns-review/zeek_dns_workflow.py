"""Import two saved Zeek DNS logs and publish one scoped policy review."""

import argparse
import json
import os
import sys
from pathlib import Path

from dns_review import publish, read_input
from dns_policy_review import review
from zeek_dns_import import import_dns


def review_logs(previous, current, scope, policy, *, previous_observed_at,
                current_observed_at, record_type):
    before, before_receipt = import_dns(previous, scope, observed_at=previous_observed_at,
                                         record_type=record_type)
    after, after_receipt = import_dns(current, scope, observed_at=current_observed_at,
                                      record_type=record_type)
    result = review(json.dumps(before, sort_keys=True, allow_nan=False).encode(),
                    json.dumps(after, sort_keys=True, allow_nan=False).encode(), scope, policy)
    return {"schema_version": 1, "report_type": "zeek-dns-policy-workflow",
            "record_type": record_type,
            "imports": {"previous": before_receipt, "current": after_receipt},
            "snapshots": {"previous": before, "current": after}, "review": result,
            "interpretation": "Both saved logs use the same explicitly selected address family. "
            "Source-line receipts and generated snapshots are retained with the policy review. "
            "Scope, collection ends, source authenticity, policy approval and ownership remain "
            "caller claims. This is not live DNS, complete discovery, a risk score or remediation."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--previous-observed-at", required=True)
    parser.add_argument("--current-observed-at", required=True)
    parser.add_argument("--record-type", required=True, choices=("A", "AAAA"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("private local output requires POSIX")
        result = review_logs(read_input(args.previous), read_input(args.current),
            read_input(args.scope), read_input(args.policy),
            previous_observed_at=args.previous_observed_at, current_observed_at=args.current_observed_at,
            record_type=args.record_type)
        publish(args.output, json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: saved DNS workflow did not complete; check logs, scope, policy, times and new output path",
              file=sys.stderr)
        return 2
    print(json.dumps({"status": "review_created", "finding_count": result["review"]["finding_count"],
                      "record_type": result["record_type"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
