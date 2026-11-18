"""Export a fresh scoped identity review as a private CSV without choosing source truth."""

import argparse
import csv
import hashlib
from io import StringIO
import json
from pathlib import Path
import sys

from asset_review import _canonical, _digest, _publish, _read, review_sources

MAX_CSV_BYTES = 32 * 1024 * 1024
COLUMNS = ("scope", "namespace", "review_sha256", "group_id", "identity_status", "conflict_id",
           "record_count", "source_inputs", "source_records", "hostname_claims", "address_claims",
           "conflicting_identifiers")


def export_csv(originals, *, namespace, scope):
    # Never interpret an incoming report as a completed review.
    report = review_sources(originals, namespace=namespace, scope=scope)
    digest = _digest(report)
    conflicts = {finding["finding_id"]: finding for finding in report["findings"]}
    output = StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    for group in report["groups"]:
        numbers = {reference["input_number"] for reference in group["source_records"]}
        row = {"scope": scope, "namespace": namespace, "review_sha256": digest,
               "group_id": group["group_id"], "identity_status": group["identity_status"],
               "conflict_id": group["conflict_id"] or "", "record_count": len(group["source_records"]),
               "source_inputs": [item for item in report["inputs"] if item["input_number"] in numbers],
               "source_records": [{"reference": reference, "observation": observation}
                   for reference, observation in zip(group["source_records"], group["observations"])],
               "hostname_claims": group["hostname_claims"], "address_claims": group["address_claims"],
               "conflicting_identifiers": conflicts.get(group["conflict_id"], {}).get("conflicting_identifiers", {})}
        # Collection cells are JSON, retaining types and record associations. Scalar
        # text comes only from strict identifier grammars or fixed status strings.
        for name in ("source_inputs", "source_records", "hostname_claims", "address_claims", "conflicting_identifiers"):
            row[name] = _canonical(row[name]).decode("utf-8")
        writer.writerow(row)
    data = output.getvalue().encode("utf-8")
    if len(data) > MAX_CSV_BYTES:
        raise ValueError("CSV exceeds output bound")
    return data, {"status": "asset_identity_csv_created", "review_sha256": digest,
                  "csv_sha256": hashlib.sha256(data).hexdigest(), "record_count": report["record_count"],
                  "group_count": report["group_count"], "unresolved_component_count": report["unresolved_component_count"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("sources", nargs="+", type=Path)
    parser.add_argument("--namespace", required=True)
    parser.add_argument("--scope", required=True, choices=("synthetic", "owned", "authorized"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if not 2 <= len(args.sources) <= 8:
            raise ValueError("two to eight sources required")
        data, result = export_csv([_read(path) for path in args.sources], namespace=args.namespace, scope=args.scope)
        _publish(args.output, data)
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print("error: asset CSV export failed; check private sources, context and new output", file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
