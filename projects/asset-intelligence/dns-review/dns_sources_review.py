"""Compare aligned, scoped saved DNS snapshots without choosing a trusted source."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import sys

from dns_review import _scope, _snapshot, publish, read_input

MAX_SOURCES = 8


def review_sources(snapshots, scope_data):
    """Group address-set claims by exact normalized hostname, never by shared IP."""
    if not isinstance(snapshots, (list, tuple)) or not 2 <= len(snapshots) <= MAX_SOURCES:
        raise ValueError("supply two to eight snapshots")
    scope, allowed = _scope(scope_data)
    parsed = [_snapshot(data, allowed) for data in snapshots]
    observed_at = parsed[0][0]
    if any(timestamp != observed_at for timestamp, _ in parsed):
        raise ValueError("snapshot observation claims must name the same instant")
    receipts = [{"source_index": index, "input_sha256": hashlib.sha256(data).hexdigest(),
                 "record_count": len(parsed[index - 1][1])}
                for index, data in enumerate(snapshots, 1)]
    digests = {}
    for receipt in receipts:
        digests.setdefault(receipt["input_sha256"], []).append(receipt["source_index"])
    records = []
    counts = dict.fromkeys(("agreement", "disagreement", "single_observation", "not_observed"), 0)
    for hostname in sorted(allowed):
        groups, missing = {}, []
        for source_index, (_, hosts) in enumerate(parsed, 1):
            if hostname not in hosts:
                missing.append(source_index)
                continue
            addresses, row = hosts[hostname]
            groups.setdefault(tuple(sorted(addresses)), []).append(
                {"source_index": source_index, "record_index": row})
        present_count = len(parsed) - len(missing)
        if not groups:
            status = "not_observed"
        elif len(groups) > 1:
            status = "disagreement"
        elif present_count == 1:
            status = "single_observation"
        else:
            status = "agreement"
        counts[status] += 1
        records.append({"hostname": hostname, "status": status,
            "observed_input_count": present_count, "missing_source_indexes": missing,
            "address_groups": [{"addresses": list(addresses), "references": references}
                for addresses, references in sorted(groups.items())]})
    return {"schema_version": 1, "report_type": "scoped-dns-source-review", "scope": scope,
            "observed_at": observed_at.isoformat(), "scope_sha256": hashlib.sha256(scope_data).hexdigest(),
            "supplied_input_count": len(parsed), "distinct_input_byte_count": len(digests),
            "identical_input_groups": [indexes for indexes in digests.values() if len(indexes) > 1],
            "sources": receipts, "status_counts": counts, "records": records,
            "interpretation": "Agreement groups supplied address-set claims, not independent sources or "
                "a correct DNS answer. Byte-distinct inputs can still share a collector or upstream data. "
                "Disagreement can reflect different views or collection context; it is not a finding, "
                "compromise or ownership decision. Missing rows are not negative answers or asset removal. "
                "Scope and aligned times remain caller claims. No source is selected as authoritative, "
                "no risk is inferred and no query, scan, notification or remediation occurs."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("snapshots", nargs="+", type=Path, help="two to eight ordered saved snapshots")
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path, help="new private JSON report")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix" or not 2 <= len(args.snapshots) <= MAX_SOURCES:
            raise ValueError("POSIX and two to eight input snapshots required")
        result = review_sources([read_input(path) for path in args.snapshots], read_input(args.scope))
        rendered = json.dumps(result, indent=2, sort_keys=True, allow_nan=False) + "\n"
        publish(args.output, rendered)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS source review failed; check private inputs, scope, aligned times and new output",
              file=sys.stderr)
        return 2
    print(json.dumps({"status": "dns_source_review_written", "status_counts": result["status_counts"],
                     "supplied_input_count": result["supplied_input_count"],
                     "distinct_input_byte_count": result["distinct_input_byte_count"],
                     "output_sha256": hashlib.sha256(rendered.encode()).hexdigest()}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
