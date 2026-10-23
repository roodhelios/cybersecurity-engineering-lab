"""Convert a bounded saved Zeek DNS JSON log into a scoped address snapshot."""

import argparse
import hashlib
import ipaddress
import json
import math
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dns_review import MAX_BYTES, MAX_RECORDS, _hostname, _load, _scope, _time, publish, read_input


def import_dns(data, scope_data, *, observed_at, record_type):
    """Select the latest transaction per scoped hostname for one address family."""
    if len(data) > MAX_BYTES or record_type not in ("A", "AAAA"):
        raise ValueError("unsupported import size or address family")
    scope, allowed = _scope(scope_data)
    end = _time(observed_at)
    qtype, family = (1, 4) if record_type == "A" else (28, 6)
    latest, count = {}, 0
    skipped = {"out_of_scope": 0, "other_record_type": 0}
    for line_number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        count += 1
        if count > MAX_RECORDS or len(line.encode("utf-8")) > 64 * 1024:
            raise ValueError("Zeek row limit exceeded")
        row = _load(line.encode("utf-8"))
        if not isinstance(row, dict):
            raise ValueError("expected a Zeek JSON object")
        host = _hostname(row.get("query"))
        if host not in allowed:
            skipped["out_of_scope"] += 1
            continue
        if type(row.get("qtype")) is not int:
            raise ValueError("expected numeric Zeek qtype")
        if row["qtype"] != qtype:
            skipped["other_record_type"] += 1
            continue
        if "qtype_name" in row and row["qtype_name"] != record_type:
            raise ValueError("inconsistent Zeek record type")
        timestamp = row.get("ts")
        if type(timestamp) not in (int, float) or not math.isfinite(timestamp) or timestamp < 0:
            raise ValueError("expected a finite Zeek timestamp")
        transaction_time = datetime.fromtimestamp(timestamp, timezone.utc)
        if transaction_time > end:
            raise ValueError("transaction follows supplied observation end")
        if type(row.get("qclass")) is not int or row["qclass"] != 1:
            raise ValueError("only Internet-class answers are supported")
        if type(row.get("rcode")) is not int or row["rcode"] < 0:
            raise ValueError("expected a response code")
        if type(row.get("TC")) is not bool or type(row.get("rejected")) is not bool:
            raise ValueError("expected Zeek truncation and rejection flags")
        reason = None
        addresses = []
        if row["TC"] or row["rejected"] or row["rcode"] != 0:
            reason = "unsuitable_response"
        elif "answers" in row and not isinstance(row["answers"], list):
            raise ValueError("expected an answer array")
        elif not row.get("answers"):
            reason = "no_address_answers"
        else:
            answers = row["answers"]
            if not isinstance(answers, list) or len(answers) > 32:
                raise ValueError("expected at most 32 answers")
            for answer in answers:
                if not isinstance(answer, str):
                    raise ValueError("expected string answers")
                try:
                    if "%" in answer:
                        raise ValueError("scoped address")
                    address = ipaddress.ip_address(answer)
                except ValueError:
                    # Zeek answers can contain CNAMEs. Do not assign their addresses to a query.
                    reason = "non_address_or_wrong_family"
                    break
                if address.version != family:
                    reason = "non_address_or_wrong_family"
                    break
                addresses.append(str(address))
        value = (reason, tuple(sorted(set(addresses))) if reason is None else ())
        previous = latest.get(host)
        if previous is None or timestamp > previous[0]:
            latest[host] = (timestamp, value, [line_number])
        elif timestamp == previous[0]:
            if value != previous[1]:
                raise ValueError("ambiguous latest transactions at equal timestamps")
            previous[2].append(line_number)
    records, selected, omitted = [], [], []
    for host, (timestamp, (reason, addresses), lines) in sorted(latest.items()):
        reference = {"hostname": host, "source_lines": lines, "transaction_ts": timestamp}
        if reason:
            omitted.append(dict(reference, reason=reason))
        else:
            records.append({"hostname": host, "addresses": list(addresses)})
            selected.append(reference)
    snapshot = {"schema_version": 1, "observed_at": end.isoformat(), "records": records}
    receipt = {"schema_version": 1, "report_type": "zeek-dns-snapshot-import", "scope": scope,
               "record_type": record_type, "input_sha256": hashlib.sha256(data).hexdigest(),
               "scope_sha256": hashlib.sha256(scope_data).hexdigest(), "rows_read": count,
               "filtered_rows": skipped, "selected": selected, "omitted_latest": omitted,
               "interpretation": "Saved transactions only. Observation end and scope are caller claims. "
               "Missing, rejected, truncated, negative, and alias answers do not establish asset removal. "
               "Compare snapshots from the same selected address family and collection context. "
               "No DNS query was sent; source authenticity and collection completeness are unverified."}
    return snapshot, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    parser.add_argument("--scope", required=True, type=Path)
    parser.add_argument("--observed-at", required=True)
    parser.add_argument("--record-type", required=True, choices=("A", "AAAA"))
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("private local files require POSIX")
        snapshot, receipt = import_dns(read_input(args.log), read_input(args.scope),
            observed_at=args.observed_at, record_type=args.record_type)
        publish(args.output, json.dumps(snapshot, sort_keys=True, indent=2, allow_nan=False) + "\n")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: Zeek DNS snapshot was not imported; check saved log, scope, time and new output path",
              file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
