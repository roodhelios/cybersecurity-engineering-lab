"""Compare scoped, supplied DNS observation snapshots without sending queries."""

import argparse
import hashlib
import ipaddress
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_RECORDS = 1000


def _fields(value, expected):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError("unexpected object fields")


def _unique(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


def _load(data):
    if len(data) > MAX_BYTES:
        raise ValueError("input exceeds 1 MiB")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_unique)
    json.dumps(value, allow_nan=False)
    return value


def _hostname(value):
    if not isinstance(value, str):
        raise ValueError("hostname must be a string")
    name = value.lower().removesuffix(".")
    if not 1 <= len(name) <= 253 or not name.isascii():
        raise ValueError("expected an ASCII hostname")
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
           for label in name.split(".")):
        raise ValueError("unsupported hostname")
    return name


def _time(value):
    if not isinstance(value, str) or len(value) > 64:
        raise ValueError("expected a bounded timestamp")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("timestamp must have a UTC offset")
    return parsed.astimezone(timezone.utc)


def _version(value):
    if type(value) is not int or value != 1:
        raise ValueError("unsupported schema version")


def _scope(data):
    policy = _load(data)
    _fields(policy, {"schema_version", "scope", "allowed_hosts"})
    _version(policy["schema_version"])
    if policy["scope"] not in ("synthetic", "owned", "authorized"):
        raise ValueError("explicit local scope required")
    hosts = policy["allowed_hosts"]
    if not isinstance(hosts, list) or not 1 <= len(hosts) <= MAX_RECORDS:
        raise ValueError("expected 1 to 1000 allowed hosts")
    canonical = [_hostname(host) for host in hosts]
    if len(canonical) != len(set(canonical)):
        raise ValueError("duplicate scope hostname")
    return policy["scope"], set(canonical)


def _snapshot(data, allowed):
    snapshot = _load(data)
    _fields(snapshot, {"schema_version", "observed_at", "records"})
    _version(snapshot["schema_version"])
    observed = _time(snapshot["observed_at"])
    records = snapshot["records"]
    if not isinstance(records, list) or len(records) > MAX_RECORDS:
        raise ValueError("at most 1000 records are supported")
    hosts = {}
    for index, record in enumerate(records, 1):
        _fields(record, {"hostname", "addresses"})
        host = _hostname(record["hostname"])
        if host not in allowed or host in hosts:
            raise ValueError("out-of-scope or duplicate hostname")
        values = record["addresses"]
        if not isinstance(values, list) or not 1 <= len(values) <= 32:
            raise ValueError("each observed host requires 1 to 32 addresses")
        if any(not isinstance(value, str) or "%" in value for value in values):
            raise ValueError("expected literal unscoped IP addresses")
        addresses = [str(ipaddress.ip_address(value)) for value in values]
        if len(addresses) != len(set(addresses)):
            raise ValueError("duplicate address")
        hosts[host] = (set(addresses), index)
    return observed, hosts


def compare(before_data, after_data, scope_data):
    scope, allowed = _scope(scope_data)
    before_time, before = _snapshot(before_data, allowed)
    after_time, after = _snapshot(after_data, allowed)
    if after_time <= before_time:
        raise ValueError("current observation must be later than baseline")
    records = []
    counts = dict.fromkeys(("changed", "unchanged", "first_observed", "not_observed_current"), 0)
    for host in sorted(before.keys() | after.keys()):
        previous, previous_row = before.get(host, (set(), None))
        current, current_row = after.get(host, (set(), None))
        if host not in before:
            status = "first_observed"
        elif host not in after:
            status = "not_observed_current"
        else:
            status = "changed" if previous != current else "unchanged"
        counts[status] += 1
        records.append({
            "hostname": host, "status": status,
            "previous_addresses": sorted(previous), "current_addresses": sorted(current),
            # A missing snapshot row is not a confirmed DNS answer or removal.
            "addresses_added": sorted(current - previous) if host in before and host in after else [],
            "addresses_removed": sorted(previous - current) if host in before and host in after else [],
            "previous_record": previous_row, "current_record": current_row,
        })
    return {
        "schema_version": 1, "report_type": "scoped-dns-observation-comparison",
        "scope": scope, "allowed_host_count": len(allowed), "observed_host_count": len(records),
        "not_observed_in_either_count": len(allowed - (before.keys() | after.keys())),
        "previous_observed_at": before_time.isoformat(), "current_observed_at": after_time.isoformat(),
        "input_sha256": {"previous": hashlib.sha256(before_data).hexdigest(),
                         "current": hashlib.sha256(after_data).hexdigest(),
                         "scope": hashlib.sha256(scope_data).hexdigest()},
        "status_counts": counts, "records": records,
        "interpretation": (
            "Supplied observations only. Missing rows do not prove asset removal or DNS failure. "
            "Address changes do not prove compromise, ownership, or source authenticity. "
            "Scope and observation times are caller claims; no DNS query was sent."
        ),
    }


def read_input(path):
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
            raise ValueError("expected a bounded regular input")
        return handle.read(MAX_BYTES + 1)


def publish(path, rendered):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".dns-review-", delete=False) as output:
            temporary = Path(output.name)
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    parser.add_argument("--scope", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new private JSON file; otherwise stdout")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("private local files require POSIX")
        result = compare(read_input(args.previous), read_input(args.current), read_input(args.scope))
        rendered = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output:
            publish(args.output, rendered)
        else:
            print(rendered, end="")
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS observations were not compared; check local inputs, scope, times, and output path",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
