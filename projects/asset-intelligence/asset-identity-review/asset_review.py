"""Review scoped mock host identities without discovery or network access."""

import argparse
from collections import defaultdict
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

MAX_INPUT_BYTES = 1024 * 1024
MAX_RECORDS_PER_SOURCE = 1000
LABEL = re.compile(r"[a-z][a-z0-9-]{2,63}")
RECORD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
ARN = re.compile(r"arn:aws:ec2:(?:af|ap|ca|eu|il|me|mx|sa|us)-[a-z]+-[1-9][0-9]*:[0-9]{12}:instance/i-(?:[0-9a-f]{8}|[0-9a-f]{17})")


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def _digest(value):
    return hashlib.sha256(_canonical(value)).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-finite JSON constant")


def _exact(value, fields):
    if type(value) is not dict or set(value) != set(fields):
        raise ValueError("unexpected object fields")


def _label(value, pattern=LABEL):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("invalid bounded identifier")
    return value


def _record(value):
    _exact(value, ("source_record_id", "kind", "identifiers", "hostname", "ip_addresses"))
    _label(value["source_record_id"], RECORD_ID)
    if value["kind"] != "host":
        raise ValueError("only host observations supported")
    ids = value["identifiers"]
    if type(ids) is not dict or set(ids) - {"cloud_resource_id", "hardware_id"}:
        raise ValueError("unsupported identity fields")
    for name, identifier in ids.items():
        _label(identifier, ARN if name == "cloud_resource_id" else RECORD_ID)
    hostname = value["hostname"]
    if hostname is not None:
        if not isinstance(hostname, str):
            raise ValueError("expected an ASCII hostname")
        hostname = hostname.removesuffix(".").lower()
        if (len(hostname) > 253 or not hostname or any(
                re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) is None
                for label in hostname.split("."))):
            raise ValueError("invalid hostname")
    raw = value["ip_addresses"]
    if type(raw) is not list or len(raw) > 32:
        raise ValueError("expected at most 32 address claims")
    addresses = set()
    for address in raw:
        if not isinstance(address, str) or "%" in address:
            raise ValueError("expected an unscoped literal address")
        addresses.add(str(ipaddress.ip_address(address)))
    return dict(value, identifiers=dict(sorted(ids.items())), hostname=hostname, ip_addresses=sorted(addresses))


def review_sources(originals, *, namespace, scope):
    _label(namespace)
    if scope not in ("synthetic", "owned", "authorized") or not 2 <= len(originals) <= 8:
        raise ValueError("explicit scope and two to eight sources required")
    records, inputs, source_ids = [], [], set()
    for number, data in enumerate(originals, 1):
        if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
            raise ValueError("bounded original source bytes required")
        document = json.loads(data.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant)
        _canonical(document)
        _exact(document, ("schema_version", "scope", "namespace", "source_id", "captured_at", "assets"))
        if (type(document["schema_version"]) is not int or document["schema_version"] != 1 or
                document["scope"] != scope or document["namespace"] != namespace):
            raise ValueError("source scope, namespace or version differs from review")
        source = _label(document["source_id"])
        if source in source_ids:
            raise ValueError("source IDs must be unique")
        source_ids.add(source)
        captured = document["captured_at"]
        if not isinstance(captured, str) or len(captured) > 64:
            raise ValueError("bounded timezone-aware capture claim required")
        instant = datetime.fromisoformat(captured.replace("Z", "+00:00"))
        if instant.tzinfo is None:
            raise ValueError("capture claim needs UTC offset")
        assets = document["assets"]
        if type(assets) is not list or len(assets) > MAX_RECORDS_PER_SOURCE:
            raise ValueError("oversized source asset collection")
        inputs.append({"input_number": number, "source_id": source,
            "captured_at": instant.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
            "original_sha256": hashlib.sha256(data).hexdigest(), "record_count": len(assets)})
        seen = set()
        for row, value in enumerate(assets, 1):
            normalized = _record(value)
            identifier = normalized["source_record_id"]
            if identifier in seen:
                raise ValueError("duplicate record ID within source")
            seen.add(identifier)
            records.append({"reference": {"input_number": number, "row_number": row,
                "source_id": source, "source_record_id": identifier}, "observation": normalized})

    parents = list(range(len(records)))

    def find(index):
        while parents[index] != index:
            parents[index] = parents[parents[index]]
            index = parents[index]
        return index

    owners = {}
    for index, item in enumerate(records):
        for key in item["observation"]["identifiers"].items():
            if key in owners:
                parents[find(index)] = find(owners[key])
            else:
                owners[key] = index
    components = defaultdict(list)
    for index, item in enumerate(records):
        components[find(index)].append(item)
    groups, findings = [], []
    for component in components.values():
        values = defaultdict(set)
        for item in component:
            for kind, identifier in item["observation"]["identifiers"].items():
                values[kind].add(identifier)
        conflicts = {kind: sorted(claims) for kind, claims in sorted(values.items()) if len(claims) > 1}
        references = [item["reference"] for item in component]
        conflict_id = None
        if conflicts:
            finding = {"finding_type": "conflicting-identity-claims", "namespace": namespace,
                       "scope": scope, "source_records": references,
                       "conflicting_identifiers": conflicts}
            conflict_id = _digest(finding)
            findings.append(dict(finding, finding_id=conflict_id))
        # Never let one matching key hide contradictions elsewhere in its component.
        for members in ([component] if not conflicts else [[item] for item in component]):
            observations = [item["observation"] for item in members]
            refs = [item["reference"] for item in members]
            if conflicts:
                status = "unresolved_identity_conflict"
            elif len(members) > 1:
                status = "matched_identifier_claims"
            else:
                status = "single_source_record" if observations[0]["identifiers"] else "no_strong_identifier"
            groups.append({"group_id": _digest({"namespace": namespace, "scope": scope, "source_records": refs}),
                "identity_status": status,
                "conflict_id": conflict_id, "source_records": refs,
                "observations": observations,
                "hostname_claims": sorted({x["hostname"] for x in observations if x["hostname"] is not None}),
                "address_claims": sorted({a for x in observations for a in x["ip_addresses"]})})
    return {"schema_version": 1, "report_type": "mock-asset-identity-review", "scope": scope,
        "namespace": namespace, "inputs": inputs, "record_count": len(records), "group_count": len(groups),
        "matched_group_count": sum(g["identity_status"] == "matched_identifier_claims" for g in groups),
        "unresolved_component_count": len(findings), "groups": groups, "findings": findings,
        "interpretation": "Supplied host/identifier claims within one declared namespace, not source truth. "
            "Only equal strong identifiers form candidates; IP/hostname alone never merge. "
            "Contradictory components remain separate records. Group IDs are review-local references, "
            "not persistent asset IDs. No source independence, completeness, freshness, accepted ownership, "
            "effective exposure, compromise, remediation or live discovery is established."}


def _read(path):
    if os.name != "posix":
        raise ValueError("bounded private input requires POSIX")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_INPUT_BYTES:
            raise ValueError("bounded regular input required")
        data = source.read(MAX_INPUT_BYTES + 1)
    if len(data) > MAX_INPUT_BYTES:
        raise ValueError("source exceeds input bound")
    return data


def _publish(path, data):
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=".asset-review-", delete=False) as target:
            temporary = Path(target.name)
            target.write(data); target.flush(); os.fsync(target.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("demo", help="review two bundled mock sources")
    review = commands.add_parser("review", help="retain a complete private review of supplied fixture sources")
    review.add_argument("sources", nargs="+", type=Path)
    review.add_argument("--namespace", required=True)
    review.add_argument("--scope", required=True, choices=("synthetic", "owned", "authorized"))
    review.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "demo":
            root = Path(__file__).resolve().parent / "examples"
            report = review_sources([_read(root/name) for name in ("cloud.json", "endpoint.json")],
                                    namespace="synthetic-assets", scope="synthetic")
            if (report["record_count"], report["group_count"], report["matched_group_count"],
                    report["unresolved_component_count"]) != (7, 6, 1, 1):
                raise ValueError("fixture outcomes did not reproduce")
            status = "mock_asset_identity_exercise_passed"
        else:
            if not 2 <= len(args.sources) <= 8:
                raise ValueError("two to eight sources required")
            report = review_sources([_read(path) for path in args.sources], namespace=args.namespace, scope=args.scope)
            _publish(args.output, (json.dumps(report, sort_keys=True, indent=2) + "\n").encode())
            status = "mock_asset_identity_review_created"
        print(json.dumps({"status": status, **{name: report[name] for name in
            ("record_count", "group_count", "matched_group_count", "unresolved_component_count")}}, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError, OverflowError):
        print("error: mock asset review failed; check private sources, scope, namespace and new output", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
