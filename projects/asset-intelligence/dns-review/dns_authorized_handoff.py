"""Require a locally pinned Ed25519 recipient approval before DNS workflow handoff."""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dns_review import MAX_BYTES, _fields, _load, read_input
from zeek_dns_workflow_verify import _canonical, read_report, read_requirements, verify_workflow

DOMAIN = b"cybersecurity-engineering-lab:dns-recipient-requirements:v1\x00"
APPROVAL_FIELDS = {"schema_version", "approval_type", "key_id", "audience", "issued_at", "expires_at",
                   "requirements_sha256", "scope_sha256", "review_policy_sha256", "signature_b64"}


def _crypto():
    try:
        from nacl.signing import VerifyKey
        from nacl.exceptions import BadSignatureError
    except ImportError:
        raise ValueError("recipient approval requires PyNaCl") from None
    return VerifyKey, BadSignatureError


def _identifier(value):
    if not isinstance(value, str) or not re.fullmatch(r"[a-z][a-z0-9-]{2,63}", value):
        raise ValueError("expected a bounded non-sensitive identifier")


def _decode(value, length):
    if not isinstance(value, str) or len(value) != 4*((length+2)//3):
        raise ValueError("invalid cryptographic encoding")
    decoded = base64.b64decode(value, validate=True)
    if len(decoded) != length or base64.b64encode(decoded).decode("ascii") != value:
        raise ValueError("noncanonical cryptographic encoding")
    return decoded


def _instant(value):
    if not isinstance(value, str) or len(value) != 20:
        raise ValueError("expected a UTC timestamp with whole seconds")
    result = datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    if result.strftime("%Y-%m-%dT%H:%M:%SZ") != value:
        raise ValueError("noncanonical UTC timestamp")
    return result


def read_authorities(data):
    policy = _load(data)
    _fields(policy, {"schema_version", "authority_type", "audience", "maximum_validity_seconds", "keys"})
    if (type(policy["schema_version"]) is not int or policy["schema_version"] != 1 or
            policy["authority_type"] != "dns-recipient-authorities"):
        raise ValueError("unsupported authority policy")
    _identifier(policy["audience"])
    lifetime = policy["maximum_validity_seconds"]
    keys = policy["keys"]
    if type(lifetime) is not int or not 1 <= lifetime <= 604800 or not isinstance(keys, list) or not 1 <= len(keys) <= 16:
        raise ValueError("invalid authority policy bounds")
    seen, seen_public_keys = set(), set()
    for key in keys:
        _fields(key, {"key_id", "public_key_b64", "status"})
        _identifier(key["key_id"])
        public_key = _decode(key["public_key_b64"], 32)
        if (key["key_id"] in seen or public_key in seen_public_keys or
                key["status"] not in ("active", "retired", "revoked")):
            raise ValueError("invalid authority key")
        seen.add(key["key_id"])
        seen_public_keys.add(public_key)
    return policy


def _message(approval):
    return DOMAIN + _canonical({key: value for key, value in approval.items() if key != "signature_b64"}).encode("ascii")


def verify_approval(approval_data, requirements, scope, review_policy, authority_data, *, now):
    """Authenticate exact requirement/context bytes using only independently supplied authority data."""
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("verification time must be timezone-aware")
    now = now.astimezone(timezone.utc)
    if any(len(data) > MAX_BYTES for data in (requirements, scope, review_policy)):
        raise ValueError("approved inputs exceed 1 MiB")
    authority = read_authorities(authority_data)
    approval = _load(approval_data)
    _fields(approval, APPROVAL_FIELDS)
    if (type(approval["schema_version"]) is not int or approval["schema_version"] != 1 or
            approval["approval_type"] != "dns-recipient-requirements" or approval["audience"] != authority["audience"]):
        raise ValueError("unsupported approval or wrong audience")
    _identifier(approval["key_id"])
    key = next((item for item in authority["keys"] if item["key_id"] == approval["key_id"]), None)
    if key is None or key["status"] != "active":
        raise ValueError("approval key is not an active pinned authority")
    issued, expires = _instant(approval["issued_at"]), _instant(approval["expires_at"])
    if (not issued <= now < expires or
            not 0 < (expires-issued).total_seconds() <= authority["maximum_validity_seconds"]):
        raise ValueError("approval is outside its permitted validity interval")
    VerifyKey, BadSignatureError = _crypto()
    try:
        VerifyKey(_decode(key["public_key_b64"], 32)).verify(_message(approval), _decode(approval["signature_b64"], 64))
    except BadSignatureError:
        raise ValueError("recipient approval signature did not verify") from None
    for field, data in (("requirements_sha256", requirements), ("scope_sha256", scope),
                        ("review_policy_sha256", review_policy)):
        if not isinstance(approval[field], str) or approval[field] != hashlib.sha256(data).hexdigest():
            raise ValueError("approved requirement or context bytes changed")
    read_requirements(requirements)
    return {"key_id": approval["key_id"], "audience": approval["audience"],
            "issued_at": approval["issued_at"], "expires_at": approval["expires_at"],
            "checked_at": now.isoformat(), "approval_sha256": hashlib.sha256(approval_data).hexdigest(),
            "authority_policy_sha256": hashlib.sha256(authority_data).hexdigest()}


def create_approval(requirements, scope, review_policy, authority_data, *, signing_key, key_id, issued_at, expires_at):
    """Issuer API: sign in memory, then verify against the intended pinned policy before returning."""
    approval = {"schema_version": 1, "approval_type": "dns-recipient-requirements", "key_id": key_id,
                "audience": read_authorities(authority_data)["audience"], "issued_at": issued_at, "expires_at": expires_at,
                "requirements_sha256": hashlib.sha256(requirements).hexdigest(),
                "scope_sha256": hashlib.sha256(scope).hexdigest(),
                "review_policy_sha256": hashlib.sha256(review_policy).hexdigest()}
    approval["signature_b64"] = base64.b64encode(signing_key.sign(_message(approval)).signature).decode("ascii")
    rendered = (_canonical(approval)+"\n").encode("ascii")
    verify_approval(rendered, requirements, scope, review_policy, authority_data, now=_instant(issued_at))
    return rendered


def verify_authorized_workflow(report, previous, current, scope, policy, *, requirements, approval,
                               authority_policy, now, assessment_data=None, ownership_data=None):
    authorization = verify_approval(approval, requirements, scope, policy, authority_policy, now=now)
    result = verify_workflow(report, previous, current, scope, policy, assessment_data=assessment_data,
                             ownership_data=ownership_data, requirements_data=requirements)
    result["recipient_authority_checked"] = True
    result["recipient_authority"] = authorization
    result["interpretation"] += (
        " Recipient requirement approval was verified against the separately supplied local authority policy. "
        "This does not authenticate source logs, risk/ownership reviewers, authority-file distribution "
        "or the freshness of that local trust policy.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path)
    parser.add_argument("previous", type=Path)
    parser.add_argument("current", type=Path)
    for name in ("scope", "policy", "requirements", "approval", "authority-policy"):
        parser.add_argument("--"+name, required=True, type=Path)
    parser.add_argument("--assessment", type=Path)
    parser.add_argument("--ownership-responses", type=Path)
    parser.add_argument("--at", help="explicit UTC fixture instant; omit to use the current UTC clock")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("bounded private input handling requires POSIX")
        now = _instant(args.at) if args.at else datetime.now(timezone.utc)
        result = verify_authorized_workflow(read_report(args.report), read_input(args.previous), read_input(args.current),
            read_input(args.scope), read_input(args.policy), requirements=read_input(args.requirements),
            approval=read_input(args.approval), authority_policy=read_input(args.authority_policy), now=now,
            assessment_data=read_input(args.assessment) if args.assessment else None,
            ownership_data=read_input(args.ownership_responses) if args.ownership_responses else None)
        result["verification_time_source"] = "explicit_fixture" if args.at else "current_utc_clock"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        print("error: authorized DNS handoff failed; check PyNaCl, pinned authority, approval, validity and original inputs",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
