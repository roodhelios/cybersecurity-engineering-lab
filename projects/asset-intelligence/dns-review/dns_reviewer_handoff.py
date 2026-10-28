"""Require finding-scoped reviewer signatures after recipient-approved DNS reproduction."""

import argparse
import base64
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

from dns_authorized_handoff import (_crypto, _decode, _identifier, _instant, read_authorities,
                                    verify_authorized_workflow)
from dns_ownership_review import finding_digest
from dns_review import _fields, _hostname, _load, _time, _version, read_input
from zeek_dns_workflow_verify import _canonical, read_report

DOMAIN = b"cybersecurity-engineering-lab:dns-finding-review:v1\x00"
FIELDS = {"schema_version", "attestation_type", "key_id", "audience", "issued_at", "expires_at",
          "finding_sha256", "role", "review_record_sha256", "signature_b64"}
ROLES = {"risk", "team-response"}


def _digest(value):
    if not isinstance(value, str) or not re.fullmatch("[0-9a-f]{64}", value):
        raise ValueError("expected a lowercase SHA-256 digest")


def _record_digest(record):
    return hashlib.sha256(_canonical(record).encode("ascii")).hexdigest()


def read_reviewers(data):
    """Validate every explicit finding/role grant; no hostname or team wildcard grants."""
    policy = _load(data)
    _fields(policy, {"schema_version", "authority_type", "audience", "maximum_validity_seconds", "keys"})
    _version(policy["schema_version"])
    if policy["authority_type"] != "dns-reviewer-authorities" or not isinstance(policy["keys"], list):
        raise ValueError("unsupported reviewer authority policy")
    keys, total = [], 0
    for key in policy["keys"]:
        _fields(key, {"key_id", "public_key_b64", "status", "grants"})
        grants = key["grants"]
        if not isinstance(grants, list) or not 1 <= len(grants) <= 2000:
            raise ValueError("reviewer keys require bounded explicit grants")
        seen = set()
        for grant in grants:
            _fields(grant, {"finding_sha256", "role", "team"})
            _digest(grant["finding_sha256"])
            if not isinstance(grant["role"], str) or grant["role"] not in ROLES:
                raise ValueError("unsupported review role")
            team = grant["team"]
            if grant["role"] == "risk":
                if team is not None:
                    raise ValueError("risk grants have no team identity")
            elif (not isinstance(team, str) or not 1 <= len(team) <= 64 or not team.strip() or
                  any(ord(char) < 32 for char in team)):
                raise ValueError("team-response grants require a bounded explicit team")
            identity = (grant["finding_sha256"], grant["role"], team)
            if identity in seen:
                raise ValueError("duplicate reviewer grant")
            seen.add(identity); total += 1
            if total > 2000:
                raise ValueError("at most 2000 total reviewer grants are supported")
        keys.append({field: key[field] for field in ("key_id", "public_key_b64", "status")})
    # Reuse the existing public-key/lifetime validation, without changing its contract.
    common = dict(policy, authority_type="dns-recipient-authorities", keys=keys)
    read_authorities(_canonical(common).encode("ascii"))
    return policy


def _message(attestation):
    return DOMAIN + _canonical({k: v for k, v in attestation.items() if k != "signature_b64"}).encode("ascii")


def _verify_one(attestation, record, team, authority, *, now):
    _fields(attestation, FIELDS)
    _version(attestation["schema_version"])
    if (attestation["attestation_type"] != "dns-finding-review" or
            attestation["audience"] != authority["audience"] or
            not isinstance(attestation["role"], str) or attestation["role"] not in ROLES):
        raise ValueError("unsupported reviewer attestation context")
    _identifier(attestation["key_id"]); _digest(attestation["finding_sha256"])
    _digest(attestation["review_record_sha256"])
    key = next((key for key in authority["keys"] if key["key_id"] == attestation["key_id"]), None)
    grant = {"finding_sha256": attestation["finding_sha256"], "role": attestation["role"], "team": team}
    if key is None or key["status"] != "active" or grant not in key["grants"]:
        raise ValueError("key is not authorized for this finding, role and routed team")
    issued, expires = _instant(attestation["issued_at"]), _instant(attestation["expires_at"])
    if (not issued <= now < expires or
            not 0 < (expires-issued).total_seconds() <= authority["maximum_validity_seconds"]):
        raise ValueError("reviewer attestation is outside its validity interval")
    claimed_time = record["observed_at"] if attestation["role"] == "risk" else record["reviewed_at"]
    if issued < _time(claimed_time) or attestation["review_record_sha256"] != _record_digest(record):
        raise ValueError("review record or claimed chronology differs from the attestation")
    VerifyKey, BadSignatureError = _crypto()
    try:
        VerifyKey(_decode(key["public_key_b64"], 32)).verify(_message(attestation), _decode(attestation["signature_b64"], 64))
    except BadSignatureError:
        raise ValueError("finding-review signature did not verify") from None


def create_attestation(record, *, finding_sha256, role, team, authority_data, signing_key,
                       key_id, issued_at, expires_at):
    """Issuer helper for supplied review records; the recipient still reproduces the workflow."""
    authority = read_reviewers(authority_data)
    attestation = {"schema_version": 1, "attestation_type": "dns-finding-review", "key_id": key_id,
                   "audience": authority["audience"], "issued_at": issued_at, "expires_at": expires_at,
                   "finding_sha256": finding_sha256, "role": role, "review_record_sha256": _record_digest(record)}
    attestation["signature_b64"] = base64.b64encode(signing_key.sign(_message(attestation)).signature).decode("ascii")
    _verify_one(attestation, record, team, authority, now=_instant(issued_at))
    return attestation


def _expected(report, assessment_data, ownership_data):
    review = report["review"]
    if not 1 <= len(review["findings"]) <= 1000 or "risk_review" not in report or "ownership_review" not in report:
        raise ValueError("reviewer handoff requires 1 to 1000 findings with both review layers")
    by_host = {item["hostname"]: (finding_digest(review, item), item["review_team"]) for item in review["findings"]}
    expected = {}
    for record in _load(assessment_data)["assessments"]:
        digest, _ = by_host[_hostname(record["hostname"])]
        expected[(digest, "risk")] = (record, None)
    for record in _load(ownership_data)["responses"]:
        expected[(record["finding_sha256"], "team-response")] = (record, record["team"])
    if len(expected) != 2 * len(by_host):
        raise ValueError("every finding requires explicit risk and team-response records")
    return expected


def verify_reviewed_handoff(report, previous, current, scope, policy, *, requirements, approval,
                            authority_policy, reviewer_policy, expected_reviewer_policy_sha256,
                            attestations, now, assessment_data, ownership_data):
    """Reproduce recipient-approved evidence and require exactly two authorized roles per finding."""
    _digest(expected_reviewer_policy_sha256)
    if (not isinstance(reviewer_policy, bytes) or len(reviewer_policy) > 1024 * 1024 or
            hashlib.sha256(reviewer_policy).hexdigest() != expected_reviewer_policy_sha256):
        raise ValueError("reviewer authority policy does not match the required independent pin")
    authority = read_reviewers(reviewer_policy)
    result = verify_authorized_workflow(report, previous, current, scope, policy, requirements=requirements,
        approval=approval, authority_policy=authority_policy, now=now,
        assessment_data=assessment_data, ownership_data=ownership_data)
    if authority["audience"] != result["recipient_authority"]["audience"]:
        raise ValueError("reviewer and recipient policies name different audiences")
    expected = _expected(json.loads(report.decode("utf-8")), assessment_data, ownership_data)
    bundle = _load(attestations)
    _fields(bundle, {"schema_version", "attestations"}); _version(bundle["schema_version"])
    values = bundle["attestations"]
    if not isinstance(values, list) or len(values) != len(expected):
        raise ValueError("expected exactly one attestation for each finding and review role")
    seen = set()
    for attestation in values:
        _fields(attestation, FIELDS)
        if not isinstance(attestation["finding_sha256"], str) or not isinstance(attestation["role"], str):
            raise ValueError("invalid finding-role identity")
        identity = (attestation["finding_sha256"], attestation["role"])
        if identity not in expected or identity in seen:
            raise ValueError("extra or duplicate finding-role attestation")
        _verify_one(attestation, *expected[identity], authority, now=now)
        seen.add(identity)
    result["reviewer_authority_checked"] = True
    result["reviewer_authority"] = {"policy_sha256": expected_reviewer_policy_sha256,
        "attestations_sha256": hashlib.sha256(attestations).hexdigest(), "attestation_count": len(seen),
        "risk_attestation_count": result["finding_count"], "team_response_attestation_count": result["finding_count"]}
    result["interpretation"] = (
        "The complete workflow reproduced and recipient requirements were authenticated. Each risk and team-response "
        "record has a signature authorized for the exact finding revision and role under the pinned reviewer policy. "
        "This authenticates enrolled keys and supplied claims, not natural persons, source truth, independent judgment, "
        "asset ownership or remediation. Existing accepted_claim/declined_claim labels remain unchanged. "
        "Key enrollment, policy freshness and trusted clock distribution remain external responsibilities.")
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "previous", "current"):
        parser.add_argument(name, type=Path)
    for name in ("scope", "policy", "requirements", "approval", "authority-policy", "reviewer-policy",
                 "attestations", "assessment", "ownership-responses"):
        parser.add_argument("--"+name, required=True, type=Path)
    parser.add_argument("--expected-reviewer-policy-sha256", required=True)
    parser.add_argument("--at", help="explicit fixture instant; omit for the current UTC clock")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ValueError("bounded private inputs require POSIX")
        now = _instant(args.at) if args.at else datetime.now(timezone.utc)
        result = verify_reviewed_handoff(read_report(args.report), read_input(args.previous), read_input(args.current),
            read_input(args.scope), read_input(args.policy), requirements=read_input(args.requirements),
            approval=read_input(args.approval), authority_policy=read_input(args.authority_policy),
            reviewer_policy=read_input(args.reviewer_policy), attestations=read_input(args.attestations),
            expected_reviewer_policy_sha256=args.expected_reviewer_policy_sha256, now=now,
            assessment_data=read_input(args.assessment), ownership_data=read_input(args.ownership_responses))
        result["verification_time_source"] = "explicit_fixture" if args.at else "current_utc_clock"
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        print("error: reviewer-authorized DNS handoff failed; check private evidence, pinned policies, roles and signatures",
              file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
