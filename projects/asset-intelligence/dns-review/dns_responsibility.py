"""Verify explicit, time-bounded acceptance of one reproduced DNS review task."""

import argparse
import base64
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from dns_authorized_handoff import _crypto, _decode, _identifier, _instant
from dns_ownership_review import finding_digest
from dns_review import _fields, _load, _time, _version, publish, read_input
from dns_reviewer_handoff import _digest, read_reviewers, verify_reviewed_handoff
from zeek_dns_workflow_verify import _canonical, read_report

DOMAIN = b"cybersecurity-engineering-lab:dns-review-responsibility:v1\x00"
FIELDS = {"schema_version", "action", "key_id", "audience", "accepted_at", "expires_at",
          "finding_sha256", "team", "workflow_sha256", "authority_policy_sha256", "signature_b64"}


def read_acceptors(data):
    policy = _load(data)
    _fields(policy, {"schema_version", "authority_type", "audience", "maximum_validity_seconds", "keys"})
    if policy["authority_type"] != "dns-review-responsibility-authorities" or not isinstance(policy["keys"], list):
        raise ValueError("unsupported responsibility policy")
    converted = []
    for key in policy["keys"]:
        _fields(key, {"key_id", "public_key_b64", "status", "grants"})
        if not isinstance(key["grants"], list): raise ValueError("invalid responsibility grants")
        grants = []
        for grant in key["grants"]:
            _fields(grant, {"finding_sha256", "team"})
            grants.append(dict(grant, role="team-response"))
        converted.append(dict(key, grants=grants))
    # Reuse the public-key, lifetime, explicit team/grant and duplicate checks,
    # without treating an existing reviewer policy as an acceptance authority.
    read_reviewers(_canonical(dict(policy, authority_type="dns-reviewer-authorities", keys=converted)).encode())
    return policy


def _message(claim):
    return DOMAIN + _canonical({k: v for k, v in claim.items() if k != "signature_b64"}).encode("ascii")


def _verify_claim(claim, report, authority_data, policy, now):
    _fields(claim, FIELDS); _version(claim["schema_version"])
    if claim["action"] != "accept-dns-review-responsibility" or claim["audience"] != policy["audience"]:
        raise ValueError("unsupported acceptance context")
    _identifier(claim["key_id"]); _digest(claim["finding_sha256"])
    for field, data in (("workflow_sha256", report), ("authority_policy_sha256", authority_data)):
        if claim[field] != hashlib.sha256(data).hexdigest(): raise ValueError("accepted context bytes changed")
    key = next((key for key in policy["keys"] if key["key_id"] == claim["key_id"]), None)
    grant = {"finding_sha256": claim["finding_sha256"], "team": claim["team"]}
    if key is None or key["status"] != "active" or grant not in key["grants"]:
        raise ValueError("key cannot accept this finding for this team")
    accepted, expires = _instant(claim["accepted_at"]), _instant(claim["expires_at"])
    if not accepted <= now < expires or not 0 < (expires-accepted).total_seconds() <= policy["maximum_validity_seconds"]:
        raise ValueError("acceptance is outside its validity interval")
    VerifyKey, BadSignatureError = _crypto()
    try:
        VerifyKey(_decode(key["public_key_b64"], 32)).verify(_message(claim), _decode(claim["signature_b64"], 64))
    except BadSignatureError:
        raise ValueError("responsibility signature did not verify") from None


def create_acceptance(report, *, authority_data, signing_key, key_id, finding_sha256, team, accepted_at, expires_at):
    """Sign exact supplied workflow bytes in memory; the receiver must reproduce them."""
    policy = read_acceptors(authority_data)
    claim = dict(schema_version=1, action="accept-dns-review-responsibility", key_id=key_id,
                 audience=policy["audience"], accepted_at=accepted_at, expires_at=expires_at,
                 finding_sha256=finding_sha256, team=team, workflow_sha256=hashlib.sha256(report).hexdigest(),
                 authority_policy_sha256=hashlib.sha256(authority_data).hexdigest())
    claim["signature_b64"] = base64.b64encode(signing_key.sign(_message(claim)).signature).decode("ascii")
    _verify_claim(claim, report, authority_data, policy, _instant(accepted_at))
    return (_canonical(claim)+"\n").encode("ascii")


def accept_responsibility(report, previous, current, scope, policy, *, acceptance, acceptance_policy,
                          expected_acceptance_policy_sha256, **handoff):
    _digest(expected_acceptance_policy_sha256)
    if hashlib.sha256(acceptance_policy).hexdigest() != expected_acceptance_policy_sha256:
        raise ValueError("responsibility authority does not match the independent pin")
    authority = read_acceptors(acceptance_policy)
    verified = verify_reviewed_handoff(report, previous, current, scope, policy, **handoff)
    claim = _load(acceptance)
    _verify_claim(claim, report, acceptance_policy, authority, handoff["now"])
    if claim["audience"] != verified["recipient_authority"]["audience"]:
        raise ValueError("responsibility audience differs from the verified recipient")
    workflow = json.loads(report)
    findings = {finding_digest(workflow["review"], item): item for item in workflow["review"]["findings"]}
    finding = findings.get(claim["finding_sha256"])
    response = next((item for item in _load(handoff["ownership_data"])["responses"]
                     if item["finding_sha256"] == claim["finding_sha256"]), None)
    if (finding is None or response is None or finding["review_team"] != claim["team"] or
            response["team"] != claim["team"] or response["decision"] != "accepted" or
            _instant(claim["accepted_at"]) < _time(response["reviewed_at"])):
        raise ValueError("acceptance requires the exact routed finding and accepted team response")
    return {"schema_version": 1, "receipt_type": "dns-review-responsibility", "status": "accepted_review_responsibility",
            "finding_sha256": claim["finding_sha256"], "team": claim["team"], "key_id": claim["key_id"],
            "audience": claim["audience"], "accepted_at": claim["accepted_at"], "expires_at": claim["expires_at"],
            "verified_at": handoff["now"].astimezone(timezone.utc).isoformat(),
            "workflow_sha256": claim["workflow_sha256"], "acceptance_sha256": hashlib.sha256(acceptance).hexdigest(),
            "acceptance_policy_sha256": expected_acceptance_policy_sha256,
            "reviewer_policy_sha256": handoff["expected_reviewer_policy_sha256"],
            "interpretation": "An independently authorized enrolled key explicitly accepted review responsibility "
            "for this exact finding revision and workflow, after recipient/reviewer verification and reproduction. "
            "This receipt is valid evidence of these checks at verified_at, not a durable assignment registry, "
            "exclusive ownership, human identity, remediation approval or completed remediation. No finding, "
            "risk, existing queue, access right or source evidence is changed. Current trust, expiry and clock "
            "must be checked again before relying on a retained acceptance."}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("report", "previous", "current"): parser.add_argument(name, type=Path)
    for name in ("scope", "policy", "requirements", "approval", "authority-policy", "reviewer-policy", "attestations",
                 "assessment", "ownership-responses", "acceptance", "acceptance-policy", "output"):
        parser.add_argument("--"+name, required=True, type=Path)
    parser.add_argument("--expected-reviewer-policy-sha256", required=True)
    parser.add_argument("--expected-acceptance-policy-sha256", required=True)
    parser.add_argument("--at", help="fixture UTC instant; omit for current UTC time")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix": raise ValueError("private file handling requires POSIX")
        now = _instant(args.at) if args.at else datetime.now(timezone.utc)
        receipt = accept_responsibility(read_report(args.report), read_input(args.previous), read_input(args.current),
            read_input(args.scope), read_input(args.policy), acceptance=read_input(args.acceptance),
            acceptance_policy=read_input(args.acceptance_policy),
            expected_acceptance_policy_sha256=args.expected_acceptance_policy_sha256,
            requirements=read_input(args.requirements), approval=read_input(args.approval),
            authority_policy=read_input(args.authority_policy), reviewer_policy=read_input(args.reviewer_policy),
            expected_reviewer_policy_sha256=args.expected_reviewer_policy_sha256,
            attestations=read_input(args.attestations), now=now, assessment_data=read_input(args.assessment),
            ownership_data=read_input(args.ownership_responses))
        receipt["verification_time_source"] = "explicit_fixture" if args.at else "current_utc_clock"
        publish(args.output, json.dumps(receipt, sort_keys=True, indent=2)+"\n")
    except (OSError, ValueError, TypeError, KeyError, AttributeError, UnicodeError, RecursionError, OverflowError):
        print("error: DNS responsibility receipt was not created; check private inputs, pins, signatures and output", file=sys.stderr)
        return 2
    print(json.dumps({"status": "accepted_review_responsibility", "receipt_created": True}))
    return 0


if __name__ == "__main__": raise SystemExit(main())
