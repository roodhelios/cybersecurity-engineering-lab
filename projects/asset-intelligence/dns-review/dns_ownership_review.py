"""Attach explicit routed-team response claims to an exact DNS finding revision."""

import hashlib
import json
import re

from dns_review import _fields, _load, _time, _version


def finding_digest(review, finding):
    observation = next(item for item in review["comparison"]["records"]
                       if item["hostname"] == finding["hostname"])
    value = {"policy_sha256": review["policy_sha256"], "finding": finding,
             "observed_at": review["comparison"]["current_observed_at"],
             "current_addresses": observation["current_addresses"]}
    data = json.dumps(value, sort_keys=True, ensure_ascii=True, allow_nan=False,
                      separators=(",", ":")).encode("ascii")
    return hashlib.sha256(data).hexdigest()


def review_ownership(review, response_data):
    document = _load(response_data)
    _fields(document, {"schema_version", "responses"})
    _version(document["schema_version"])
    responses = document["responses"]
    if not isinstance(responses, list) or len(responses) > 1000:
        raise ValueError("expected at most 1000 team responses")
    findings = {finding_digest(review, item): item for item in review["findings"]}
    facts = {}
    observed = _time(review["comparison"]["current_observed_at"])
    for index, item in enumerate(responses, 1):
        _fields(item, {"finding_sha256", "team", "decision", "reviewed_at", "review_reference"})
        digest = item["finding_sha256"]
        if not isinstance(digest, str) or digest not in findings or digest in facts:
            raise ValueError("response must bind one unique current finding revision")
        if item["team"] != findings[digest]["review_team"]:
            raise ValueError("only the explicitly routed team can supply this response")
        if item["decision"] not in ("accepted", "declined"):
            raise ValueError("expected an explicit accepted or declined response")
        reference = item["review_reference"]
        if not isinstance(reference, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", reference):
            raise ValueError("expected a bounded response reference")
        reviewed = _time(item["reviewed_at"])
        if reviewed < observed:
            raise ValueError("team response cannot precede the current observation")
        facts[digest] = {"status": item["decision"] + "_claim", "response_record": index,
                         "team": item["team"], "review_reference": reference,
                         "reviewed_at": reviewed.isoformat()}
    return {"schema_version": 1, "report_type": "dns-team-response-review",
            "response_sha256": hashlib.sha256(response_data).hexdigest(),
            "responded_count": len(facts), "pending_count": len(findings)-len(facts),
            "findings": [dict(item, finding_sha256=digest,
                ownership_response=facts.get(digest, {"status": "pending", "team": item["review_team"]}))
                for digest, item in sorted(findings.items())],
            "interpretation": "Responses are explicit caller-supplied claims, not authenticated team "
            "acceptance or asset ownership. Missing responses remain pending. A response is bound to "
            "the policy and observation revision; it never dismisses the finding or changes risk. "
            "No notification, access grant or remediation occurs."}
