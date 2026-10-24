"""Score DNS policy mismatches using explicit, observation-bound review inputs."""

import ipaddress
import re

from dns_review import _fields, _hostname, _load, _time, _version

MODEL_ID = "dns-policy-review-risk-v1"
IMPACT = {"low": 10, "moderate": 30, "high": 50}
EXPOSURE = {"internal": 0, "restricted": 10, "public": 25}
AUTHORIZATION = {"approved": -20, "unreviewed": 20, "denied": 35}


def _choice(value, points):
    if not isinstance(value, str) or value not in points:
        raise ValueError("unsupported reviewed assessment value")
    return points[value]


def score_review(review, assessment_data):
    """Extend an in-memory policy review, never infer missing assessment facts."""
    document = _load(assessment_data)
    _fields(document, {"schema_version", "assessments"})
    _version(document["schema_version"])
    values = document["assessments"]
    if not isinstance(values, list) or len(values) > 1000:
        raise ValueError("at most 1000 assessments are supported")
    observations = {item["hostname"]: item for item in review["comparison"]["records"]}
    findings = {item["hostname"]: item for item in review["findings"]}
    facts = {}
    current_time = _time(review["comparison"]["current_observed_at"])
    for index, item in enumerate(values, 1):
        _fields(item, {"hostname", "current_addresses", "observed_at", "business_impact",
                       "service_exposure", "change_authorization", "review_reference"})
        host = _hostname(item["hostname"])
        if host not in findings or host in facts:
            raise ValueError("assessment must identify one unique current mismatch finding")
        addresses = item["current_addresses"]
        if not isinstance(addresses, list) or not 1 <= len(addresses) <= 32:
            raise ValueError("expected 1 to 32 current addresses")
        if any(not isinstance(address, str) or "%" in address for address in addresses):
            raise ValueError("expected literal unscoped addresses")
        normalized = [str(ipaddress.ip_address(address)) for address in addresses]
        if len(set(normalized)) != len(normalized):
            raise ValueError("duplicate normalized assessment address")
        if set(normalized) != set(observations[host]["current_addresses"]) or _time(item["observed_at"]) != current_time:
            raise ValueError("assessment does not bind the current observation")
        reference = item["review_reference"]
        if not isinstance(reference, str) or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,63}", reference):
            raise ValueError("expected a bounded review reference")
        factors = [{"factor": name, "value": item[name], "points": _choice(item[name], points)}
                   for name, points in (("business_impact", IMPACT), ("service_exposure", EXPOSURE),
                                        ("change_authorization", AUTHORIZATION))]
        uncapped = sum(factor["points"] for factor in factors)
        score = max(0, min(100, uncapped))
        facts[host] = {"assessment_status": "scored", "assessment_record": index,
            "review_reference": reference, "risk_score": score,
            "review_band": "urgent" if score >= 70 else "priority" if score >= 40 else "routine",
            "uncapped_score": uncapped, "cap_adjustment": score-uncapped, "factors": factors}
    records = []
    for host, finding in sorted(findings.items()):
        records.append(dict(finding, **facts.get(host, {"assessment_status": "unassessed"})))
    return {"schema_version": 1, "report_type": "scoped-dns-risk-review", "model_id": MODEL_ID,
            "scored_count": len(facts), "unassessed_count": len(findings)-len(facts), "findings": records,
            "interpretation": "Risk scores are explicit lab triage heuristics, not probabilities or "
            "vulnerability severity. Impact, exposure, authorization and review references are supplied "
            "claims, not authenticated approval or ownership. Missing assessment facts remain unassessed "
            "without a score. An approved change can lower triage but does not dismiss the mismatch. "
            "No live lookup, exploitation, notification or remediation occurs."}
