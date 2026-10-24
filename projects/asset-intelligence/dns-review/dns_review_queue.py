"""Prioritize local DNS review work without executing or claiming remediation."""

from dns_ownership_review import finding_digest

ORDER = {"urgent": 0, "priority": 1, "routine": 2, "unassessed": 3}


def build_queue(workflow):
    review = workflow["review"]
    risk = {item["hostname"]: item for item in workflow.get("risk_review", {}).get("findings", [])}
    responses = {item["finding_sha256"]: item["ownership_response"]
                 for item in workflow.get("ownership_review", {}).get("findings", [])}
    records = []
    for finding in review["findings"]:
        digest = finding_digest(review, finding)
        assessed = risk.get(finding["hostname"], {})
        scored = assessed.get("assessment_status") == "scored"
        response = responses.get(digest, {"status": "pending", "team": finding["review_team"]})
        item = {"hostname": finding["hostname"], "finding_sha256": digest,
                "review_team": finding["review_team"], "review_band": assessed["review_band"] if scored else "unassessed",
                "assessment_status": "scored" if scored else "unassessed",
                "team_response": response,
                "next_review": "supply_assessment_facts" if not scored else
                    "resolve_declined_routing" if response["status"] == "declined_claim" else
                    "request_team_response" if response["status"] == "pending" else "review_proposed_remediation"}
        if scored:
            item["risk_score"] = assessed["risk_score"]
            item["risk_factors"] = assessed["factors"]
            item["assessment_reference"] = assessed["review_reference"]
        records.append(item)
    records.sort(key=lambda item: (ORDER[item["review_band"]], -item.get("risk_score", 0), item["hostname"]))
    return {"schema_version": 1, "report_type": "dns-review-queue", "finding_count": len(records),
            "band_counts": {band: sum(item["review_band"] == band for item in records) for band in ORDER},
            "items": records,
            "interpretation": "Scored review work is ordered by explicit lab band, descending score "
            "and hostname. Unassessed work is a separate bucket, not low risk. Team responses remain "
            "unauthenticated claims. Next-review labels are suggestions, not approved remediation, "
            "due dates, ownership acceptance or execution. No access change or notification occurs."}
