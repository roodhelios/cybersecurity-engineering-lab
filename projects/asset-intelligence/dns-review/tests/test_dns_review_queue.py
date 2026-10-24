import copy
import json
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dns_review_queue import build_queue
from zeek_dns_workflow import review_logs


def workflow(**options):
    return review_logs((ROOT/"examples/zeek-dns-before.jsonl").read_bytes(),
        (ROOT/"examples/zeek-dns.jsonl").read_bytes(), (ROOT/"examples/scope.json").read_bytes(),
        (ROOT/"examples/review-policy.json").read_bytes(),
        previous_observed_at="2026-10-23T00:00:00Z", current_observed_at="2026-10-24T00:00:00Z",
        record_type="A", **options)


class DNSQueueTests(unittest.TestCase):
    def test_unassessed_work_has_no_zero_score_or_implied_remediation(self):
        original = workflow()
        self.assertNotIn("review_queue", original)
        queue = workflow(include_queue=True)["review_queue"]
        self.assertEqual(queue["band_counts"]["unassessed"], 1)
        self.assertNotIn("risk_score", queue["items"][0])
        self.assertEqual(queue["items"][0]["next_review"], "supply_assessment_facts")
        self.assertNotIn("due_date", queue["items"][0])

    def test_fixture_risk_and_team_response_drive_distinct_review_steps(self):
        facts = (ROOT/"examples/risk-assessments.json").read_bytes()
        response = json.loads((ROOT/"examples/ownership-responses.json").read_bytes())
        baseline = workflow(assessment_data=facts)
        original = copy.deepcopy(baseline)
        queue = build_queue(baseline)
        self.assertEqual(queue["items"][0]["next_review"], "request_team_response")
        self.assertEqual(baseline, original)
        for decision, step in (("accepted", "review_proposed_remediation"), ("declined", "resolve_declined_routing")):
            response["responses"][0]["decision"] = decision
            result = workflow(assessment_data=facts, ownership_data=json.dumps(response).encode(), include_queue=True)
            item = result["review_queue"]["items"][0]
            self.assertEqual((item["risk_score"], item["review_band"], item["next_review"]), (95, "urgent", step))
            self.assertEqual(result["review"]["finding_count"], 1)
            self.assertEqual(item["assessment_reference"], "synthetic-dns-review-001")

    def test_multiple_findings_sort_by_band_score_then_hostname_without_mutation(self):
        value = workflow(assessment_data=(ROOT/"examples/risk-assessments.json").read_bytes())
        finding = value["review"]["findings"][0]
        observation = next(x for x in value["review"]["comparison"]["records"] if x["hostname"] == finding["hostname"])
        risk = value["risk_review"]["findings"][0]
        rows = [("z.example.test", "priority", 60), ("c.example.test", "urgent", 80),
                ("b.example.test", "urgent", 95), ("a.example.test", "urgent", 95)]
        value["review"]["findings"] = [dict(finding, hostname=host) for host, _, _ in rows]
        value["review"]["comparison"]["records"] = [dict(observation, hostname=host) for host, _, _ in rows]
        value["risk_review"]["findings"] = [dict(risk, hostname=host, review_band=band, risk_score=score) for host, band, score in rows]
        self.assertEqual([x["hostname"] for x in build_queue(value)["items"]],
                         ["a.example.test", "b.example.test", "c.example.test", "z.example.test"])

    def test_empty_review_keeps_explicit_zero_counts(self):
        value = workflow(); value["review"]["findings"] = []
        queue = build_queue(value)
        self.assertEqual(queue["items"], [])
        self.assertEqual(sum(queue["band_counts"].values()), 0)
