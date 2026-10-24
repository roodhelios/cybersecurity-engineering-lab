import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dns_risk_review import score_review
from zeek_dns_workflow import main, review_logs

SCOPE = (ROOT/"examples/scope.json").read_bytes()
POLICY = (ROOT/"examples/review-policy.json").read_bytes()
BEFORE = (ROOT/"examples/zeek-dns-before.jsonl").read_bytes()
AFTER = (ROOT/"examples/zeek-dns.jsonl").read_bytes()
ASSESSMENT = (ROOT/"examples/risk-assessments.json").read_bytes()


def workflow(data=None):
    return review_logs(BEFORE, AFTER, SCOPE, POLICY, previous_observed_at="2026-10-23T00:00:00Z",
        current_observed_at="2026-10-24T00:00:00Z", record_type="A", assessment_data=data)


class DNSRiskTests(unittest.TestCase):
    def test_fixture_score_explains_each_supplied_factor(self):
        result = workflow(ASSESSMENT)["risk_review"]
        finding = result["findings"][0]
        self.assertEqual(finding["risk_score"], 95)
        self.assertEqual(finding["review_band"], "urgent")
        self.assertEqual([item["points"] for item in finding["factors"]], [50, 25, 20])
        self.assertEqual(finding["cap_adjustment"], 0)
        self.assertEqual(finding["review_team"], "web-platform")

    def test_both_cap_boundaries_preserve_the_original_mismatch(self):
        for fields, score, adjustment in [({"change_authorization": "denied"}, 100, -10),
            ({"business_impact": "low", "service_exposure": "internal", "change_authorization": "approved"}, 0, 10)]:
            document = json.loads(ASSESSMENT); document["assessments"][0].update(fields)
            result = workflow(json.dumps(document).encode())
            self.assertEqual(result["review"]["finding_count"], 1)
            self.assertEqual(result["risk_review"]["findings"][0]["risk_score"], score)
            self.assertEqual(result["risk_review"]["findings"][0]["cap_adjustment"], adjustment)

    def test_missing_facts_do_not_become_a_low_score_and_default_output_is_unchanged(self):
        self.assertNotIn("risk_review", workflow())
        result = workflow(b'{"schema_version":1,"assessments":[]}')["risk_review"]
        self.assertEqual(result["unassessed_count"], 1)
        self.assertEqual(result["findings"][0]["assessment_status"], "unassessed")
        self.assertNotIn("risk_score", result["findings"][0])

    def test_review_band_thresholds_are_explicit(self):
        cases = [("moderate", "public", "approved", 35, "routine"),
                 ("high", "restricted", "approved", 40, "priority"),
                 ("moderate", "internal", "denied", 65, "priority"),
                 ("high", "internal", "unreviewed", 70, "urgent")]
        for impact, exposure, authorization, score, band in cases:
            document = json.loads(ASSESSMENT)
            document["assessments"][0].update(business_impact=impact, service_exposure=exposure,
                                             change_authorization=authorization)
            result = workflow(json.dumps(document).encode())["risk_review"]["findings"][0]
            self.assertEqual((result["risk_score"], result["review_band"]), (score, band))

    def test_assessment_schema_and_record_bounds(self):
        document = json.loads(ASSESSMENT)
        for invalid in (dict(document, schema_version=True), dict(document, extra="unknown"),
                        dict(document, assessments=document["assessments"]*1001)):
            with self.assertRaises(ValueError):
                workflow(json.dumps(invalid).encode())
        with self.assertRaises(ValueError):
            workflow(b" "*(1024*1024+1))

    def test_stale_ambiguous_unknown_and_unmatched_review_inputs_fail(self):
        for change in ({"current_addresses": ["192.0.2.10"]}, {"observed_at": "2026-10-23T00:00:00Z"},
                       {"hostname": "worker.example.test"}, {"business_impact": "unknown"},
                       {"current_addresses": ["192.0.2.11", "192.0.2.11"]}, {"review_reference": "invalid\nreference"}):
            document = json.loads(ASSESSMENT); document["assessments"][0].update(change)
            with self.assertRaises(ValueError):
                workflow(json.dumps(document).encode())
        document = json.loads(ASSESSMENT); document["assessments"] *= 2
        with self.assertRaises(ValueError):
            workflow(json.dumps(document).encode())

    @unittest.skipUnless(os.name == "posix", "private workflow requires POSIX")
    def test_cli_publishes_private_risk_result_only_after_complete_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            output, facts = Path(directory)/"review.json", Path(directory)/"facts.json"
            facts.write_bytes(ASSESSMENT)
            args = [str(ROOT/"examples/zeek-dns-before.jsonl"), str(ROOT/"examples/zeek-dns.jsonl"),
                "--scope", str(ROOT/"examples/scope.json"), "--policy", str(ROOT/"examples/review-policy.json"),
                "--record-type", "A", "--previous-observed-at", "2026-10-23T00:00:00Z",
                "--current-observed-at", "2026-10-24T00:00:00Z", "--assessment", str(facts), "--output", str(output)]
            with redirect_stdout(StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_bytes())["risk_review"]["scored_count"], 1)
            output.unlink(); facts.write_bytes(b"private-fixture-marker")
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("private-fixture-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
