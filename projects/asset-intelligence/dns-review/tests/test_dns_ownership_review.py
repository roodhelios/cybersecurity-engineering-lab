import copy
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
from dns_ownership_review import finding_digest, review_ownership
from zeek_dns_workflow import main, review_logs


def workflow(**options):
    return review_logs((ROOT/"examples/zeek-dns-before.jsonl").read_bytes(),
        (ROOT/"examples/zeek-dns.jsonl").read_bytes(), (ROOT/"examples/scope.json").read_bytes(),
        (ROOT/"examples/review-policy.json").read_bytes(),
        previous_observed_at="2026-10-23T00:00:00Z", current_observed_at="2026-10-24T00:00:00Z",
        record_type="A", **options)


class DNSOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.review = workflow()["review"]
        self.entry = {"finding_sha256": finding_digest(self.review, self.review["findings"][0]),
            "team": "web-platform", "decision": "accepted",
            "reviewed_at": "2026-10-24T01:00:00Z", "review_reference": "synthetic-response-001"}

    def data(self, entries=None):
        return json.dumps({"schema_version": 1, "responses": [self.entry] if entries is None else entries}).encode()

    def test_response_claim_does_not_dismiss_or_rescore_finding(self):
        original = copy.deepcopy(self.review)
        for decision in ("accepted", "declined"):
            self.entry["decision"] = decision
            result = review_ownership(self.review, self.data())
            self.assertEqual(result["responded_count"], 1)
            self.assertEqual(result["findings"][0]["ownership_response"]["status"], decision+"_claim")
            self.assertEqual(result["findings"][0]["finding_type"], "reviewed_dns_address_mismatch")
            self.assertNotIn("risk_score", result["findings"][0])
        self.assertEqual(self.review, original)
        self.assertNotIn("ownership_review", workflow())
        result = workflow(ownership_data=self.data(),
                          assessment_data=(ROOT/"examples/risk-assessments.json").read_bytes())
        self.assertEqual(result["risk_review"]["findings"][0]["risk_score"], 95)
        self.assertEqual(result["ownership_review"]["responded_count"], 1)

    def test_missing_response_stays_pending(self):
        result = review_ownership(self.review, self.data([]))
        self.assertEqual(result["pending_count"], 1)
        self.assertEqual(result["findings"][0]["ownership_response"]["status"], "pending")

    def test_new_policy_observation_or_finding_revision_rejects_stale_response(self):
        for field in ("policy", "time", "addresses", "finding"):
            changed = copy.deepcopy(self.review)
            if field == "policy": changed["policy_sha256"] = "0"*64
            if field == "time": changed["comparison"]["current_observed_at"] = "2026-10-24T00:01:00Z"
            if field == "addresses": changed["comparison"]["records"][0]["current_addresses"] = ["192.0.2.99"]
            if field == "finding": changed["findings"][0]["review_team"] = "other-team"
            with self.subTest(field=field), self.assertRaises(ValueError):
                review_ownership(changed, self.data())

    def test_invalid_wrong_team_early_ambiguous_and_oversized_responses_fail(self):
        for change in ({"team": "other"}, {"decision": True}, {"reviewed_at": "2026-10-23T23:59:59Z"},
                       {"review_reference": "invalid\nref"}, {"finding_sha256": "0"*64}, {"extra": 1}):
            with self.subTest(change=change), self.assertRaises((ValueError, TypeError)):
                review_ownership(self.review, self.data([dict(self.entry, **change)]))
        for entries in ([self.entry, self.entry], [self.entry]*1001):
            with self.assertRaises(ValueError):
                review_ownership(self.review, self.data(entries))
        with self.assertRaises(ValueError):
            review_ownership(self.review, b'{"schema_version":true,"responses":[]}')

    @unittest.skipUnless(os.name == "posix", "private publication requires POSIX")
    def test_cli_keeps_private_output_and_rejects_stale_claim_before_publication(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); responses, output = root/"responses.json", root/"result.json"
            responses.write_bytes(self.data())
            args = [str(ROOT/"examples/zeek-dns-before.jsonl"), str(ROOT/"examples/zeek-dns.jsonl"),
                "--scope", str(ROOT/"examples/scope.json"), "--policy", str(ROOT/"examples/review-policy.json"),
                "--previous-observed-at", "2026-10-23T00:00:00Z", "--current-observed-at", "2026-10-24T00:00:00Z",
                "--record-type", "A", "--ownership-responses", str(responses), "--output", str(output)]
            with redirect_stdout(StringIO()): self.assertEqual(main(args), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertEqual(json.loads(output.read_text())["ownership_review"]["responded_count"], 1)
            before = output.read_bytes()
            with redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), before)
            output.unlink(); self.entry["finding_sha256"] = "0"*64; responses.write_bytes(self.data())
            stdout = StringIO()
            with redirect_stdout(stdout), redirect_stderr(StringIO()): self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
