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
from zeek_dns_workflow import main, review_logs

SCOPE = (ROOT/"examples/scope.json").read_bytes()
POLICY = (ROOT/"examples/review-policy.json").read_bytes()
CURRENT = (ROOT/"examples/zeek-dns.jsonl").read_bytes()
PREVIOUS = CURRENT.splitlines()[0]+b"\n"


class DNSWorkflowTests(unittest.TestCase):
    def review(self, previous=PREVIOUS, current=CURRENT, policy=POLICY):
        return review_logs(previous, current, SCOPE, policy,
            previous_observed_at="2026-10-23T00:00:00Z",
            current_observed_at="2026-10-24T00:00:00Z", record_type="A")

    def test_one_workflow_retains_sources_snapshots_and_review_team(self):
        result = self.review()
        self.assertEqual(result["review"]["finding_count"], 1)
        finding = result["review"]["findings"][0]
        self.assertEqual(finding["hostname"], "web.example.test")
        self.assertEqual(finding["review_team"], "web-platform")
        self.assertEqual(result["snapshots"]["current"]["records"][0]["addresses"], ["192.0.2.11"])
        self.assertEqual(result["imports"]["current"]["selected"][0]["source_lines"], [2])
        self.assertEqual(result["imports"]["current"]["omitted_latest"][0]["reason"], "unsuitable_response")

    def test_invalid_current_tail_and_policy_reject_complete_workflow(self):
        with self.assertRaises(ValueError):
            self.review(current=CURRENT+b"\nprivate-fixture-marker")
        policy = json.loads(POLICY); policy["rules"][0]["hostname"] = "outside.example.test"
        with self.assertRaises(ValueError):
            self.review(policy=json.dumps(policy).encode())
        with self.assertRaises(ValueError):
            review_logs(PREVIOUS, CURRENT, SCOPE, POLICY, previous_observed_at="2026-10-24T00:00:00Z",
                        current_observed_at="2026-10-24T00:00:00Z", record_type="A")

    @unittest.skipUnless(os.name == "posix", "private files require POSIX")
    def test_cli_publishes_one_private_report_and_never_replaces_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            before, current, scope, policy, output = (root/name for name in
                ("before.jsonl", "after.jsonl", "scope.json", "policy.json", "review.json"))
            for path, data in ((before, PREVIOUS), (current, CURRENT), (scope, SCOPE), (policy, POLICY)):
                path.write_bytes(data)
            args = [str(before), str(current), "--scope", str(scope), "--policy", str(policy),
                "--previous-observed-at", "2026-10-23T00:00:00Z", "--current-observed-at", "2026-10-24T00:00:00Z",
                "--record-type", "A", "--output", str(output)]
            with redirect_stdout(StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            original = output.read_bytes()
            with redirect_stderr(StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), original)
            output.unlink(); current.write_bytes(CURRENT+b"\nprivate-fixture-marker")
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("private-fixture-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
