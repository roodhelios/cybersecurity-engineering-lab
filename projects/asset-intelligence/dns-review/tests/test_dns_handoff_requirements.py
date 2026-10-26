import copy
import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from zeek_dns_workflow import review_logs
from zeek_dns_workflow_verify import main, verify_workflow


class HandoffRequirementsTests(unittest.TestCase):
    def setUp(self):
        self.inputs = [(ROOT / "examples" / name).read_bytes() for name in (
            "zeek-dns-before.jsonl", "zeek-dns.jsonl", "scope.json", "review-policy.json")]
        self.options = {"assessment_data": (ROOT / "examples/risk-assessments.json").read_bytes(),
                        "ownership_data": (ROOT / "examples/ownership-responses.json").read_bytes()}
        self.requirements = (ROOT / "examples/handoff-requirements.json").read_bytes()

    def report(self, **options):
        return review_logs(*self.inputs, previous_observed_at="2026-10-23T00:00:00Z",
                           current_observed_at="2026-10-24T00:00:00Z", record_type="A", **options)

    def verify(self, report, requirements, **options):
        return verify_workflow(json.dumps(report).encode(), *self.inputs,
                               requirements_data=requirements, **options)

    def test_complete_report_meets_independent_requirements_without_network_or_mutation(self):
        report = self.report(include_queue=True, **self.options)
        before = copy.deepcopy(report)
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.verify(report, self.requirements, **self.options)
        self.assertTrue(result["requirements_checked"])
        self.assertEqual(result["requirements_sha256"], hashlib.sha256(self.requirements).hexdigest())
        self.assertEqual(report, before)
        for private in ("web.example.test", "192.0.2.11", "web-platform"):
            self.assertNotIn(private, json.dumps(result))

    def test_consistent_omission_does_not_satisfy_required_layers(self):
        for omitted in ("risk_review", "ownership_review", "review_queue"):
            options = dict(self.options)
            if omitted == "risk_review": options.pop("assessment_data")
            if omitted == "ownership_review": options.pop("ownership_data")
            report = self.report(include_queue=omitted != "review_queue", **options)
            self.assertEqual(self.verify(report, None, **options)["status"], "workflow_reproduced")
            with self.subTest(omitted=omitted), self.assertRaises(ValueError):
                self.verify(report, self.requirements, **options)

    def test_family_is_independent_and_legacy_verification_stays_unchanged(self):
        report = self.report()
        self.assertNotIn("requirements_checked", self.verify(report, None))
        value = {"schema_version": 1, "record_type": "A", "required_layers": []}
        self.assertTrue(self.verify(report, json.dumps(value).encode())["requirements_checked"])
        value["record_type"] = "AAAA"
        with self.assertRaises(ValueError): self.verify(report, json.dumps(value).encode())

    def test_invalid_contracts_and_duplicate_fields_reject(self):
        original = json.loads(self.requirements)
        invalid = [dict(original, schema_version=True), dict(original, schema_version=1.0),
                   dict(original, record_type="ANY"), dict(original, required_layers=True),
                   dict(original, required_layers=["risk_review", "risk_review"]),
                   dict(original, required_layers=[{}]), dict(original, required_layers=["unknown"]),
                   dict(original, extra="ignored"), {"schema_version": 1}]
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.verify(self.report(include_queue=True, **self.options), json.dumps(value).encode(), **self.options)
        with self.assertRaises(ValueError): self.verify(self.report(), b'{"schema_version":1,"schema_version":1}')
        with self.assertRaises(ValueError): self.verify(self.report(), b" " * (1024 * 1024 + 1))

    def test_matching_requirements_never_replace_full_reproduction(self):
        report = self.report(include_queue=True, **self.options)
        report["review"]["finding_count"] = 0
        with self.assertRaises(ValueError): self.verify(report, self.requirements, **self.options)

    @unittest.skipUnless(os.name == "posix", "bounded local file reads require POSIX")
    def test_cli_missing_layer_has_no_success_or_private_error_and_preserves_inputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            documents = [json.dumps(self.report()).encode(), *self.inputs, self.requirements]
            files = []
            for index, data in enumerate(documents):
                path = root / str(index)
                path.write_bytes(data)
                files.append(path)
            args = [str(files[0]), str(files[1]), str(files[2]), "--scope", str(files[3]),
                    "--policy", str(files[4]), "--requirements", str(files[5])]
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr): self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), "")
            for private in (directory, "web.example.test", "risk_review"):
                self.assertNotIn(private, stderr.getvalue())
            self.assertEqual([path.read_bytes() for path in files], documents)
