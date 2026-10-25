import copy
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
from zeek_dns_workflow_verify import main, read_report, verify_workflow


class DNSWorkflowVerifyTests(unittest.TestCase):
    def setUp(self):
        self.inputs = [(ROOT/"examples"/name).read_bytes() for name in (
            "zeek-dns-before.jsonl", "zeek-dns.jsonl", "scope.json", "review-policy.json")]
        self.assessment = (ROOT/"examples/risk-assessments.json").read_bytes()
        self.ownership = (ROOT/"examples/ownership-responses.json").read_bytes()

    def workflow(self, **options):
        return review_logs(*self.inputs, previous_observed_at="2026-10-23T00:00:00Z",
                          current_observed_at="2026-10-24T00:00:00Z", record_type="A", **options)

    def verify(self, report, **options):
        return verify_workflow(json.dumps(report).encode(), *self.inputs, **options)

    def test_basic_and_complete_workflows_reproduce_without_network_or_input_mutation(self):
        for options in ({}, {"assessment_data": self.assessment, "ownership_data": self.ownership}):
            report = self.workflow(include_queue=True, **options); original = copy.deepcopy(report)
            with patch("socket.socket", side_effect=AssertionError("network forbidden")):
                result = self.verify(report, **options)
            self.assertEqual(result["status"], "workflow_reproduced")
            self.assertEqual(result["finding_count"], 1)
            self.assertTrue(result["queue_checked"])
            self.assertEqual(result["risk_review_checked"], bool(options))
            self.assertEqual(report, original)
            for private in ("web.example.test", "192.0.2.11", "web-platform"):
                self.assertNotIn(private, json.dumps(result))

    def test_changes_to_receipts_snapshots_findings_risk_responses_and_queue_reject(self):
        options = {"assessment_data": self.assessment, "ownership_data": self.ownership}
        original = self.workflow(include_queue=True, **options)
        for section in ("imports", "snapshots", "review", "risk_review", "ownership_review", "review_queue"):
            report = copy.deepcopy(original); report[section]["extra"] = "synthetic-change"
            with self.subTest(section=section), self.assertRaises(ValueError): self.verify(report, **options)
        mutations = (
            (("imports", "current", "selected", 0, "source_lines"), [999]),
            (("snapshots", "current", "records", 0, "addresses"), ["192.0.2.99"]),
            (("review", "finding_count"), 0),
            (("risk_review", "findings", 0, "risk_score"), 0),
            (("ownership_review", "findings", 0, "ownership_response", "status"), "declined_claim"),
            (("review_queue", "items", 0, "next_review"), "synthetic-step"),
        )
        for path, value in mutations:
            report = copy.deepcopy(original); target = report
            for field in path[:-1]: target = target[field]
            target[path[-1]] = value
            with self.subTest(path=path), self.assertRaises(ValueError): self.verify(report, **options)
        report = copy.deepcopy(original); report["schema_version"] = True
        with self.assertRaises(ValueError): self.verify(report, **options)

    def test_all_original_input_bytes_and_optional_layer_inputs_are_required(self):
        report = self.workflow(assessment_data=self.assessment, ownership_data=self.ownership)
        raw = json.dumps(report).encode()
        for index in range(4):
            changed = self.inputs.copy(); changed[index] += b"\n"
            with self.assertRaises(ValueError):
                verify_workflow(raw, *changed, assessment_data=self.assessment, ownership_data=self.ownership)
        with self.assertRaises(ValueError): self.verify(report)
        with self.assertRaises(ValueError): self.verify(self.workflow(), assessment_data=self.assessment)
        with self.assertRaises(ValueError):
            self.verify(report, assessment_data=self.assessment+b"\n", ownership_data=self.ownership)
        with self.assertRaises(ValueError):
            self.verify(report, assessment_data=self.assessment, ownership_data=self.ownership+b"\n")

    def test_duplicate_fields_nonfinite_unknown_fields_and_size_bounds_reject(self):
        report = self.workflow()
        report["unexpected"] = 1
        for raw in (json.dumps(report).encode(), b'{"report_type":0,"report_type":1}',
                    b'{"report_type":"zeek-dns-policy-workflow","unexpected":NaN}'):
            with self.assertRaises((ValueError, KeyError)): verify_workflow(raw, *self.inputs)
        with patch("zeek_dns_workflow_verify.MAX_REPORT_BYTES", 1), self.assertRaises(ValueError):
            self.verify(self.workflow())

    @unittest.skipUnless(os.name == "posix", "bounded private input handling requires POSIX")
    def test_cli_preserves_files_and_emits_no_success_or_private_data_on_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); report = root/"workflow.json"
            report.write_text(json.dumps(self.workflow()))
            sources = []
            for index, data in enumerate(self.inputs):
                path = root/str(index); path.write_bytes(data); sources.append(path)
            args = [str(report), str(sources[0]), str(sources[1]), "--scope", str(sources[2]), "--policy", str(sources[3])]
            before = {p: p.read_bytes() for p in [report, *sources]}; stdout = StringIO()
            with redirect_stdout(stdout): self.assertEqual(main(args), 0)
            self.assertEqual(json.loads(stdout.getvalue())["status"], "workflow_reproduced")
            self.assertEqual(before, {p: p.read_bytes() for p in before})
            report.write_bytes(b"private-fixture-marker"); stdout = StringIO(); stderr = StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr): self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), ""); self.assertNotIn("private-fixture-marker", stderr.getvalue())
            link = root/"link"; link.symlink_to(report)
            with self.assertRaises(OSError): read_report(link)
