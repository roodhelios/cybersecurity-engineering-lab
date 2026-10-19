"""Review saved reports against retained inputs rather than trusting their hashes."""

import copy
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from event_normalizer.correlation_cli import correlate_jsonl
from event_normalizer.evidence_verify import main, verify_report

FIXTURE = Path(__file__).parent / "fixtures" / "repeated_attempts.jsonl"


class EvidenceVerifyTests(unittest.TestCase):
    def setUp(self):
        self.text = FIXTURE.read_text()
        self.report = correlate_jsonl(StringIO(self.text), include_evidence=True)

    def test_complete_report_reproduces(self):
        result = verify_report(StringIO(self.text), self.report)
        self.assertEqual(result, {"schema_version": 1, "status": "reproduced",
                                 "events_read": 4, "finding_count": 1, "evidence_references": 4})

    def test_finding_reference_and_metadata_changes_fail(self):
        for change in (lambda r: r.update(events_read=5),
                       lambda r: r["findings"][0].update(technique_id="T0000"),
                       lambda r: r["findings"][0]["evidence"][0].update(line_number=2),
                       lambda r: r["findings"][0]["evidence"][0].update(event_sha256="0" * 64),
                       lambda r: r["findings"].clear(),
                       lambda r: r.update(extra="not in contract"),
                       lambda r: r.update(finding_count=True)):
            with self.subTest(change=change):
                report = copy.deepcopy(self.report)
                change(report)
                with self.assertRaises(ValueError):
                    verify_report(StringIO(self.text), report)

    def test_changed_input_and_inserted_blank_line_fail(self):
        for text in ("\n" + self.text, self.text.replace('"S0"', '"SF"')):
            with self.assertRaises(ValueError):
                verify_report(StringIO(text), self.report)

    def test_json_key_order_and_spacing_do_not_matter(self):
        text = "\n".join(json.dumps(json.loads(line), sort_keys=True) for line in self.text.splitlines())
        self.assertEqual(verify_report(StringIO(text), self.report)["status"], "reproduced")

    def test_empty_report_and_old_contract(self):
        report = correlate_jsonl(StringIO(""), include_evidence=True)
        self.assertEqual(verify_report(StringIO(""), report)["finding_count"], 0)
        for value in ([], {}, dict(report, schema_version=True), dict(report, schema_version=1)):
            with self.assertRaises(ValueError):
                verify_report(StringIO(""), value)

    def test_cli_success_and_duplicate_invalid_oversized_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text(json.dumps(self.report))
            output = StringIO()
            with redirect_stdout(output):
                self.assertEqual(main([str(FIXTURE), str(path)]), 0)
            self.assertEqual(json.loads(output.getvalue())["status"], "reproduced")
            for text in ('{"schema_version":2,"schema_version":2}', 'not-json', '[]'):
                path.write_text(text)
                output = StringIO()
                with redirect_stdout(output), redirect_stderr(StringIO()):
                    self.assertEqual(main([str(FIXTURE), str(path)]), 2)
                self.assertEqual(output.getvalue(), "")
            path.write_text(json.dumps(self.report))
            with patch("event_normalizer.evidence_verify.MAX_REPORT_BYTES", 8):
                with redirect_stderr(StringIO()):
                    self.assertEqual(main([str(FIXTURE), str(path)]), 2)


if __name__ == "__main__":
    unittest.main()
