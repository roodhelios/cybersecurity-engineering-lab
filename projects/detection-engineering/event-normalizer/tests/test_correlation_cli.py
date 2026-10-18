"""Exercise the local correlation command and its batch limits."""

import json
import sys
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from event_normalizer.correlation_cli import correlate_jsonl, main
from event_normalizer.cli import JsonlInputError


FIXTURE = Path(__file__).parent / "fixtures" / "repeated_attempts.jsonl"


class CorrelationCliTests(unittest.TestCase):
    def test_file_command_reports_candidate_without_raw_records(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(FIXTURE)]), 0)
        report = json.loads(output.getvalue())
        self.assertEqual((report["events_read"], report["finding_count"]), (4, 1))
        self.assertEqual(report["findings"][0]["attempt_count"], 4)
        self.assertEqual(report["findings"][0]["technique_id"], "T1046")
        self.assertNotIn("raw", output.getvalue())

    def test_stdin_and_file_have_identical_results(self):
        output = StringIO()
        with patch("sys.stdin", StringIO(FIXTURE.read_text())), redirect_stdout(output):
            self.assertEqual(main([]), 0)
        self.assertEqual(json.loads(output.getvalue()), correlate_jsonl(StringIO(FIXTURE.read_text())))

    def test_empty_batch_has_no_findings(self):
        self.assertEqual(correlate_jsonl(StringIO("\n"))["finding_count"], 0)

    def test_malformed_tail_has_line_number_and_no_partial_report(self):
        output, errors = StringIO(), StringIO()
        with patch("sys.stdin", StringIO(FIXTURE.read_text() + "not-json\n")):
            with redirect_stdout(output), redirect_stderr(errors):
                self.assertEqual(main([]), 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("<stdin>:5:", errors.getvalue())

    def test_event_count_and_line_limits_reject_excess(self):
        with patch("event_normalizer.correlation_cli.MAX_EVENTS", 3):
            with self.assertRaisesRegex(JsonlInputError, "batch exceeds"):
                correlate_jsonl(StringIO(FIXTURE.read_text()))
        with patch("event_normalizer.correlation_cli.MAX_LINE_CHARS", 10):
            with self.assertRaisesRegex(JsonlInputError, "line exceeds"):
                correlate_jsonl(StringIO(" " * 11))

    def test_invalid_utf8_and_missing_paths_return_two(self):
        with patch("pathlib.Path.open", side_effect=UnicodeError("invalid UTF-8")):
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["fixture.jsonl"]), 2)
        with redirect_stderr(StringIO()):
            self.assertEqual(main([str(FIXTURE / "missing")]), 2)


if __name__ == "__main__":
    unittest.main()
