from __future__ import annotations

import io
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from aws_cost_plan.cloudtrail_triage import CloudTrailTriageError, main, triage_event


def event(**changes):
    value = {"eventTime": "2026-09-27T20:00:00Z",
             "eventSource": "signin.amazonaws.com", "eventName": "ConsoleLogin",
             "userIdentity": {"type": "IAMUser"},
             "responseElements": {"ConsoleLogin": "Success"},
             "additionalEventData": {"MFAUsed": "Yes"}}
    value.update(changes)
    return value


class CloudTrailTriageTests(unittest.TestCase):
    def test_login_without_mfa_is_high(self):
        found = triage_event(event(additionalEventData={"MFAUsed": "No"}))
        self.assertEqual((found[0].rule_id, found[0].severity), ("CT002", "high"))

    def test_failed_login_is_medium(self):
        found = triage_event(event(responseElements={"ConsoleLogin": "Failure"}))
        self.assertEqual((found[0].rule_id, found[0].severity), ("CT001", "medium"))

    def test_root_stop_logging_emits_two_findings(self):
        found = triage_event(event(eventSource="cloudtrail.amazonaws.com",
            eventName="StopLogging", userIdentity={"type": "Root"}))
        self.assertEqual([item.rule_id for item in found], ["CT003", "CT004"])

    def test_bad_timestamp_fails_closed(self):
        with self.assertRaisesRegex(CloudTrailTriageError, "ISO 8601"):
            triage_event(event(eventTime="invalid"))

    def test_cli_reports_invalid_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.jsonl"
            path.write_text(json.dumps(event()) + "\n{bad\n", encoding="utf-8")
            errors = io.StringIO()
            with redirect_stderr(errors), redirect_stdout(io.StringIO()):
                status = main([str(path)])
        self.assertEqual(status, 2)
        self.assertIn("line 2", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
