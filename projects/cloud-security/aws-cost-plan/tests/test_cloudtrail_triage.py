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

    def test_logging_outcome_for_both_actions_and_error_locations(self):
        for action in ("StopLogging", "DeleteTrail"):
            base = event(eventSource="cloudtrail.amazonaws.com", eventName=action,
                         responseElements=None)
            found = triage_event(base)[0]
            self.assertEqual((found.rule_id, found.severity), ("CT003", "critical"))
            self.assertIn("no recorded error", found.message)
            for location in ("top", "response"):
                for field in ("errorCode", "errorMessage"):
                    with self.subTest(action=action, location=location, field=field):
                        changed = dict(base)
                        error = {field: "sensitive-service-detail"}
                        changed.update(error if location == "top" else {"responseElements": error})
                        found = triage_event(changed)[0]
                        self.assertEqual(found.severity, "medium")
                        self.assertIn("attempt returned an error", found.message)
                        self.assertNotIn("sensitive-service-detail", found.message)

    def test_failed_root_attempt_still_emits_root_finding(self):
        found = triage_event(event(eventSource="cloudtrail.amazonaws.com",
            eventName="StopLogging", errorCode="AccessDenied",
            userIdentity={"type": "Root"}))
        self.assertEqual([(item.rule_id, item.severity) for item in found],
                         [("CT003", "medium"), ("CT004", "high")])

    def test_malformed_logging_error_is_not_treated_as_success(self):
        for field in ("errorCode", "errorMessage"):
            for value in (None, "", " ", 123, [], {}):
                for nested in (False, True):
                    changes = {field: value} if not nested else {"responseElements": {field: value}}
                    with self.subTest(field=field, value=value, nested=nested):
                        with self.assertRaises(CloudTrailTriageError):
                            triage_event(event(eventSource="cloudtrail.amazonaws.com",
                                eventName="DeleteTrail", **changes))
        with self.assertRaises(CloudTrailTriageError):
            triage_event(event(eventSource="cloudtrail.amazonaws.com",
                eventName="StopLogging", responseElements=[]))

    def test_cli_classifies_outcomes_without_echoing_error_text(self):
        output = io.StringIO()
        fixture = Path(__file__).resolve().parents[1] / "examples/cloudtrail-logging-outcomes.jsonl"
        with redirect_stdout(output):
            self.assertEqual(main([str(fixture)]), 1)
        findings = json.loads(output.getvalue())["findings"]
        self.assertEqual([item["severity"] for item in findings],
                         ["medium", "critical", "medium"])
        self.assertEqual([item["line"] for item in findings], [1, 2, 3])
        self.assertNotIn("AccessDenied", output.getvalue())

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
