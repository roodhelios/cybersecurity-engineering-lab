from __future__ import annotations

import unittest

from aws_cost_plan.cloudtrail_correlation import (
    CloudTrailCorrelationError,
    correlate_failed_logins,
)


def failed(minute: int, user="fixture-user", source="192.0.2.10"):
    return {
        "eventTime": f"2026-09-28T20:{minute:02d}:00Z",
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": source,
        "userIdentity": {"type": "IAMUser", "userName": user},
        "responseElements": {"ConsoleLogin": "Failure"},
        "additionalEventData": {"MFAUsed": "No"},
    }


class CloudTrailCorrelationTests(unittest.TestCase):
    def test_threshold_in_one_window_emits_candidate(self):
        found = correlate_failed_logins([failed(4), failed(0), failed(2)])
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].failure_count, 3)
        self.assertEqual(found[0].principal, "fixture-user")

    def test_events_outside_window_do_not_match(self):
        self.assertEqual(correlate_failed_logins(
            [failed(0), failed(6), failed(12)], window_seconds=300
        ), ())

    def test_principals_and_sources_are_not_combined(self):
        events = [failed(0), failed(1), failed(2, source="192.0.2.11")]
        self.assertEqual(correlate_failed_logins(events), ())

    def test_missing_correlation_key_fails_closed(self):
        event = failed(0)
        del event["sourceIPAddress"]
        with self.assertRaisesRegex(CloudTrailCorrelationError, "sourceIPAddress"):
            correlate_failed_logins([event, event, event])

    def test_bounds_are_enforced_before_processing(self):
        for changes, message in (({"threshold": 1}, "threshold"),
                                 ({"window_seconds": 3601}, "window_seconds")):
            with self.subTest(message=message), self.assertRaisesRegex(
                    CloudTrailCorrelationError, message):
                correlate_failed_logins([], **changes)


if __name__ == "__main__":
    unittest.main()
