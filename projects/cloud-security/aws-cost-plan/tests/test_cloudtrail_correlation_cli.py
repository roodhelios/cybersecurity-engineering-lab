from __future__ import annotations

import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

from aws_cost_plan.cloudtrail_correlation_cli import main


def failed(event_id: str, timestamp: str) -> dict[str, object]:
    return {
        "eventID": event_id,
        "eventTime": timestamp,
        "eventSource": "signin.amazonaws.com",
        "eventName": "ConsoleLogin",
        "sourceIPAddress": "192.0.2.10",
        "userIdentity": {"type": "IAMUser", "userName": "fixture-user"},
        "responseElements": {"ConsoleLogin": "Failure"},
        "additionalEventData": {"MFAUsed": "No"},
    }


class CloudTrailCorrelationCliTests(unittest.TestCase):
    def test_cli_writes_deterministic_candidate_file_without_overwrite(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "events.jsonl"
            output = root / "candidates.json"
            source.write_text("\n".join(json.dumps(item) for item in (
                failed("id-2", "2026-09-29T10:02:00Z"),
                failed("id-1", "2026-09-29T10:00:00Z"),
                failed("id-3", "2026-09-29T10:01:00Z"),
            )), encoding="utf-8")
            status = main([str(source), "--output", str(output)])
            before = output.read_text(encoding="utf-8")
            errors = StringIO()
            with redirect_stderr(errors):
                overwrite = main([str(source), "--output", str(output)])
        document = json.loads(before)
        self.assertEqual((status, overwrite), (0, 2))
        self.assertEqual(document["candidates"][0]["event_ids"], ["id-1", "id-2", "id-3"])
        self.assertIn("output already exists", errors.getvalue())

    def test_cli_rejects_malformed_and_non_object_lines(self):
        for line in ("not-json", "[]"):
            with self.subTest(line=line), tempfile.TemporaryDirectory() as directory:
                source = Path(directory) / "events.jsonl"
                source.write_text(line + "\n", encoding="utf-8")
                errors = StringIO()
                with redirect_stderr(errors):
                    status = main([str(source)])
                self.assertEqual(status, 2)
                self.assertIn("line 1", errors.getvalue())

    def test_cli_reports_empty_successful_document(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            source.write_text("", encoding="utf-8")
            output = StringIO()
            with redirect_stdout(output):
                status = main([str(source)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue()), {"schema_version": 1, "candidates": []})


if __name__ == "__main__":
    unittest.main()
