"""Exercise native envelope imports through the existing triage and handoff paths."""

import gzip
import hashlib
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from aws_cost_plan.cloudtrail_import import convert_records, main
from aws_cost_plan.cloudtrail_handoff import build_handoff
from aws_cost_plan.cloudtrail_correlation import correlate_failed_logins

ROOT = Path(__file__).resolve().parents[1]


class CloudTrailImportTests(unittest.TestCase):
    def setUp(self):
        self.events = [json.loads(line) for line in (ROOT / "examples/cloudtrail-events.jsonl").read_text().splitlines() if line.strip()]
        for number, event in enumerate(self.events, 1):
            event["eventID"] = f"synthetic-import-{number}"
        self.raw = json.dumps({"Records": self.events}).encode()

    def test_plain_and_gzip_keep_all_fields_and_feed_handoff_and_correlation(self):
        self.events[0]["unreviewed_extension"] = {"label": "synthetic"}
        raw = json.dumps({"Records": self.events}).encode()
        plain, receipt = convert_records(raw)
        zipped, compressed = convert_records(gzip.compress(raw, mtime=0))
        self.assertEqual(plain, zipped)
        self.assertEqual([json.loads(line) for line in plain.splitlines()], self.events)
        self.assertNotEqual(receipt["input_sha256"], compressed["input_sha256"])
        self.assertEqual(receipt["normalized_sha256"], hashlib.sha256(plain.encode()).hexdigest())
        handoff = build_handoff(plain.encode(), case_id="import-test", scope_note="synthetic")
        self.assertEqual(handoff["event_count"], len(self.events))
        self.assertEqual(correlate_failed_logins([json.loads(line) for line in plain.splitlines()]),
                         correlate_failed_logins(self.events))

    def test_malformed_envelopes_records_and_duplicates_fail(self):
        values = [[], {}, {"Records": None}, {"Records": [1]},
                  {"Records": self.events + [self.events[0]]},
                  {"Records": self.events + [{"eventID": "bad"}]},
                  {"Records": [], "unexpected": True}]
        for value in values:
            with self.subTest(value=type(value).__name__), self.assertRaises(ValueError):
                convert_records(json.dumps(value).encode())
        for raw in (b'{"Records":[],"Records":[]}', b'{"Records":[{"x":NaN}]}', b'\xff', b'\x1f\x8btruncated'):
            with self.subTest(raw=raw[:2]), self.assertRaises((ValueError, OSError, EOFError)):
                convert_records(raw)

    def test_expansion_line_and_count_limits(self):
        with patch("aws_cost_plan.cloudtrail_import.MAX_BYTES", 100), self.assertRaises(ValueError):
            convert_records(gzip.compress(b" " * 101, mtime=0))
        with patch("aws_cost_plan.cloudtrail_import.MAX_EVENTS", 1), self.assertRaises(ValueError):
            convert_records(self.raw)
        with patch("aws_cost_plan.cloudtrail_import.MAX_LINE", 10), self.assertRaises(ValueError):
            convert_records(self.raw)

    def test_corrupt_gzip_trailer_and_nested_duplicate_fields_fail(self):
        corrupted = bytearray(gzip.compress(self.raw, mtime=0))
        corrupted[-8] ^= 1
        with self.assertRaises(OSError):
            convert_records(bytes(corrupted))
        with self.assertRaises(ValueError):
            convert_records(b'{"Records":[{"eventID":"a","eventID":"b"}]}')

    @unittest.skipUnless(os.name == "posix", "private file publication requires POSIX")
    def test_cli_is_private_exclusive_and_never_publishes_partial_input(self):
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "input.json.gz", Path(directory) / "events.jsonl"
            source.write_bytes(gzip.compress(self.raw, mtime=0))
            before = source.read_bytes()
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                self.assertEqual(main([str(source), "--output", str(output)]), 0)
            self.assertEqual(json.loads(stdout.getvalue())["event_count"], len(self.events))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            original = output.read_bytes()
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), "--output", str(output)]), 2)
            self.assertEqual(output.read_bytes(), original)
            self.assertEqual(source.read_bytes(), before)
            source.write_bytes(self.raw[:-1])
            output.unlink()
            stdout = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(io.StringIO()):
                self.assertEqual(main([str(source), "--output", str(output)]), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
