import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
import neighbor_import
from arp_consistency import review_lines


def snapshot(**changes):
    row = {"dst": "192.0.2.10", "dev": "lab0",
           "lladdr": "02:00:00:00:00:10", "state": ["REACHABLE"]}
    row.update(changes)
    return json.dumps([row]).encode()


class SnapshotConversionTests(unittest.TestCase):
    def test_normalizes_timestamp_and_mac_for_existing_review_contract(self):
        records, skipped = neighbor_import.convert_snapshot(
            snapshot(lladdr="02:AA:00:00:00:10"), "2026-10-23T01:00:00-04:00")
        self.assertEqual(records[0]["timestamp"], "2026-10-23T05:00:00+00:00")
        self.assertEqual(records[0]["mac"], "02:aa:00:00:00:10")
        self.assertEqual(skipped, 0)

    def test_only_explicit_unresolved_rows_can_omit_mac(self):
        for state in ("INCOMPLETE", "FAILED"):
            data = json.dumps([{"dst": "192.0.2.10", "dev": "lab0", "state": [state]}]).encode()
            self.assertEqual(neighbor_import.convert_snapshot(data, "2026-10-23T05:00:00Z"), ([], 1))
        with self.assertRaises(ValueError):
            neighbor_import.convert_snapshot(b'[{"dst":"192.0.2.10","dev":"lab0"}]',
                                             "2026-10-23T05:00:00Z")

    def test_ambiguous_duplicate_ipv6_and_oversized_inputs_fail(self):
        row = json.loads(snapshot())[0]
        inputs = [json.dumps([row, row]).encode(), snapshot(dst="2001:db8::1"),
                  b'[{"dst":"192.0.2.10","dst":"192.0.2.11"}]', b"{}"]
        for data in inputs:
            with self.subTest(data=data), self.assertRaises(ValueError):
                neighbor_import.convert_snapshot(data, "2026-10-23T05:00:00Z")
        with patch.object(neighbor_import, "MAX_SNAPSHOT_BYTES", 1), self.assertRaises(ValueError):
            neighbor_import.convert_snapshot(snapshot(), "2026-10-23T05:00:00Z")


@unittest.skipUnless(os.name == "posix", "private import requires POSIX")
class SnapshotCliTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.output = self.root / "observations.jsonl"
        self.arguments = [
            "--snapshot", "2026-10-23T05:00:00Z", str(PROJECT / "examples/neighbors-before.json"),
            "--snapshot", "2026-10-23T05:01:00Z", str(PROJECT / "examples/neighbors-after.json"),
        ]

    def test_fixture_import_feeds_the_review_and_private_file(self):
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(neighbor_import.main(self.arguments), 0)
        report = review_lines(stdout.getvalue().splitlines())
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["elapsed_seconds"], 60)
        self.assertIn("skipped 1 unresolved rows", stderr.getvalue())
        with redirect_stderr(StringIO()):
            self.assertEqual(neighbor_import.main(self.arguments + ["--output", str(self.output)]), 0)
        self.assertEqual(self.output.read_text(), stdout.getvalue())
        self.assertEqual(self.output.stat().st_mode & 0o777, 0o600)

    def test_existing_file_and_invalid_tail_preserve_output(self):
        self.output.write_text("keep existing content")
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            self.assertEqual(neighbor_import.main(self.arguments + ["--output", str(self.output)]), 2)
        self.assertEqual(self.output.read_text(), "keep existing content")
        bad = self.root / "bad.json"
        bad.write_text("private-fixture-marker")
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(neighbor_import.main(self.arguments + [
                "--snapshot", "2026-10-23T05:02:00Z", str(bad)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertNotIn("private-fixture-marker", stderr.getvalue())

    def test_backward_times_and_snapshot_limit_fail(self):
        repeated = self.arguments[:3] + self.arguments[:3]
        for arguments in (repeated, self.arguments[3:] + self.arguments[:3]):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(neighbor_import.main(arguments), 2)
        with patch.object(neighbor_import, "MAX_SNAPSHOTS", 1):
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(neighbor_import.main(self.arguments), 2)

    def test_combined_observation_limit_prevents_partial_output(self):
        stdout = StringIO()
        arguments = self.arguments + ["--snapshot", "2026-10-23T05:02:00Z",
                                      str(PROJECT / "examples/neighbors-after.json")]
        with patch.object(neighbor_import, "MAX_RECORDS", 2):
            with redirect_stdout(stdout), redirect_stderr(StringIO()):
                self.assertEqual(neighbor_import.main(arguments), 2)
        self.assertEqual(stdout.getvalue(), "")

    def test_symlink_and_fifo_are_rejected_without_waiting(self):
        link = self.root / "link.json"
        link.symlink_to(PROJECT / "examples/neighbors-before.json")
        fifo = self.root / "fifo.json"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                neighbor_import.read_snapshot(path)


if __name__ == "__main__":
    unittest.main()
