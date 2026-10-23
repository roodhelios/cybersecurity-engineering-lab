import hashlib
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from neighbor_import import import_snapshots, main


@unittest.skipUnless(os.name == "posix", "private snapshot files require POSIX")
class NeighborReceiptTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)
        self.before = self.root / "before.json"
        self.after = self.root / "after.json"
        self.before.write_bytes((PROJECT / "examples/neighbors-before.json").read_bytes())
        self.after.write_bytes((PROJECT / "examples/neighbors-after.json").read_bytes())
        self.snapshots = [("2026-10-23T05:00:00Z", self.before),
                          ("2026-10-23T05:01:00Z", self.after)]
        self.args = ["--snapshot", self.snapshots[0][0], str(self.before),
                     "--snapshot", self.snapshots[1][0], str(self.after)]

    def test_receipt_binds_exact_bytes_and_generated_observation_lines(self):
        rendered, receipt = import_snapshots(self.snapshots)
        self.assertEqual(receipt["observations_sha256"], hashlib.sha256(rendered.encode()).hexdigest())
        self.assertEqual(receipt["snapshots"][0]["input_sha256"],
                         hashlib.sha256(self.before.read_bytes()).hexdigest())
        self.assertEqual(receipt["observation_references"], [
            {"observation_line": 1, "snapshot_index": 1, "source_row": 1},
            {"observation_line": 2, "snapshot_index": 2, "source_row": 1}])
        self.assertEqual(receipt["unresolved_count"], 1)
        self.assertNotIn(str(self.root), json.dumps(receipt))
        self.assertNotIn("192.0.2.10", json.dumps(receipt))

    def test_reference_rows_follow_normalized_sorting(self):
        rows = json.loads(self.before.read_bytes())
        rows.reverse()
        self.before.write_text(json.dumps(rows))
        _, receipt = import_snapshots(self.snapshots)
        self.assertEqual(receipt["observation_references"][0]["source_row"], 2)

    def test_private_receipt_then_verified_import_matches_default_output(self):
        receipt_path = self.root / "receipt.json"
        output = self.root / "observations.jsonl"
        with redirect_stderr(StringIO()):
            self.assertEqual(main(self.args + ["--format", "receipt", "--output", str(receipt_path)]), 0)
            self.assertEqual(main(self.args + ["--verify-receipt", str(receipt_path),
                                               "--output", str(output)]), 0)
        rendered, _ = import_snapshots(self.snapshots)
        self.assertEqual(output.read_text(), rendered)
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)

    def test_changed_source_bytes_and_edited_reference_block_output(self):
        _, receipt = import_snapshots(self.snapshots)
        receipt_path = self.root / "receipt.json"
        receipt_path.write_text(json.dumps(receipt))
        original = self.before.read_bytes()
        self.before.write_bytes(original + b"\n")
        self.assert_failed(receipt_path)
        self.before.write_bytes(original)
        receipt["observation_references"][0]["source_row"] = 2
        receipt_path.write_text(json.dumps(receipt))
        self.assert_failed(receipt_path)

    def test_duplicate_fields_and_unknown_receipt_content_fail(self):
        path = self.root / "receipt.json"
        _, receipt = import_snapshots(self.snapshots)
        for data in (json.dumps(receipt)[:-1] + ', "schema_version":1}',
                     json.dumps(dict(receipt, private="private-fixture-marker"))):
            path.write_text(data)
            self.assert_failed(path)

    def assert_failed(self, receipt_path):
        output = self.root / "failed.jsonl"
        stdout, stderr = StringIO(), StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            self.assertEqual(main(self.args + ["--verify-receipt", str(receipt_path),
                                               "--output", str(output)]), 2)
        self.assertEqual(stdout.getvalue(), "")
        self.assertFalse(output.exists())
        self.assertNotIn("private-fixture-marker", stderr.getvalue())


if __name__ == "__main__":
    unittest.main()
