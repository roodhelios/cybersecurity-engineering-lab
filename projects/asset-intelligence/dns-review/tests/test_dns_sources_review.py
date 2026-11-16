"""Aligned source review preserves conflicts, omissions and original row provenance."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dns_sources_review import main, review_sources

ROOT = Path(__file__).resolve().parents[1]
FIRST = (ROOT / "examples/after.json").read_bytes()
SECOND = (ROOT / "examples/alternate-view.json").read_bytes()
SCOPE = (ROOT / "examples/scope.json").read_bytes()


class SourceReviewTests(unittest.TestCase):
    def test_groups_complete_address_sets_and_preserves_physical_rows(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            report = review_sources([FIRST, SECOND, FIRST], SCOPE)
        self.assertEqual(report["status_counts"],
            {"agreement": 1, "disagreement": 1, "single_observation": 1, "not_observed": 1})
        rows = {row["hostname"]: row for row in report["records"]}
        self.assertEqual(rows["web.example.test"]["address_groups"], [
            {"addresses": ["192.0.2.11"], "references": [
                {"source_index": 1, "record_index": 1}, {"source_index": 3, "record_index": 1}]},
            {"addresses": ["192.0.2.12"], "references": [{"source_index": 2, "record_index": 1}]}])
        self.assertEqual(rows["worker.example.test"]["missing_source_indexes"], [1, 3])
        self.assertEqual(rows["unseen.example.test"]["address_groups"], [])
        self.assertEqual(rows["unseen.example.test"]["missing_source_indexes"], [1, 2, 3])
        # Sharing an address with new.example.test never merges worker's identity.
        self.assertEqual(len(rows), 4)
        self.assertEqual(report["sources"][1]["input_sha256"], hashlib.sha256(SECOND).hexdigest())

    def test_identical_bytes_are_explicit_and_not_claimed_to_be_independent(self):
        report = review_sources([FIRST, FIRST], SCOPE)
        self.assertEqual(report["distinct_input_byte_count"], 1)
        self.assertEqual(report["identical_input_groups"], [[1, 2]])
        self.assertEqual(report["status_counts"]["agreement"], 2)
        self.assertIn("not independent sources", report["interpretation"])
        self.assertNotIn("risk_score", json.dumps(report))
        self.assertNotIn("authoritative_source", report)

    def test_equivalent_utc_instant_and_normalized_address_sets_agree(self):
        first = {"schema_version": 1, "observed_at": "2026-10-23T12:00:00Z", "records": [
            {"hostname": "WEB.example.test.", "addresses": ["2001:db8::1", "192.0.2.1"]}]}
        second = {"schema_version": 1, "observed_at": "2026-10-23T08:00:00-04:00", "records": [
            {"hostname": "web.example.test", "addresses": ["192.0.2.1", "2001:0db8:0:0:0:0:0:1"]}]}
        result = review_sources([json.dumps(first).encode(), json.dumps(second).encode()], SCOPE)
        self.assertEqual(result["status_counts"]["agreement"], 1)
        self.assertEqual(result["observed_at"], "2026-10-23T12:00:00+00:00")
        self.assertEqual(result["records"][-2]["hostname"], "web.example.test")

    def test_different_instants_and_invalid_source_counts_fail(self):
        changed = SECOND.replace(b"12:00:00Z", b"12:00:01Z")
        for inputs in ([FIRST], [FIRST] * 9, [FIRST, changed]):
            with self.subTest(count=len(inputs)), self.assertRaises(ValueError):
                review_sources(inputs, SCOPE)
        self.assertEqual(review_sources([FIRST] * 8, SCOPE)["supplied_input_count"], 8)

    def test_invalid_snapshot_contracts_reject_the_complete_review(self):
        invalid = [b'{"schema_version":1,"schema_version":1}',
                   SECOND.replace(b'"schema_version": 1', b'"schema_version": true'),
                   SECOND.replace(b"worker.example.test", b"outside.example.test"),
                   SECOND.replace(b'"192.0.2.12"', b'NaN'),
                   SECOND.replace(b'"192.0.2.12"', b'"invalid-address"'),
                   SECOND.replace(b'"hostname": "web.example.test"',
                                  b'"unexpected": 1, "hostname": "web.example.test"'),
                   b" " * (1024 * 1024 + 1)]
        for source in invalid:
            with self.subTest(prefix=source[:25]), self.assertRaises(ValueError):
                review_sources([FIRST, source], SCOPE)

    @unittest.skipUnless(os.name == "posix", "private file publication requires POSIX")
    def test_cli_publishes_private_complete_report_and_preserves_existing_output(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = [root / "a.json", root / "b.json", root / "scope.json"]
            for path, data in zip(paths, (FIRST, SECOND, SCOPE)):
                path.write_bytes(data)
            output = root / "review.json"
            args = [str(paths[0]), str(paths[1]), "--scope", str(paths[2]), "--output", str(output)]
            stdout = StringIO()
            with redirect_stdout(stdout), patch("socket.socket", side_effect=AssertionError("network forbidden")):
                self.assertEqual(main(args), 0)
            summary = json.loads(stdout.getvalue())
            self.assertEqual(summary["output_sha256"], hashlib.sha256(output.read_bytes()).hexdigest())
            self.assertEqual(json.loads(output.read_bytes()), review_sources([FIRST, SECOND], SCOPE))
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            self.assertNotIn("example.test", stdout.getvalue())
            self.assertNotIn(str(root), stdout.getvalue())
            original = output.read_bytes()
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn(str(root), stderr.getvalue())
            self.assertEqual(output.read_bytes(), original)

    @unittest.skipUnless(os.name == "posix", "no-follow local reads require POSIX")
    def test_malformed_tail_and_symlink_never_publish_a_partial_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            a, b, scope, output = [root / name for name in ("a", "b", "scope", "out")]
            a.write_bytes(FIRST)
            b.write_bytes(SECOND + b"private-invalid-tail")
            scope.write_bytes(SCOPE)
            args = [str(a), str(b), "--scope", str(scope), "--output", str(output)]
            for symlink in (False, True):
                if symlink:
                    b.unlink()
                    b.symlink_to(a)
                with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                    self.assertEqual(main(args), 2)
                self.assertFalse(output.exists())
                self.assertEqual(stdout.getvalue(), "")
                self.assertNotIn("private-invalid-tail", stderr.getvalue())

    def test_cli_rejects_excess_inputs_before_opening_paths(self):
        with patch("dns_sources_review.read_input", side_effect=AssertionError("must not open")):
            with redirect_stderr(StringIO()):
                self.assertEqual(main(["missing"] * 9 + ["--scope", "missing", "--output", "missing"]), 2)

    def test_fresh_standard_library_demo_reports_expected_coverage(self):
        result = subprocess.run([sys.executable, "-S", str(ROOT / "demo_dns_sources.py")],
            capture_output=True, text=True, timeout=10)
        self.assertEqual((result.returncode, result.stderr), (0, ""))
        self.assertEqual(json.loads(result.stdout)["status"], "dns_source_review_exercise_passed")


if __name__ == "__main__":
    unittest.main()
