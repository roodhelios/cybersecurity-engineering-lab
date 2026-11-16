"""Recipient pins and full reproduction bind the ordered source-review handoff."""

from contextlib import redirect_stderr, redirect_stdout
import hashlib
from io import StringIO
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dns_sources_review import review_sources
import dns_sources_verify as verifier

EXAMPLES = Path(__file__).resolve().parents[1] / "examples"


def digest(data):
    return hashlib.sha256(data).hexdigest()


class SourceRecipientTests(unittest.TestCase):
    def setUp(self):
        self.snapshots = [(EXAMPLES / name).read_bytes() for name in ("after.json", "alternate-view.json")]
        self.scope = (EXAMPLES / "scope.json").read_bytes()
        self.report = json.dumps(review_sources(self.snapshots, self.scope), sort_keys=True).encode()
        self.pins = dict(expected_report_sha256=digest(self.report),
                         expected_input_sha256=list(map(digest, self.snapshots)),
                         expected_scope_sha256=digest(self.scope))

    def test_complete_report_reproduces_without_echoing_private_claims(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = verifier.verify_sources(self.report, self.snapshots, self.scope, **self.pins)
        self.assertEqual(result["status"], "dns_source_review_reproduced")
        self.assertEqual(result["status_counts"], review_sources(self.snapshots, self.scope)["status_counts"])
        self.assertNotIn("example.test", json.dumps(result))
        self.assertNotIn("192.0.2.", json.dumps(result))

    def test_every_pin_is_checked_before_parsing_or_reproduction(self):
        for key in self.pins:
            pins = dict(self.pins)
            pins[key] = ["0" * 64] * 2 if key == "expected_input_sha256" else "0" * 64
            with self.subTest(key=key), patch.object(verifier.json, "loads", side_effect=AssertionError("no parse")):
                with self.assertRaises(ValueError):
                    verifier.verify_sources(self.report, self.snapshots, self.scope, **pins)

    def test_order_and_changed_original_bytes_cannot_be_rebound_to_an_old_report(self):
        variants = [list(reversed(self.snapshots)), [self.snapshots[0] + b"\n", self.snapshots[1]]]
        for snapshots in variants:
            for repin in (False, True):
                pins = dict(self.pins)
                if repin:
                    pins["expected_input_sha256"] = list(map(digest, snapshots))
                with self.subTest(repin=repin), self.assertRaises(ValueError):
                    verifier.verify_sources(self.report, snapshots, self.scope, **pins)
        with self.assertRaises(ValueError):
            verifier.verify_sources(self.report, self.snapshots, self.scope + b"\n", **self.pins)

    def test_changed_counts_references_types_and_unknown_fields_fail_even_with_outer_repin(self):
        for kind in ("count", "reference", "type", "unknown"):
            document = json.loads(self.report)
            if kind == "count": document["status_counts"]["agreement"] += 1
            elif kind == "reference": document["records"][0]["address_groups"][0]["references"][0]["record_index"] += 1
            elif kind == "type": document["schema_version"] = True
            else: document["extra"] = "not accepted"
            data = json.dumps(document).encode()
            pins = dict(self.pins, expected_report_sha256=digest(data))
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                verifier.verify_sources(data, self.snapshots, self.scope, **pins)

    def test_ambiguous_nonfinite_and_malformed_reports_are_rejected(self):
        bad = [b"\xff", b"{" * 1500, self.report.replace(b"{", b'{"schema_version": 1,', 1),
               self.report.replace(b"{", b'{"extra": NaN,', 1),
               self.report.replace(b"{", b'{"extra": 1e999,', 1)]
        for data in bad:
            with self.subTest(prefix=data[:20]), self.assertRaises((ValueError, RecursionError)):
                verifier.verify_sources(data, self.snapshots, self.scope,
                    **dict(self.pins, expected_report_sha256=digest(data)))

    def test_input_count_and_pin_shape_are_not_inferred_from_report(self):
        for pins in ([digest(self.snapshots[0])], [None, None], ["A" * 64] * 2):
            with self.subTest(pins=pins), self.assertRaises(ValueError):
                verifier.verify_sources(self.report, self.snapshots, self.scope,
                    **dict(self.pins, expected_input_sha256=pins))

    @unittest.skipUnless(os.name == "posix", "private bounded file reads require POSIX")
    def test_cli_is_read_only_and_rejects_report_pin_before_opening_originals(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report, scope, first, second = [root / name for name in ("report", "scope", "first", "second")]
            for path, data in zip((report, scope, first, second), (self.report, self.scope, *self.snapshots)):
                path.write_bytes(data)
            before = {p.name: p.read_bytes() for p in root.iterdir()}
            arguments = [str(report), str(first), str(second), "--scope", str(scope),
                "--expected-report-sha256", self.pins["expected_report_sha256"],
                "--expected-scope-sha256", self.pins["expected_scope_sha256"]]
            for pin in self.pins["expected_input_sha256"]:
                arguments.extend(["--expected-input-sha256", pin])
            with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
                self.assertEqual(verifier.main(arguments), 0)
            self.assertEqual(errors.getvalue(), "")
            self.assertEqual(json.loads(output.getvalue())["status"], "dns_source_review_reproduced")
            self.assertEqual(before, {p.name: p.read_bytes() for p in root.iterdir()})
            arguments[arguments.index("--expected-report-sha256") + 1] = "0" * 64
            with patch.object(verifier, "read_input", side_effect=AssertionError("originals must not open")):
                with redirect_stdout(StringIO()) as output, redirect_stderr(StringIO()) as errors:
                    self.assertEqual(verifier.main(arguments), 2)
            self.assertEqual(output.getvalue(), "")
            self.assertNotIn(str(root), errors.getvalue())

    @unittest.skipUnless(os.name == "posix", "bounded no-follow reads require POSIX")
    def test_report_bounds_and_special_paths_fail_without_hanging(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "report"
            report.write_bytes(self.report)
            with patch.object(verifier, "MAX_REPORT_BYTES", len(self.report)):
                self.assertEqual(verifier._read_report(report), self.report)
                report.write_bytes(self.report + b"\n")
                with self.assertRaises(ValueError): verifier._read_report(report)
            report.unlink()
            report.symlink_to(EXAMPLES / "after.json")
            with self.assertRaises(OSError): verifier._read_report(report)
            report.unlink()
            report.mkdir()
            with self.assertRaises((OSError, ValueError)): verifier._read_report(report)
            report.rmdir()
            os.mkfifo(report)
            with self.assertRaises(ValueError): verifier._read_report(report)


if __name__ == "__main__":
    unittest.main()
