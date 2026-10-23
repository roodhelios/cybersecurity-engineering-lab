import importlib.util
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from dns_review import compare
from zeek_dns_import import import_dns, main

SCOPE = json.dumps({"schema_version": 1, "scope": "synthetic",
                    "allowed_hosts": ["web.example.test"]}).encode()
END = "2026-10-23T00:00:00Z"


def row(**values):
    return dict({"query": "WEB.example.test.", "ts": 1700000000, "qtype": 1,
                 "qclass": 1, "rcode": 0, "TC": False, "rejected": False,
                 "answers": ["192.0.2.10"]}, **values)


def log(*rows):
    return b"\n".join(json.dumps(item).encode() for item in rows)


class ZeekImportTests(unittest.TestCase):
    def run_import(self, *rows, **options):
        return import_dns(log(*rows), SCOPE, observed_at=END,
                          record_type=options.get("record_type", "A"))

    def test_latest_transaction_not_union_and_snapshot_runs_in_comparison(self):
        before, _ = self.run_import(row())
        after, receipt = self.run_import(row(ts=1700000001, answers=["192.0.2.11"]), row())
        before["observed_at"] = "2026-10-22T00:00:00Z"
        result = compare(json.dumps(before).encode(), json.dumps(after).encode(), SCOPE)
        self.assertEqual(result["records"][0]["addresses_added"], ["192.0.2.11"])
        self.assertEqual(receipt["selected"][0]["source_lines"], [1])
        self.assertEqual(receipt["rows_read"], 2)

    def test_negative_latest_never_falls_back_to_an_earlier_positive_answer(self):
        for changed in [row(ts=1700000001, rcode=3), row(ts=1700000001, TC=True),
                        row(ts=1700000001, rejected=True), row(ts=1700000001, answers=[]),
                        row(ts=1700000001, answers=["alias.example.test", "192.0.2.11"])]:
            with self.subTest(changed=changed):
                snapshot, receipt = self.run_import(row(), changed)
                self.assertEqual(snapshot["records"], [])
                self.assertEqual(receipt["omitted_latest"][0]["source_lines"], [2])

    def test_explicit_family_scope_and_equal_timestamp_ambiguity(self):
        snapshot, receipt = self.run_import(row(query="outside.example.test"),
            row(), row(qtype=28, answers=["2001:db8::1"]), record_type="AAAA")
        self.assertEqual(snapshot["records"][0]["addresses"], ["2001:db8::1"])
        self.assertEqual(receipt["filtered_rows"], {"out_of_scope": 1, "other_record_type": 1})
        with self.assertRaises(ValueError):
            self.run_import(row(), row(answers=["192.0.2.11"]))
        _, receipt = self.run_import(row(), row())
        self.assertEqual(receipt["selected"][0]["source_lines"], [1, 2])

    def test_invalid_rows_bounds_and_unknown_metadata(self):
        for changed in [row(ts=True), row(ts=float("nan")), row(ts=99999999999),
                        row(qclass=True), row(TC="F"), row(rcode=True), row(qtype_name="AAAA"),
                        row(answers=[123]), row(answers=["192.0.2.1"] * 33)]:
            with self.assertRaises((ValueError, OverflowError)):
                self.run_import(changed)
        snapshot, receipt = self.run_import(row(extra_private_field="private-fixture-marker"))
        self.assertNotIn("private-fixture-marker", json.dumps([snapshot, receipt]))
        with self.assertRaises(ValueError):
            import_dns(b'{"query":"web.example.test","query":"duplicate"}', SCOPE,
                       observed_at=END, record_type="A")
        with self.assertRaises(ValueError):
            self.run_import(*[row()] * 1001)

    @unittest.skipUnless(os.name == "posix", "private outputs require POSIX")
    def test_cli_private_output_no_overwrite_and_invalid_tail_no_partial_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source, scope, output = root/"dns.jsonl", root/"scope.json", root/"snapshot.json"
            source.write_bytes(log(row())); scope.write_bytes(SCOPE)
            args = [str(source), "--scope", str(scope), "--observed-at", END,
                    "--record-type", "A", "--output", str(output)]
            with redirect_stdout(StringIO()):
                self.assertEqual(main(args), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            original = output.read_bytes()
            with redirect_stderr(StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), original)
            output.unlink(); source.write_bytes(log(row()) + b"\nprivate-fixture-marker")
            error, stdout = StringIO(), StringIO()
            with redirect_stderr(error), redirect_stdout(stdout):
                self.assertEqual(main(args), 2)
            self.assertFalse(output.exists()); self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("private-fixture-marker", error.getvalue())


if __name__ == "__main__":
    unittest.main()
