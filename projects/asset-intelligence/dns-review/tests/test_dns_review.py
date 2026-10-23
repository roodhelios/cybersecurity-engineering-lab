import copy
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

PROJECT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT))
from dns_review import compare, main, read_input


def encoded(value):
    return json.dumps(value).encode()


class DNSReviewTests(unittest.TestCase):
    def setUp(self):
        self.before = json.loads((PROJECT / "examples/before.json").read_text())
        self.after = json.loads((PROJECT / "examples/after.json").read_text())
        self.scope = json.loads((PROJECT / "examples/scope.json").read_text())

    def compare(self):
        return compare(encoded(self.before), encoded(self.after), encoded(self.scope))

    def test_fixture_changes_and_missing_coverage_are_distinct(self):
        result = self.compare()
        self.assertEqual(result["status_counts"], {
            "changed": 1, "unchanged": 0, "first_observed": 1, "not_observed_current": 1})
        self.assertEqual(result["not_observed_in_either_count"], 1)
        records = {row["hostname"]: row for row in result["records"]}
        web = records["web.example.test"]
        self.assertEqual(web["addresses_added"], ["192.0.2.11"])
        self.assertEqual(web["addresses_removed"], ["192.0.2.10"])
        self.assertEqual((web["previous_record"], web["current_record"]), (1, 1))
        self.assertEqual(records["worker.example.test"]["addresses_removed"], [])
        self.assertEqual(records["new.example.test"]["addresses_added"], [])
        self.assertEqual(result, self.compare())

    def test_shared_address_never_merges_hostnames(self):
        self.after["records"] = copy.deepcopy(self.before["records"])
        self.after["records"][1]["addresses"] = ["192.0.2.10"]
        result = self.compare()
        self.assertEqual(result["observed_host_count"], 2)
        self.assertEqual(result["status_counts"]["unchanged"], 1)
        self.assertEqual(result["status_counts"]["changed"], 1)

    def test_ipv6_normalization_and_address_order_do_not_create_changes(self):
        self.before["records"] = [{"hostname": "web.example.test", "addresses": ["2001:db8::1", "192.0.2.10"]}]
        self.after["records"] = [{"hostname": "WEB.example.test.", "addresses": ["192.0.2.10", "2001:0db8::1"]}]
        self.assertEqual(self.compare()["status_counts"]["unchanged"], 1)

    def test_duplicate_and_out_of_scope_hosts_fail(self):
        self.after["records"].append(copy.deepcopy(self.after["records"][0]))
        with self.assertRaises(ValueError):
            self.compare()
        self.after["records"].pop()
        self.after["records"][0]["hostname"] = "outside.example.test"
        with self.assertRaises(ValueError):
            self.compare()

    def test_invalid_address_hostname_time_and_scope_fail(self):
        original = copy.deepcopy(self.after)
        for hostname, addresses in (("bad\nname", ["192.0.2.1"]), ("web.example.test", ["bad"]),
                                    ("web.example.test", ["fe80::1%eth0"]),
                                    ("web.example.test", ["192.0.2.1", "192.0.2.1"]),
                                    ("web.example.test", [])):
            self.after["records"] = [{"hostname": hostname, "addresses": addresses}]
            with self.subTest(hostname=hostname), self.assertRaises(ValueError):
                self.compare()
        self.after = copy.deepcopy(original)
        for timestamp in (self.before["observed_at"], "2026-10-23T12:00:00", "bad"):
            self.after["observed_at"] = timestamp
            with self.assertRaises(ValueError):
                self.compare()
        self.after = copy.deepcopy(original)
        self.scope["scope"] = "unknown"
        with self.assertRaises(ValueError):
            self.compare()

    def test_unknown_duplicate_nonfinite_and_boolean_schema_fail(self):
        for data in (b'{"schema_version":1,"schema_version":1}',
                     encoded(dict(self.before, schema_version=True)),
                     encoded(dict(self.before, extra="private-fixture-marker")),
                     encoded(dict(self.before, observed_at=float("nan")))):
            with self.assertRaises(ValueError):
                compare(data, encoded(self.after), encoded(self.scope))

    def test_empty_snapshots_preserve_unobserved_scope_count(self):
        self.before["records"] = self.after["records"] = []
        result = self.compare()
        self.assertEqual(result["records"], [])
        self.assertEqual(result["not_observed_in_either_count"], 4)

    @unittest.skipUnless(os.name == "posix", "private local files require POSIX")
    def test_cli_private_output_no_overwrite_and_sanitized_failures(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            previous, current, scope, output = [root / name for name in ("before", "after", "scope", "output")]
            for path, value in ((previous, self.before), (current, self.after), (scope, self.scope)):
                path.write_bytes(encoded(value))
            args = [str(previous), str(current), "--scope", str(scope), "--output", str(output)]
            self.assertEqual(main(args), 0)
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            before = output.read_bytes()
            with redirect_stderr(StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(output.read_bytes(), before)
            output.unlink()
            current.write_text('private-fixture-marker')
            stdout, stderr = StringIO(), StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                self.assertEqual(main(args), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn("private-fixture-marker", stderr.getvalue())
            self.assertFalse(output.exists())

    @unittest.skipUnless(os.name == "posix", "local input flags require POSIX")
    def test_limits_and_nonregular_inputs_fail(self):
        with patch("dns_review.MAX_BYTES", 1), self.assertRaises(ValueError):
            self.compare()
        with patch("dns_review.MAX_RECORDS", 1), self.assertRaises(ValueError):
            self.compare()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "input"; path.write_text('{}')
            link = root / "link"; link.symlink_to(path)
            fifo = root / "fifo"; os.mkfifo(fifo)
            for invalid in (link, fifo):
                with self.assertRaises((OSError, ValueError)):
                    read_input(invalid)


if __name__ == "__main__":
    unittest.main()
