"""CSV review keeps contradictions and exact input lineage visible."""

import csv
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

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import asset_review
import asset_review_csv as export


class AssetCSVTests(unittest.TestCase):
    def setUp(self):
        self.paths = [ROOT / "examples" / name for name in ("cloud.json", "endpoint.json")]
        self.originals = [path.read_bytes() for path in self.paths]

    def render(self, originals=None):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            return export.export_csv(self.originals if originals is None else originals,
                                     namespace="synthetic-assets", scope="synthetic")

    def test_rows_preserve_group_status_conflicts_and_all_source_lineage(self):
        data, summary = self.render()
        self.assertEqual((data, summary), self.render())
        rows = list(csv.DictReader(StringIO(data.decode())))
        report = asset_review.review_sources(self.originals, namespace="synthetic-assets", scope="synthetic")
        self.assertEqual(len(rows), 6)
        self.assertEqual(sum(int(row["record_count"]) for row in rows), 7)
        self.assertEqual(summary["csv_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(summary["review_sha256"], asset_review._digest(report))
        self.assertEqual(sum(row["identity_status"] == "unresolved_identity_conflict" for row in rows), 2)
        for row, group in zip(rows, report["groups"]):
            self.assertEqual(row["group_id"], group["group_id"])
            self.assertEqual(json.loads(row["hostname_claims"]), group["hostname_claims"])
            self.assertEqual(json.loads(row["address_claims"]), group["address_claims"])
            records = json.loads(row["source_records"])
            self.assertEqual([r["reference"] for r in records], group["source_records"])
            self.assertEqual([r["observation"] for r in records], group["observations"])
            for source in json.loads(row["source_inputs"]):
                self.assertEqual(source, report["inputs"][source["input_number"] - 1])
            if group["conflict_id"]:
                self.assertEqual(json.loads(row["conflicting_identifiers"]), report["findings"][0]["conflicting_identifiers"])
        self.assertNotIn("observations", summary)

    def test_empty_sources_write_header_and_zero_counts(self):
        documents = [json.loads(data) for data in self.originals]
        for document in documents: document["assets"] = []
        data, summary = self.render([json.dumps(doc).encode() for doc in documents])
        self.assertEqual(data.decode(), ",".join(export.COLUMNS) + "\n")
        self.assertEqual(summary["record_count"], 0)

    def test_input_types_and_formula_prefixes_are_not_accepted_as_identifiers(self):
        for field, value in (("hostname", "=unsafe.example.test"), ("source_record_id", "+unsafe"),
                             ("identifiers", {"hardware_id": "@unsafe"})):
            documents = [json.loads(data) for data in self.originals]
            documents[0]["assets"][0][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.render([json.dumps(doc).encode() for doc in documents])
        data, _ = self.render()
        self.assertTrue(all(not str(value).startswith(("=", "+", "-", "@", "\t", "\r"))
            for row in csv.DictReader(StringIO(data.decode())) for value in row.values()))

    def test_changed_claims_and_original_whitespace_change_digest(self):
        data, original = self.render()
        changed = list(self.originals)
        changed[0] += b"\n"
        different, summary = self.render(changed)
        self.assertNotEqual(summary["review_sha256"], original["review_sha256"])
        self.assertNotEqual(different, data)

    @unittest.skipUnless(os.name == "posix", "private CLI requires POSIX")
    def test_cli_writes_private_file_preserves_existing_and_has_fixed_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "review.csv"
            args = [*map(str, self.paths), "--namespace", "synthetic-assets", "--scope", "synthetic", "--output", str(target)]
            with redirect_stdout(StringIO()) as output:
                self.assertEqual(export.main(args), 0)
            summary = json.loads(output.getvalue())
            data = target.read_bytes()
            self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            self.assertEqual(summary["group_count"], 6)
            self.assertNotIn("mock-cloud", output.getvalue())
            with redirect_stderr(StringIO()) as errors, redirect_stdout(StringIO()) as out:
                self.assertEqual(export.main(args), 2)
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(out.getvalue(), "")
            self.assertNotIn(str(target), errors.getvalue())
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_output_bound_fails_before_publication(self):
        with patch.object(export, "MAX_CSV_BYTES", 1), self.assertRaises(ValueError):
            self.render()


if __name__ == "__main__":
    unittest.main()
