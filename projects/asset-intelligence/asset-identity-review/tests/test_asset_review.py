"""Mock identifier claims remain scoped, explainable and conflict preserving."""

import copy
from contextlib import redirect_stderr, redirect_stdout
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
import asset_review as review


class AssetReviewTests(unittest.TestCase):
    def setUp(self):
        self.originals = [(ROOT/"examples"/name).read_bytes() for name in ("cloud.json", "endpoint.json")]
        self.documents = [json.loads(data) for data in self.originals]

    def run_review(self, documents=None, **options):
        data = self.originals if documents is None else [json.dumps(doc).encode() for doc in documents]
        return review.review_sources(data, **({"namespace": "synthetic-assets", "scope": "synthetic"} | options))

    def test_complete_fixture_normalizes_claims_and_preserves_ambiguity(self):
        with patch("socket.socket", side_effect=AssertionError("network forbidden")):
            result = self.run_review()
        self.assertEqual(result, self.run_review())
        self.assertEqual((result["record_count"], result["group_count"],
                          result["matched_group_count"], result["unresolved_component_count"]), (7, 6, 1, 1))
        matched = next(g for g in result["groups"] if g["identity_status"] == "matched_identifier_claims")
        self.assertEqual(matched["hostname_claims"], ["web.example.test"])
        self.assertEqual(matched["address_claims"], ["192.0.2.10", "2001:db8::10"])
        self.assertEqual([r["row_number"] for r in matched["source_records"]], [1, 1])
        self.assertEqual(len(result["findings"][0]["source_records"]), 2)
        self.assertEqual(len([g for g in result["groups"] if g["identity_status"] == "unresolved_identity_conflict"]), 2)

    def test_ip_and_hostname_alone_never_merge_records(self):
        result = self.run_review()
        groups = [g for g in result["groups"] if g["hostname_claims"] == ["shared.example.test"]]
        self.assertEqual(len(groups), 2)
        self.assertTrue(all(g["identity_status"] == "no_strong_identifier" for g in groups))

    def test_transitive_conflicting_cloud_ids_split_entire_component(self):
        documents = copy.deepcopy(self.documents)
        a = documents[0]["assets"][0]
        b = documents[1]["assets"][0]
        a["identifiers"]["hardware_id"] = "synthetic-serial"
        b["identifiers"] = {"hardware_id": "synthetic-serial"}
        c = copy.deepcopy(b)
        c["source_record_id"] = "transitive"
        c["identifiers"]["cloud_resource_id"] = documents[0]["assets"][2]["identifiers"]["cloud_resource_id"]
        # Isolate this three-record component from the other conflict fixture.
        documents[0]["assets"] = [a]
        documents[1]["assets"] = [b, c]
        result = self.run_review(documents)
        self.assertEqual((result["group_count"], result["matched_group_count"]), (3, 0))
        self.assertEqual(result["unresolved_component_count"], 1)
        self.assertIn("cloud_resource_id", result["findings"][0]["conflicting_identifiers"])
        self.assertTrue(all(len(g["source_records"]) == 1 for g in result["groups"]))

    def test_equal_strong_claims_merge_without_inventing_truth_for_changed_attributes(self):
        documents = copy.deepcopy(self.documents)
        documents[0]["assets"] = documents[0]["assets"][:1]
        documents[1]["assets"] = documents[1]["assets"][:1]
        documents[1]["assets"][0]["hostname"] = "different.example.test"
        result = self.run_review(documents)
        self.assertEqual(result["matched_group_count"], 1)
        self.assertEqual(result["groups"][0]["hostname_claims"], ["different.example.test", "web.example.test"])

    def test_namespace_scope_version_and_source_id_must_agree(self):
        for field, value in (("namespace", "other-namespace"), ("scope", "owned"),
                             ("schema_version", True), ("source_id", "mock-cloud"),
                             ("captured_at", "2026-11-17T00:00:00")):
            documents = copy.deepcopy(self.documents)
            documents[1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.run_review(documents)
        for options in ({"namespace": "bad namespace"}, {"scope": "public"}):
            with self.assertRaises(ValueError): self.run_review(**options)

    def test_review_ids_are_bound_to_declared_namespace(self):
        documents = copy.deepcopy(self.documents)
        for document in documents: document["namespace"] = "other-namespace"
        other = self.run_review(documents, namespace="other-namespace")
        original = self.run_review()
        self.assertEqual(other["record_count"], original["record_count"])
        self.assertTrue({g["group_id"] for g in original["groups"]}.isdisjoint(g["group_id"] for g in other["groups"]))
        self.assertNotEqual(other["findings"][0]["finding_id"], original["findings"][0]["finding_id"])

    def test_duplicate_records_bad_identifier_and_unknown_fields_reject_all_input(self):
        changes = [{"kind": "service"}, {"hostname": "bad..example.test"}, {"hostname": "*.example.test"},
                   {"ip_addresses": ["fe80::1%eth0"]}, {"identifiers": {"unknown": "value"}},
                   {"identifiers": {"cloud_resource_id": "i-0123456789abcdef0"}}, {"extra": "unsupported"}]
        for change in changes:
            documents = copy.deepcopy(self.documents)
            documents[0]["assets"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError): self.run_review(documents)
        documents = copy.deepcopy(self.documents)
        documents[0]["assets"].append(documents[0]["assets"][0])
        with self.assertRaises(ValueError): self.run_review(documents)

    def test_strict_json_byte_record_and_collection_limits(self):
        for bad in (b'{"schema_version":1,"schema_version":1}', b'{"x":NaN}', b'{"x":1e999}', b'\xff'):
            with self.assertRaises(ValueError):
                review.review_sources([bad, self.originals[1]], namespace="synthetic-assets", scope="synthetic")
        for data in ([self.originals[0]], self.originals*5):
            with self.assertRaises(ValueError): review.review_sources(data, namespace="synthetic-assets", scope="synthetic")
        for setting in ("MAX_INPUT_BYTES", "MAX_RECORDS_PER_SOURCE"):
            with patch.object(review, setting, 1), self.assertRaises(ValueError): self.run_review()

    def test_empty_sources_do_not_claim_zero_real_assets_and_bytes_are_bound(self):
        documents = copy.deepcopy(self.documents)
        for document in documents: document["assets"] = []
        result = self.run_review(documents)
        self.assertEqual((result["record_count"], result["group_count"]), (0, 0))
        changed = list(self.originals); changed[0] += b"\n"
        other = review.review_sources(changed, namespace="synthetic-assets", scope="synthetic")
        self.assertNotEqual(self.run_review()["inputs"][0]["original_sha256"], other["inputs"][0]["original_sha256"])

    @unittest.skipUnless(os.name == "posix", "private publication requires POSIX")
    def test_cli_retains_private_review_without_echoing_records_or_overwriting(self):
        with tempfile.TemporaryDirectory() as directory, patch("socket.socket", side_effect=AssertionError("network forbidden")):
            output = Path(directory)/"review.json"
            args = ["review", *[str(ROOT/"examples"/name) for name in ("cloud.json", "endpoint.json")],
                    "--namespace", "synthetic-assets", "--scope", "synthetic", "--output", str(output)]
            with redirect_stdout(StringIO()) as stdout: self.assertEqual(review.main(args), 0)
            self.assertNotIn("web.example.test", stdout.getvalue())
            self.assertNotIn(str(output), stdout.getvalue())
            self.assertEqual(json.loads(output.read_bytes()), self.run_review())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            before = output.read_bytes()
            with redirect_stdout(StringIO()) as stdout, redirect_stderr(StringIO()) as stderr:
                self.assertEqual(review.main(args), 2)
            self.assertEqual(stdout.getvalue(), "")
            self.assertNotIn(str(output), stderr.getvalue())
            self.assertEqual(output.read_bytes(), before)
            self.assertFalse(list(Path(directory).glob('.asset-review-*')))

    @unittest.skipUnless(os.name == "posix", "bounded no-follow reads require POSIX")
    def test_symlink_directory_fifo_and_invalid_tail_do_not_publish(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); source, path = root/"source", root/"input"
            source.write_bytes(self.originals[0]); path.symlink_to(source)
            with self.assertRaises(OSError): review._read(path)
            path.unlink(); path.mkdir()
            with self.assertRaises((OSError, ValueError)): review._read(path)
            path.rmdir(); os.mkfifo(path)
            with self.assertRaises(ValueError): review._read(path)
            path.unlink(); path.write_bytes(self.originals[0] + b"invalid-tail")
            with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
                self.assertEqual(review.main(["review", str(source), str(path), "--namespace", "synthetic-assets",
                    "--scope", "synthetic", "--output", str(root/"output")]), 2)
            self.assertFalse((root/"output").exists())


if __name__ == "__main__":
    unittest.main()
