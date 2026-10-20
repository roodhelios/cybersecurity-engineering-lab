import hashlib
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest.mock import patch

import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from aws_cost_plan.cloudtrail_handoff import build_handoff, main

FIXTURE = Path(__file__).resolve().parents[1] / "examples/cloudtrail-events.jsonl"


class CloudTrailHandoffTests(unittest.TestCase):
    def test_logging_outcomes_survive_handoff_without_raw_error_details(self):
        data = FIXTURE.with_name("cloudtrail-logging-outcomes.jsonl").read_bytes()
        result = build_handoff(data, case_id="outcome-review", scope_note="synthetic")
        self.assertEqual(result["finding_count"], 3)
        self.assertEqual([row["findings"][0]["severity"] for row in result["timeline"]],
                         ["medium", "critical", "medium"])
        self.assertEqual(result["containment"], "not_performed")
        self.assertEqual(result["recovery"], "not_verified")
        self.assertNotIn("AccessDenied", json.dumps(result))

    def test_fixture_groups_findings_by_event_and_preserves_provenance(self):
        data = FIXTURE.read_bytes()
        result = build_handoff(data, case_id="synthetic-001", scope_note="synthetic fixture only")
        self.assertEqual(result["source_sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual((result["event_count"], result["finding_count"], result["flagged_event_count"]), (2, 3, 2))
        self.assertEqual([f["rule_id"] for f in result["timeline"][1]["findings"]], ["CT003", "CT004"])
        self.assertEqual(result["containment"], "not_performed")
        self.assertEqual(result["status"], "unreviewed")
        self.assertNotIn("userIdentity", json.dumps(result))

    def test_timeline_sorts_utc_and_preserves_original_line_numbers(self):
        lines = FIXTURE.read_bytes().splitlines()
        result = build_handoff(b"\n" + lines[1] + b"\n" + lines[0], case_id="demo", scope_note="local")
        self.assertEqual([event["source_line"] for event in result["timeline"]], [3, 2])

    def test_empty_input_never_claims_recovery_or_a_clean_account(self):
        result = build_handoff(b"", case_id="demo", scope_note="empty collection")
        self.assertEqual(result["event_count"], 0)
        self.assertEqual(result["status"], "unreviewed")
        self.assertEqual(result["recovery"], "not_verified")

    def test_fractional_timestamp_order_is_chronological_not_lexical(self):
        event = json.loads(FIXTURE.read_bytes().splitlines()[0])
        later = dict(event, eventTime="2026-09-27T20:00:00.5Z")
        data = (json.dumps(later) + "\n" + json.dumps(event)).encode()
        result = build_handoff(data, case_id="demo", scope_note="synthetic")
        self.assertEqual([row["source_line"] for row in result["timeline"]], [2, 1])

    def test_cli_publishes_private_output_without_overwriting_or_changing_input(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "handoff.json"
            original = FIXTURE.read_bytes()
            args = [str(FIXTURE), "--case-id", "demo", "--scope-note", "synthetic", "--output", str(target)]
            self.assertEqual(main(args), 0)
            saved = target.read_bytes()
            self.assertEqual(json.loads(saved)["finding_count"], 3)
            if os.name == "posix":
                self.assertEqual(target.stat().st_mode & 0o777, 0o600)
            with redirect_stderr(io.StringIO()):
                self.assertEqual(main(args), 2)
            self.assertEqual(target.read_bytes(), saved)
            self.assertEqual(FIXTURE.read_bytes(), original)
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_invalid_input_and_metadata_emit_no_success_document(self):
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "events.jsonl"
            for data in (b"{", b"[]", b"\xff"):
                source.write_bytes(data)
                output = io.StringIO()
                with redirect_stdout(output), redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(source), "--case-id", "demo", "--scope-note", "local"]), 2)
                self.assertEqual(output.getvalue(), "")
        with self.assertRaises(ValueError):
            build_handoff(b"", case_id="../case", scope_note="local")
        with self.assertRaises(ValueError):
            build_handoff(b"", case_id="demo", scope_note=" ")

    def test_size_limit_and_failed_publication_leave_no_output(self):
        with patch("aws_cost_plan.cloudtrail_handoff.MAX_BYTES", 1):
            with self.assertRaises(ValueError):
                build_handoff(b"{}", case_id="demo", scope_note="local")
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "handoff.json"
            with patch("aws_cost_plan.cloudtrail_handoff.os.link", side_effect=OSError("failed")):
                with redirect_stderr(io.StringIO()):
                    self.assertEqual(main([str(FIXTURE), "--case-id", "demo", "--scope-note", "local", "--output", str(target)]), 2)
            self.assertEqual(list(Path(directory).iterdir()), [])
