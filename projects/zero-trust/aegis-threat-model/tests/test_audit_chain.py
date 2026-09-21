"""Tests for append-only authorization audit records and hash links."""

from __future__ import annotations

import io
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from aegis_threat_model.audit_chain import (
    AuditChainError,
    AuditRecord,
    build_audit_record,
    parse_json_lines,
    verify_audit_chain,
)
from aegis_threat_model.audit_cli import main


FIXTURE_PATH = PROJECT_ROOT / "examples" / "audit-records.jsonl"


def chain() -> tuple[AuditRecord, AuditRecord]:
    first = build_audit_record(
        sequence=1,
        recorded_at="2026-09-21T23:00:00Z",
        request_id="request-fixture-0001",
        agent_id="agent-analyst",
        session_id="session-fixture",
        tool_name="inventory.lookup",
        effect="allow",
        reason="authorized",
        stage="policy",
        key_version=2,
        previous_hash=None,
    )
    second = build_audit_record(
        sequence=2,
        recorded_at="2026-09-21T23:00:01Z",
        request_id="request-fixture-0002",
        agent_id="agent-analyst",
        session_id="session-fixture",
        tool_name="asset.quarantine",
        effect="deny",
        reason="role_not_allowed",
        stage="policy",
        key_version=2,
        previous_hash=first.record_hash,
    )
    return first, second


class AuditChainTests(unittest.TestCase):
    def test_builds_and_verifies_contiguous_chain(self) -> None:
        records = chain()

        summary = verify_audit_chain(records)

        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["head_hash"], records[-1].record_hash)

    def test_repository_fixture_has_reviewable_head(self) -> None:
        records = parse_json_lines(FIXTURE_PATH.read_text(encoding="utf-8").splitlines())

        summary = verify_audit_chain(records)

        self.assertEqual(summary["record_count"], 2)
        self.assertEqual(summary["last_recorded_at"], "2026-09-21T23:00:01Z")

    def test_changed_decision_fails_record_digest(self) -> None:
        value = chain()[0].to_dict()
        value["effect"] = "deny"

        with self.assertRaisesRegex(AuditChainError, "integrity check"):
            AuditRecord.from_dict(value)

    def test_reordered_or_missing_record_breaks_link(self) -> None:
        first, second = chain()
        for records, message in (
            ((second, first), "contiguous"),
            ((first, build_audit_record(
                sequence=3,
                recorded_at="2026-09-21T23:00:02Z",
                request_id="request-fixture-0003",
                agent_id="agent-analyst",
                session_id="session-fixture",
                tool_name="inventory.lookup",
                effect="allow",
                reason="authorized",
                stage="policy",
                key_version=2,
                previous_hash=second.record_hash,
            )), "contiguous"),
        ):
            with self.subTest(message=message):
                with self.assertRaisesRegex(AuditChainError, message):
                    verify_audit_chain(records)

    def test_duplicate_request_and_time_regression_are_rejected(self) -> None:
        first, second = chain()
        duplicate = build_audit_record(
            sequence=2,
            recorded_at="2026-09-21T23:00:01Z",
            request_id=first.request_id,
            agent_id=second.agent_id,
            session_id=second.session_id,
            tool_name=second.tool_name,
            effect=second.effect,
            reason=second.reason,
            stage=second.stage,
            key_version=second.key_version,
            previous_hash=first.record_hash,
        )
        backward = build_audit_record(
            sequence=2,
            recorded_at="2026-09-21T22:59:59Z",
            request_id=second.request_id,
            agent_id=second.agent_id,
            session_id=second.session_id,
            tool_name=second.tool_name,
            effect=second.effect,
            reason=second.reason,
            stage=second.stage,
            key_version=second.key_version,
            previous_hash=first.record_hash,
        )

        with self.assertRaisesRegex(AuditChainError, "duplicate request_id"):
            verify_audit_chain((first, duplicate))
        with self.assertRaisesRegex(AuditChainError, "backward in time"):
            verify_audit_chain((first, backward))

    def test_cross_field_rules_fail_closed(self) -> None:
        base = chain()[0].to_dict()
        for changes, message in (
            ({"stage": "verification", "effect": "allow"}, "must have a deny"),
            ({"stage": "policy", "key_version": None}, "require a verified"),
        ):
            with self.subTest(message=message):
                value = {**base, **changes, "record_hash": "0" * 64}
                with self.assertRaisesRegex(AuditChainError, message):
                    AuditRecord.from_dict(value)

    def test_cli_reports_fixture_and_refuses_input_overwrite(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([str(FIXTURE_PATH)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["record_count"], 2)

        errors = io.StringIO()
        with redirect_stderr(errors):
            overwrite_status = main(
                [str(FIXTURE_PATH), "--output", str(FIXTURE_PATH)]
            )
        self.assertEqual(overwrite_status, 2)
        self.assertIn("output must differ", errors.getvalue())

    def test_cli_reports_invalid_line_without_partial_output(self) -> None:
        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "audit.jsonl"
            source.write_text("not-json\n", encoding="utf-8")
            with redirect_stderr(errors):
                status = main([str(source)])

        self.assertEqual(status, 2)
        self.assertIn("line 1", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
