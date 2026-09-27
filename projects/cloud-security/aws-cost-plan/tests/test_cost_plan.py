"""Tests for the offline AWS cost and teardown plan."""

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

from aws_cost_plan.cli import main
from aws_cost_plan.model import CostPlanError, load_cost_plan, validate_cost_plan


FIXTURE_PATH = PROJECT_ROOT / "examples" / "aws-cost-plan.json"


def plan() -> dict:
    return json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))


class CostPlanTests(unittest.TestCase):
    def test_repository_plan_has_budget_headroom_and_digest(self) -> None:
        summary = load_cost_plan(FIXTURE_PATH).to_dict()

        self.assertEqual(summary["monthly_budget_usd"], "10.00")
        self.assertEqual(summary["planned_cap_usd"], "4.00")
        self.assertEqual(summary["remaining_usd"], "6.00")
        self.assertEqual(len(summary["plan_sha256"]), 64)

    def test_resource_caps_cannot_exceed_budget(self) -> None:
        value = plan()
        value["resources"][0]["monthly_cap_usd"] = "9.00"
        value["resources"][1]["monthly_cap_usd"] = "2.00"

        with self.assertRaisesRegex(CostPlanError, "exceed the monthly budget"):
            validate_cost_plan(value)

    def test_money_requires_exact_string_values(self) -> None:
        for amount in (10, 10.0, "1.234", "-1.00"):
            with self.subTest(amount=amount):
                value = plan()
                value["monthly_budget_usd"] = amount
                with self.assertRaisesRegex(CostPlanError, "USD string"):
                    validate_cost_plan(value)

    def test_alerts_cover_early_warning_and_full_budget(self) -> None:
        for thresholds in ([60, 100], [50, 80], [50, 50, 100], [80, 50, 100]):
            with self.subTest(thresholds=thresholds):
                value = plan()
                value["alert_thresholds_percent"] = thresholds
                with self.assertRaisesRegex(CostPlanError, "alert"):
                    validate_cost_plan(value)

    def test_required_cost_controls_fail_closed(self) -> None:
        for field, changed in (
            ("root_mfa_confirmed", False),
            ("budget_alert_configured", False),
            ("unbounded_usage_allowed", True),
        ):
            with self.subTest(field=field):
                value = plan()
                value["controls"][field] = changed
                with self.assertRaises(CostPlanError):
                    validate_cost_plan(value)

    def test_every_resource_has_unique_teardown_evidence(self) -> None:
        value = plan()
        value["resources"][1]["resource_id"] = value["resources"][0]["resource_id"]
        with self.assertRaisesRegex(CostPlanError, "resource_id values must be unique"):
            validate_cost_plan(value)

        value = plan()
        value["resources"][0]["teardown_steps"] = []
        with self.assertRaisesRegex(CostPlanError, "non-empty list"):
            validate_cost_plan(value)

    def test_unknown_fields_are_rejected(self) -> None:
        value = plan()
        value["estimated_savings"] = "100 percent"

        with self.assertRaisesRegex(CostPlanError, "unknown fields"):
            validate_cost_plan(value)

    def test_cli_renders_summary_and_refuses_overwrite(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main([str(FIXTURE_PATH)])
        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["planned_cap_usd"], "4.00")

        errors = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            existing = Path(directory) / "summary.json"
            existing.write_text("keep", encoding="utf-8")
            with redirect_stderr(errors):
                overwrite_status = main(
                    [str(FIXTURE_PATH), "--output", str(existing)]
                )
        self.assertEqual(overwrite_status, 2)
        self.assertIn("output already exists", errors.getvalue())


if __name__ == "__main__":
    unittest.main()
