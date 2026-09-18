"""Tests for the least-privilege policy data and fixture oracle."""

from __future__ import annotations

import copy
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from aegis_threat_model.policy import (
    PolicyContractError,
    PolicyData,
    PolicyInput,
    check_rego_structure,
    decide,
    evaluate_cases,
    load_json,
    parse_case_suite,
)
from aegis_threat_model.policy_cli import main


DATA_PATH = PROJECT_ROOT / "policy" / "data.json"
CASES_PATH = PROJECT_ROOT / "policy" / "cases.json"
REGO_PATH = PROJECT_ROOT / "policy" / "aegis.rego"


def data_dict() -> dict:
    return json.loads(DATA_PATH.read_text(encoding="utf-8"))


def cases_dict() -> dict:
    return json.loads(CASES_PATH.read_text(encoding="utf-8"))


class PolicyContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.policy = PolicyData.from_dict(load_json(DATA_PATH))

    def test_repository_cases_match_reference_decisions(self) -> None:
        cases = parse_case_suite(load_json(CASES_PATH))

        summary = evaluate_cases(self.policy, cases)

        self.assertEqual(summary["case_count"], 8)
        self.assertEqual(summary["matched_count"], 8)
        self.assertEqual(summary["mismatches"], [])
        self.assertEqual(summary["effects"], {"allow": 4, "deny": 3, "step_up": 1})

    def test_unknown_tool_denies_before_role_evaluation(self) -> None:
        decision = decide(
            self.policy,
            PolicyInput("agent-not-registered", "tool.not.registered", 10, False),
        )

        self.assertEqual(decision.to_dict(), {
            "effect": "deny",
            "reason": "unknown_tool",
        })

    def test_step_up_threshold_is_inclusive(self) -> None:
        decision = decide(
            self.policy,
            PolicyInput("agent-responder", "asset.quarantine", 70, False),
        )

        self.assertEqual(decision.effect, "step_up")

    def test_valid_step_up_token_allows_authorized_role(self) -> None:
        decision = decide(
            self.policy,
            PolicyInput("agent-responder", "asset.quarantine", 100, True),
        )

        self.assertEqual(decision.effect, "allow")

    def test_tool_cannot_reference_undeclared_role(self) -> None:
        value = data_dict()
        value["tools"]["inventory.lookup"]["roles"].append("not-declared")

        with self.assertRaisesRegex(PolicyContractError, "undeclared roles"):
            PolicyData.from_dict(value)

    def test_duplicate_case_identifier_is_rejected(self) -> None:
        value = cases_dict()
        value["cases"].append(copy.deepcopy(value["cases"][0]))

        with self.assertRaisesRegex(PolicyContractError, "duplicate case_id"):
            parse_case_suite(value)

    def test_boolean_risk_score_is_rejected(self) -> None:
        value = cases_dict()
        value["cases"][0]["input"]["risk_score"] = True

        with self.assertRaisesRegex(PolicyContractError, "risk_score"):
            parse_case_suite(value)

    def test_rego_file_contains_required_contract_anchors(self) -> None:
        check_rego_structure(REGO_PATH)

    def test_cli_reports_all_matching_cases(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "--data",
                    str(DATA_PATH),
                    "--cases",
                    str(CASES_PATH),
                    "--rego",
                    str(REGO_PATH),
                ]
            )

        summary = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(summary["matched_count"], 8)
        self.assertEqual(summary["rego_structure"], "checked")


if __name__ == "__main__":
    unittest.main()
