"""Tests for the local OPA conformance runner and its failure boundaries."""

from __future__ import annotations

import io
import json
import os
import shutil
import sys
import tempfile
import textwrap
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from aegis_threat_model.opa_conformance import (
    OpaConformanceError,
    evaluate_case_with_opa,
    run_opa_cases,
)
from aegis_threat_model.opa_conformance_cli import main
from aegis_threat_model.policy import load_json, parse_case_suite


DATA_PATH = PROJECT_ROOT / "policy" / "data.json"
CASES_PATH = PROJECT_ROOT / "policy" / "cases.json"
REGO_PATH = PROJECT_ROOT / "policy" / "aegis.rego"


FAKE_OPA = """\
#!/usr/bin/env python3
import json
import sys

value = json.load(sys.stdin)
if value["tool_name"] == "tool.not.registered":
    decision = {"effect": "deny", "reason": "unknown_tool"}
elif value["agent_id"] == "agent-not-registered":
    decision = {"effect": "deny", "reason": "role_not_allowed"}
elif value["agent_id"] == "agent-analyst" and value["tool_name"] == "asset.quarantine":
    decision = {"effect": "deny", "reason": "role_not_allowed"}
elif (
    value["tool_name"] == "asset.quarantine"
    and value["risk_score"] >= 70
    and not value["step_up_token_valid"]
):
    decision = {"effect": "step_up", "reason": "step_up_required"}
else:
    decision = {"effect": "allow", "reason": "authorized"}
print(json.dumps({"result": [{"expressions": [{"value": decision}]}]}))
"""


class OpaConformanceTests(unittest.TestCase):
    def setUp(self) -> None:
        self.cases = parse_case_suite(load_json(CASES_PATH))

    def make_executable(self, directory: str, source: str = FAKE_OPA) -> Path:
        path = Path(directory) / "opa-fixture"
        path.write_text(textwrap.dedent(source), encoding="utf-8")
        path.chmod(path.stat().st_mode | 0o111)
        return path

    def test_fixture_executable_matches_all_reviewed_cases(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            report = run_opa_cases(
                self.cases,
                rego_path=REGO_PATH,
                data_path=DATA_PATH,
                opa_binary=self.make_executable(directory),
            )

        self.assertEqual(report["case_count"], 8)
        self.assertEqual(report["matched_count"], 8)
        self.assertEqual(report["mismatches"], [])

    def test_missing_executable_has_direct_error(self) -> None:
        with self.assertRaisesRegex(OpaConformanceError, "was not found"):
            evaluate_case_with_opa(
                self.cases[0],
                rego_path=REGO_PATH,
                data_path=DATA_PATH,
                opa_binary="opa-not-installed-for-test",
            )

    def test_invalid_result_shape_fails_closed(self) -> None:
        source = """\
        #!/usr/bin/env python3
        print('{"result": []}')
        """
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_executable(directory, source)
            with self.assertRaisesRegex(OpaConformanceError, "one decision"):
                evaluate_case_with_opa(
                    self.cases[0],
                    rego_path=REGO_PATH,
                    data_path=DATA_PATH,
                    opa_binary=executable,
                )

    def test_nonzero_exit_reports_one_bounded_error_line(self) -> None:
        source = """\
        #!/usr/bin/env python3
        import sys
        print('synthetic OPA failure', file=sys.stderr)
        raise SystemExit(3)
        """
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_executable(directory, source)
            with self.assertRaisesRegex(OpaConformanceError, "synthetic OPA failure"):
                evaluate_case_with_opa(
                    self.cases[0],
                    rego_path=REGO_PATH,
                    data_path=DATA_PATH,
                    opa_binary=executable,
                )

    def test_cli_writes_machine_readable_report(self) -> None:
        output = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            executable = self.make_executable(directory)
            with redirect_stdout(output):
                status = main(
                    [
                        "--opa",
                        str(executable),
                        "--rego",
                        str(REGO_PATH),
                        "--data",
                        str(DATA_PATH),
                        "--cases",
                        str(CASES_PATH),
                    ]
                )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["matched_count"], 8)

    def test_cli_refuses_to_overwrite_an_input(self) -> None:
        errors = io.StringIO()
        with redirect_stderr(errors):
            status = main(
                [
                    "--rego",
                    str(REGO_PATH),
                    "--data",
                    str(DATA_PATH),
                    "--cases",
                    str(CASES_PATH),
                    "--output",
                    str(DATA_PATH),
                ]
            )

        self.assertEqual(status, 2)
        self.assertIn("output must differ", errors.getvalue())

    @unittest.skipUnless(shutil.which("opa"), "OPA executable is not installed")
    def test_installed_opa_matches_repository_cases(self) -> None:
        report = run_opa_cases(
            self.cases,
            rego_path=REGO_PATH,
            data_path=DATA_PATH,
        )

        self.assertEqual(report["matched_count"], len(self.cases))


if __name__ == "__main__":
    unittest.main()
