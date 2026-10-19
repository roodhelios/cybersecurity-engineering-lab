"""Run the combined signature and authorization regressions against native OPA."""

import io
import json
import shutil
import sys
import unittest
from contextlib import redirect_stdout, redirect_stderr
from dataclasses import replace
from functools import partial
from pathlib import Path
from unittest.mock import Mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
import test_authorization as regression
from aegis_threat_model.authorization import authorize_signed_request
from aegis_threat_model.authorization_cli import main
from aegis_threat_model.opa_conformance import evaluate_input_with_opa, _decision_from_result, OpaConformanceError
from aegis_threat_model.verification import MemoryNonceStore


class NativeFailureTests(unittest.TestCase):
    def test_non_text_native_effects_fail_as_contract_errors(self):
        for effect in ([], {}, None, True, 1):
            with self.subTest(effect=effect), self.assertRaises(OpaConformanceError):
                _decision_from_result({"result": [{"expressions": [{"value": {
                    "effect": effect, "reason": "synthetic"}}]}]})

    def test_bad_signature_never_calls_native_evaluator(self):
        fixture = regression.AuthorizationRegressionTests()
        fixture.setUp()
        request = replace(fixture.signed_request(), signature_b64="not-base64")
        evaluator = Mock(side_effect=AssertionError("policy must not be reached"))
        result = authorize_signed_request(request, credential=fixture.credential(request.agent_id),
            nonces=MemoryNonceStore(), policy=fixture.policy, risk_score=20,
            step_up_token_valid=False, now=regression.NOW, policy_evaluator=evaluator)
        self.assertEqual(result.stage, "verification")
        evaluator.assert_not_called()

    def test_missing_native_binary_cannot_fall_back_or_print_success(self):
        output = io.StringIO()
        with redirect_stdout(output), redirect_stderr(io.StringIO()):
            status = main(["--request", str(ROOT / "examples/signed-request.json"),
                "--credential", str(ROOT / "examples/credential.json"), "--policy", str(regression.POLICY_PATH),
                "--risk-score", "20", "--now", str(regression.NOW),
                "--opa", str(ROOT / "missing-opa-binary"), "--rego", str(ROOT / "policy/aegis.rego")])
        self.assertEqual(status, 2)
        self.assertEqual(output.getvalue(), "")


@unittest.skipUnless(shutil.which("opa"), "OPA executable is not installed")
class NativeAuthorizationTests(regression.AuthorizationRegressionTests):
    def authorize(self, request, *, nonces=None, risk_score=20, step_up_token_valid=False):
        evaluator = partial(evaluate_input_with_opa, opa_binary=shutil.which("opa"),
                            rego_path=ROOT / "policy/aegis.rego", data_path=regression.POLICY_PATH)
        return authorize_signed_request(request, credential=self.credential(request.agent_id),
            nonces=nonces or MemoryNonceStore(), policy=self.policy, risk_score=risk_score,
            step_up_token_valid=step_up_token_valid, now=regression.NOW, policy_evaluator=evaluator)

    def test_cli_runs_repository_fixture_without_network_access(self):
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(["--request", str(ROOT / "examples/signed-request.json"),
                "--credential", str(ROOT / "examples/credential.json"), "--policy", str(regression.POLICY_PATH),
                "--risk-score", "20", "--now", str(regression.NOW),
                "--opa", shutil.which("opa"), "--rego", str(ROOT / "policy/aegis.rego")])
        self.assertEqual(status, 0)
        result = json.loads(output.getvalue())
        self.assertEqual((result["effect"], result["policy_engine"]), ("allow", "opa"))


if __name__ == "__main__":
    unittest.main()
