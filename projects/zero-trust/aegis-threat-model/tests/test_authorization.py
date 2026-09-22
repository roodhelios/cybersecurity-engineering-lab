"""Cross-control tests for signed verification and policy authorization."""

from __future__ import annotations

import base64
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from dataclasses import replace
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from aegis_threat_model.authorization import authorize_signed_request
from aegis_threat_model.authorization_cli import main
from aegis_threat_model.policy import PolicyContractError, PolicyData, load_json
from aegis_threat_model.verification import (
    AgentCredential,
    MemoryNonceStore,
    SignedToolRequest,
    canonical_request,
)


NOW = 1_789_686_000
POLICY_PATH = PROJECT_ROOT / "policy" / "data.json"


class AuthorizationRegressionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.public_key_b64 = base64.b64encode(public_key).decode("ascii")
        self.policy = PolicyData.from_dict(load_json(POLICY_PATH))

    def signed_request(
        self,
        *,
        agent_id: str = "agent-analyst",
        tool_name: str = "inventory.lookup",
        timestamp: int = NOW,
        nonce: str = "nonce-authorization-0001",
    ) -> SignedToolRequest:
        request = SignedToolRequest.from_dict(
            {
                "agent_id": agent_id,
                "session_id": "session-authorization",
                "tool_name": tool_name,
                "tool_args": {"asset_id": "asset-synthetic-001"},
                "timestamp": timestamp,
                "nonce": nonce,
                "signature_b64": "pending",
            }
        )
        signature = self.private_key.sign(canonical_request(request))
        return replace(
            request,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def credential(self, agent_id: str) -> AgentCredential:
        return AgentCredential(
            agent_id=agent_id,
            status="active",
            public_key_b64=self.public_key_b64,
            key_version=2,
        )

    def authorize(
        self,
        request: SignedToolRequest,
        *,
        nonces: MemoryNonceStore | None = None,
        risk_score: int = 20,
        step_up_token_valid: bool = False,
    ):
        return authorize_signed_request(
            request,
            credential=self.credential(request.agent_id),
            nonces=nonces or MemoryNonceStore(),
            policy=self.policy,
            risk_score=risk_score,
            step_up_token_valid=step_up_token_valid,
            now=NOW,
        )

    def test_valid_signed_inventory_request_is_allowed(self) -> None:
        decision = self.authorize(self.signed_request())

        self.assertEqual(decision.to_dict(), {
            "effect": "allow",
            "reason": "authorized",
            "stage": "policy",
            "key_version": 2,
        })

    def test_replay_stops_before_policy(self) -> None:
        request = self.signed_request()
        nonces = MemoryNonceStore()

        first = self.authorize(request, nonces=nonces)
        second = self.authorize(request, nonces=nonces)

        self.assertEqual(first.effect, "allow")
        self.assertEqual(second.to_dict(), {
            "effect": "deny",
            "reason": "replay_detected",
            "stage": "verification",
            "key_version": None,
        })

    def test_malformed_signature_stops_before_policy(self) -> None:
        request = replace(self.signed_request(), signature_b64="not-base64")

        decision = self.authorize(request)

        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "invalid_signature")
        self.assertEqual(decision.stage, "verification")

    def test_past_and_future_clock_skew_stop_before_policy(self) -> None:
        for index, timestamp in enumerate((NOW - 61, NOW + 61), start=1):
            with self.subTest(timestamp=timestamp):
                request = self.signed_request(
                    timestamp=timestamp,
                    nonce=f"nonce-authorization-clock-{index}",
                )
                decision = self.authorize(request)
                self.assertEqual(decision.reason, "stale_timestamp")
                self.assertEqual(decision.stage, "verification")

    def test_signed_role_escalation_is_denied_by_policy(self) -> None:
        request = self.signed_request(tool_name="asset.quarantine")

        decision = self.authorize(request, risk_score=80)

        self.assertEqual(decision.effect, "deny")
        self.assertEqual(decision.reason, "role_not_allowed")
        self.assertEqual(decision.stage, "policy")

    def test_high_risk_responder_requires_bound_step_up(self) -> None:
        request = self.signed_request(
            agent_id="agent-responder",
            tool_name="asset.quarantine",
        )

        required = self.authorize(request, risk_score=80)
        allowed = self.authorize(
            self.signed_request(
                agent_id="agent-responder",
                tool_name="asset.quarantine",
                nonce="nonce-authorization-0002",
            ),
            risk_score=80,
            step_up_token_valid=True,
        )

        self.assertEqual(required.effect, "step_up")
        self.assertEqual(required.reason, "step_up_required")
        self.assertEqual(allowed.effect, "allow")

    def test_invalid_risk_value_fails_closed(self) -> None:
        request = self.signed_request()
        nonces = MemoryNonceStore()
        with self.assertRaisesRegex(PolicyContractError, "risk_score"):
            self.authorize(request, nonces=nonces, risk_score=True)

        self.assertEqual(self.authorize(request, nonces=nonces).effect, "allow")

    def test_cli_runs_repository_fixture_without_network_access(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "--request",
                    str(PROJECT_ROOT / "examples" / "signed-request.json"),
                    "--credential",
                    str(PROJECT_ROOT / "examples" / "credential.json"),
                    "--policy",
                    str(POLICY_PATH),
                    "--risk-score",
                    "20",
                    "--now",
                    str(NOW),
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["effect"], "allow")


if __name__ == "__main__":
    unittest.main()
