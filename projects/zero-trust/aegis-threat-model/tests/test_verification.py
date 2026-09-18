"""Tests for local signed-request verification and replay controls."""

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

from aegis_threat_model.verification import (
    AgentCredential,
    MemoryNonceStore,
    RequestFormatError,
    SignedToolRequest,
    canonical_request,
    verify_request,
)
from aegis_threat_model.verify_cli import main


NOW = 1_789_686_000


class RequestVerificationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.private_key = Ed25519PrivateKey.from_private_bytes(bytes(range(32)))
        public_key = self.private_key.public_key().public_bytes(
            serialization.Encoding.Raw,
            serialization.PublicFormat.Raw,
        )
        self.credential = AgentCredential(
            agent_id="agent-test",
            status="active",
            public_key_b64=base64.b64encode(public_key).decode("ascii"),
            key_version=4,
        )

    def request(self, **changes: object) -> SignedToolRequest:
        fields = {
            "agent_id": "agent-test",
            "session_id": "session-test",
            "tool_name": "inventory.lookup",
            "tool_args": {"asset_id": "asset-synthetic-001", "details": True},
            "timestamp": NOW,
            "nonce": "nonce-request-0001",
            "signature_b64": "not-signed-yet",
            **changes,
        }
        request = SignedToolRequest.from_dict(fields)
        signature = self.private_key.sign(canonical_request(request))
        return replace(
            request,
            signature_b64=base64.b64encode(signature).decode("ascii"),
        )

    def test_valid_request_is_allowed_with_key_version(self) -> None:
        decision = verify_request(
            self.request(),
            credential=self.credential,
            nonces=MemoryNonceStore(),
            now=NOW,
        )

        self.assertEqual(decision.to_dict(), {
            "allowed": True,
            "reason": "verified",
            "key_version": 4,
        })

    def test_second_use_of_nonce_is_rejected(self) -> None:
        request = self.request()
        nonces = MemoryNonceStore()

        first = verify_request(
            request, credential=self.credential, nonces=nonces, now=NOW
        )
        second = verify_request(
            request, credential=self.credential, nonces=nonces, now=NOW
        )

        self.assertTrue(first.allowed)
        self.assertEqual(second.reason, "replay_detected")

    def test_changed_arguments_fail_without_consuming_nonce(self) -> None:
        original = self.request()
        changed = SignedToolRequest.from_dict(
            {
                **{
                    "agent_id": original.agent_id,
                    "session_id": original.session_id,
                    "tool_name": original.tool_name,
                    "timestamp": original.timestamp,
                    "nonce": original.nonce,
                    "signature_b64": original.signature_b64,
                },
                "tool_args": {"asset_id": "asset-synthetic-999", "details": True},
            }
        )
        nonces = MemoryNonceStore()

        rejected = verify_request(
            changed, credential=self.credential, nonces=nonces, now=NOW
        )
        accepted = verify_request(
            original, credential=self.credential, nonces=nonces, now=NOW
        )

        self.assertEqual(rejected.reason, "invalid_signature")
        self.assertTrue(accepted.allowed)

    def test_past_and_future_clock_skew_are_rejected(self) -> None:
        for timestamp in (NOW - 61, NOW + 61):
            with self.subTest(timestamp=timestamp):
                decision = verify_request(
                    self.request(timestamp=timestamp),
                    credential=self.credential,
                    nonces=MemoryNonceStore(),
                    now=NOW,
                )
                self.assertEqual(decision.reason, "stale_timestamp")

    def test_malformed_signature_and_key_fail_closed(self) -> None:
        malformed_request = replace(self.request(), signature_b64="not-base64")
        malformed_key = replace(self.credential, public_key_b64="AAAA")

        request_decision = verify_request(
            malformed_request,
            credential=self.credential,
            nonces=MemoryNonceStore(),
            now=NOW,
        )
        key_decision = verify_request(
            self.request(nonce="nonce-request-0002"),
            credential=malformed_key,
            nonces=MemoryNonceStore(),
            now=NOW,
        )

        self.assertEqual(request_decision.reason, "invalid_signature")
        self.assertEqual(key_decision.reason, "invalid_signature")

    def test_unknown_and_inactive_credentials_fail_closed(self) -> None:
        request = self.request()
        unknown = verify_request(
            request,
            credential=None,
            nonces=MemoryNonceStore(),
            now=NOW,
        )
        inactive = verify_request(
            request,
            credential=replace(self.credential, status="revoked"),
            nonces=MemoryNonceStore(),
            now=NOW,
        )

        self.assertEqual(unknown.reason, "unknown_agent")
        self.assertEqual(inactive.reason, "agent_not_active")

    def test_request_parser_rejects_boolean_timestamp_and_short_nonce(self) -> None:
        base = json.loads(
            (PROJECT_ROOT / "examples" / "signed-request.json").read_text(
                encoding="utf-8"
            )
        )
        for field, value, message in (
            ("timestamp", True, "timestamp"),
            ("nonce", "short", "at least 16"),
        ):
            with self.subTest(field=field):
                changed = {**base, field: value}
                with self.assertRaisesRegex(RequestFormatError, message):
                    SignedToolRequest.from_dict(changed)

    def test_nonce_ttl_must_cover_full_clock_window(self) -> None:
        with self.assertRaisesRegex(ValueError, "twice the accepted clock skew"):
            verify_request(
                self.request(),
                credential=self.credential,
                nonces=MemoryNonceStore(),
                now=NOW,
                max_skew_seconds=60,
                nonce_ttl_seconds=119,
            )

    def test_canonical_bytes_ignore_argument_insertion_order(self) -> None:
        left = self.request(tool_args={"b": 2, "a": 1})
        right = replace(left, tool_args={"a": 1, "b": 2})

        self.assertEqual(canonical_request(left), canonical_request(right))

    def test_fixture_cli_verifies_without_network_access(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = main(
                [
                    "--request",
                    str(PROJECT_ROOT / "examples" / "signed-request.json"),
                    "--credential",
                    str(PROJECT_ROOT / "examples" / "credential.json"),
                    "--now",
                    str(NOW),
                ]
            )

        self.assertEqual(status, 0)
        self.assertEqual(json.loads(output.getvalue())["reason"], "verified")


if __name__ == "__main__":
    unittest.main()
