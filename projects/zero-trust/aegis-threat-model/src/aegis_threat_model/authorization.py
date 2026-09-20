"""Compose signed-request verification with the least-privilege policy oracle."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Literal

from .policy import PolicyData, PolicyInput, decide
from .verification import (
    AgentCredential,
    NonceStore,
    SignedToolRequest,
    verify_request,
)


AuthorizationStage = Literal["verification", "policy"]
AuthorizationEffect = Literal["allow", "deny", "step_up"]


@dataclass(frozen=True, slots=True)
class AuthorizationDecision:
    effect: AuthorizationEffect
    reason: str
    stage: AuthorizationStage
    key_version: int | None

    def to_dict(self) -> dict[str, Any]:
        return {
            "effect": self.effect,
            "reason": self.reason,
            "stage": self.stage,
            "key_version": self.key_version,
        }


def authorize_signed_request(
    request: SignedToolRequest,
    *,
    credential: AgentCredential | None,
    nonces: NonceStore,
    policy: PolicyData,
    risk_score: int,
    step_up_token_valid: bool,
    now: int,
    max_skew_seconds: int = 60,
    nonce_ttl_seconds: int = 300,
) -> AuthorizationDecision:
    """Fail closed at verification before evaluating least-privilege policy."""

    policy_input = PolicyInput.from_dict(
        {
            "agent_id": request.agent_id,
            "tool_name": request.tool_name,
            "risk_score": risk_score,
            "step_up_token_valid": step_up_token_valid,
        }
    )
    verified = verify_request(
        request,
        credential=credential,
        nonces=nonces,
        now=now,
        max_skew_seconds=max_skew_seconds,
        nonce_ttl_seconds=nonce_ttl_seconds,
    )
    if not verified.allowed:
        return AuthorizationDecision(
            effect="deny",
            reason=verified.reason,
            stage="verification",
            key_version=verified.key_version,
        )

    policy_decision = decide(policy, policy_input)
    return AuthorizationDecision(
        effect=policy_decision.effect,
        reason=policy_decision.reason,
        stage="policy",
        key_version=verified.key_version,
    )
