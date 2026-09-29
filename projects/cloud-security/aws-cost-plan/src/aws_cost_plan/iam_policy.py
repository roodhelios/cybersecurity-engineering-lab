"""Review a small, explicit subset of IAM identity policies offline."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any


class IamPolicyError(ValueError):
    """Raised when a policy uses an unsupported or malformed construct."""


@dataclass(frozen=True, slots=True)
class PolicyFinding:
    code: str
    statement: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {"code": self.code, "statement": self.statement, "message": self.message}


def _strings(value: Any, field: str, index: int) -> tuple[str, ...]:
    if isinstance(value, str):
        values = (value,)
    elif isinstance(value, list):
        values = tuple(value)
    else:
        raise IamPolicyError(f"statement {index} {field} must be a string or list")
    if not values or any(not isinstance(item, str) or not item.strip() for item in values):
        raise IamPolicyError(f"statement {index} {field} must contain non-empty strings")
    return values


def _has_mfa_condition(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    conditions = value.get("Bool")
    return (
        isinstance(conditions, Mapping)
        and conditions.get("aws:MultiFactorAuthPresent") == "true"
    )


def review_identity_policy(value: Mapping[str, Any]) -> tuple[PolicyFinding, ...]:
    """Return conservative findings for explicit identity policy statements.

    This is a review aid, not an AWS policy simulator. Resource policies and IAM
    constructs outside the supported subset fail closed instead of being guessed at.
    """
    if not isinstance(value, Mapping):
        raise IamPolicyError("policy must be an object")
    extra = set(value) - {"Version", "Id", "Statement"}
    if extra:
        raise IamPolicyError(f"unsupported policy fields: {', '.join(sorted(extra))}")
    if value.get("Version") != "2012-10-17":
        raise IamPolicyError("Version must be 2012-10-17")
    statements = value.get("Statement")
    if isinstance(statements, Mapping):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        raise IamPolicyError("Statement must be a non-empty object or list")

    findings: list[PolicyFinding] = []
    required = {"Effect", "Action", "Resource"}
    allowed = required | {"Sid", "Condition"}
    for index, statement in enumerate(statements, start=1):
        if not isinstance(statement, Mapping):
            raise IamPolicyError(f"statement {index} must be an object")
        unsupported = set(statement) - allowed
        missing = required - set(statement)
        if unsupported:
            raise IamPolicyError(
                f"statement {index} has unsupported fields: {', '.join(sorted(unsupported))}"
            )
        if missing:
            raise IamPolicyError(
                f"statement {index} is missing fields: {', '.join(sorted(missing))}"
            )
        effect = statement["Effect"]
        if not isinstance(effect, str):
            raise IamPolicyError(f"statement {index} Effect must be a string")
        if effect not in {"Allow", "Deny"}:
            raise IamPolicyError(f"statement {index} Effect must be Allow or Deny")
        actions = _strings(statement["Action"], "Action", index)
        resources = _strings(statement["Resource"], "Resource", index)
        if effect != "Allow":
            continue
        if any("*" in action or "?" in action for action in actions):
            findings.append(PolicyFinding(
                "IAM001", index, "Allow uses a wildcard action; enumerate required actions"
            ))
        if any(resource == "*" for resource in resources):
            findings.append(PolicyFinding(
                "IAM002", index, "Allow uses Resource *; scope it to the required ARN"
            ))
        sensitive = any(
            action.lower().startswith("iam:")
            or action.lower() == "sts:assumerole"
            for action in actions
        )
        if sensitive and not _has_mfa_condition(statement.get("Condition")):
            findings.append(PolicyFinding(
                "IAM003", index,
                "IAM or role-assumption permission has no explicit MFA condition",
            ))
    return tuple(findings)
