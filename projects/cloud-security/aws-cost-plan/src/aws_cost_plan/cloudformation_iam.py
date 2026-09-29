"""Review embedded IAM identity policies in a bounded CloudFormation JSON subset."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .iam_policy import IamPolicyError, review_identity_policy


POLICY_TYPES = {"AWS::IAM::Policy", "AWS::IAM::ManagedPolicy"}


class CloudFormationPolicyError(ValueError):
    """Raised when a template policy cannot be reviewed without guessing."""


@dataclass(frozen=True, slots=True)
class TemplateFinding:
    logical_id: str
    policy_name: str
    code: str
    statement: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "logical_id": self.logical_id,
            "policy_name": self.policy_name,
            "code": self.code,
            "statement": self.statement,
            "message": self.message,
        }


def _review_document(
    logical_id: str, policy_name: str, document: Any
) -> list[TemplateFinding]:
    try:
        findings = review_identity_policy(document)
    except IamPolicyError as exc:
        raise CloudFormationPolicyError(
            f"resource {logical_id} policy {policy_name}: {exc}"
        ) from exc
    return [
        TemplateFinding(logical_id, policy_name, item.code, item.statement, item.message)
        for item in findings
    ]


def review_cloudformation_template(value: Mapping[str, Any]) -> tuple[TemplateFinding, ...]:
    """Review inline IAM policies in a JSON CloudFormation template.

    This recognizes AWS::IAM::Role inline Policies, AWS::IAM::Policy, and
    AWS::IAM::ManagedPolicy. YAML and intrinsic-function expressions inside policy
    documents are not evaluated. Unsupported policy grammar fails closed.
    """
    if not isinstance(value, Mapping):
        raise CloudFormationPolicyError("template must be an object")
    resources = value.get("Resources")
    if not isinstance(resources, Mapping):
        raise CloudFormationPolicyError("template Resources must be an object")

    findings: list[TemplateFinding] = []
    for logical_id, resource in resources.items():
        if not isinstance(logical_id, str) or not logical_id:
            raise CloudFormationPolicyError("resource logical IDs must be non-empty strings")
        if not isinstance(resource, Mapping):
            raise CloudFormationPolicyError(f"resource {logical_id} must be an object")
        resource_type = resource.get("Type")
        if resource_type != "AWS::IAM::Role" and resource_type not in POLICY_TYPES:
            continue
        properties = resource.get("Properties", {})
        if not isinstance(properties, Mapping):
            raise CloudFormationPolicyError(f"resource {logical_id} Properties must be an object")

        if resource_type == "AWS::IAM::Role":
            policies = properties.get("Policies", [])
            if not isinstance(policies, list):
                raise CloudFormationPolicyError(f"resource {logical_id} Policies must be a list")
            for index, policy in enumerate(policies, start=1):
                if not isinstance(policy, Mapping):
                    raise CloudFormationPolicyError(
                        f"resource {logical_id} policy {index} must be an object"
                    )
                name = policy.get("PolicyName")
                if not isinstance(name, str) or not name.strip():
                    raise CloudFormationPolicyError(
                        f"resource {logical_id} policy {index} needs a literal PolicyName"
                    )
                if "PolicyDocument" not in policy:
                    raise CloudFormationPolicyError(
                        f"resource {logical_id} policy {name} is missing PolicyDocument"
                    )
                findings.extend(_review_document(logical_id, name, policy["PolicyDocument"]))
        elif "PolicyDocument" not in properties:
            raise CloudFormationPolicyError(
                f"resource {logical_id} is missing PolicyDocument"
            )
        else:
            name = properties.get("PolicyName") or properties.get("ManagedPolicyName")
            if not isinstance(name, str) or not name.strip():
                name = resource_type.rsplit("::", 1)[-1]
            findings.extend(_review_document(logical_id, name, properties["PolicyDocument"]))
    return tuple(findings)
