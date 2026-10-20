"""Review IAM identity policies in a bounded Terraform plan JSON subset."""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from .iam_policy import IamPolicyError, review_identity_policy


SUPPORTED_RESOURCE_TYPES = {"aws_iam_policy", "aws_iam_role_policy"}
MAX_MODULES = 1_000
MAX_RESOURCES = 20_000


class TerraformPolicyError(ValueError):
    """Raised when a planned IAM policy cannot be reviewed without guessing."""


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, item in pairs:
        if key in result:
            raise TerraformPolicyError(f"duplicate JSON field: {key}")
        result[key] = item
    return result


def load_terraform_json(payload: str | bytes) -> Any:
    """Decode JSON while rejecting duplicate object fields."""
    try:
        return json.loads(payload, object_pairs_hook=_unique_object)
    except json.JSONDecodeError as exc:
        raise TerraformPolicyError(f"invalid JSON: {exc.msg}") from exc
    except RecursionError as exc:
        raise TerraformPolicyError("JSON nesting is too deep") from exc


@dataclass(frozen=True, slots=True)
class TerraformFinding:
    address: str
    policy_name: str
    code: str
    statement: int
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "address": self.address,
            "policy_name": self.policy_name,
            "code": self.code,
            "statement": self.statement,
            "message": self.message,
        }


def _policy_document(address: str, raw_policy: Any) -> Mapping[str, Any]:
    if not isinstance(raw_policy, str) or not raw_policy.strip():
        raise TerraformPolicyError(
            f"resource {address} policy must be a non-empty JSON string"
        )
    try:
        document = load_terraform_json(raw_policy)
    except TerraformPolicyError as exc:
        raise TerraformPolicyError(f"resource {address} policy: {exc}") from exc
    if not isinstance(document, Mapping):
        raise TerraformPolicyError(f"resource {address} policy must decode to an object")
    return document


def _module_resources(module: Mapping[str, Any], location: str) -> list[Mapping[str, Any]]:
    collected: list[Mapping[str, Any]] = []
    pending: list[tuple[Mapping[str, Any], str]] = [(module, location)]
    modules_seen = 0
    while pending:
        current, current_location = pending.pop()
        modules_seen += 1
        if modules_seen > MAX_MODULES:
            raise TerraformPolicyError(f"plan exceeds the {MAX_MODULES} module limit")
        resources = current.get("resources", [])
        if not isinstance(resources, list):
            raise TerraformPolicyError(f"{current_location} resources must be a list")
        for index, resource in enumerate(resources, start=1):
            if not isinstance(resource, Mapping):
                raise TerraformPolicyError(
                    f"{current_location} resource {index} must be an object"
                )
            collected.append(resource)
            if len(collected) > MAX_RESOURCES:
                raise TerraformPolicyError(
                    f"plan exceeds the {MAX_RESOURCES} resource limit"
                )

        children = current.get("child_modules", [])
        if not isinstance(children, list):
            raise TerraformPolicyError(
                f"{current_location} child_modules must be a list"
            )
        reviewed_children: list[tuple[Mapping[str, Any], str]] = []
        for index, child in enumerate(children, start=1):
            if not isinstance(child, Mapping):
                raise TerraformPolicyError(
                    f"{current_location} child module {index} must be an object"
                )
            child_address = child.get("address")
            if not isinstance(child_address, str) or not child_address.strip():
                raise TerraformPolicyError(
                    f"{current_location} child module {index} needs a non-empty address"
                )
            reviewed_children.append((child, child_address))
        pending.extend(reversed(reviewed_children))
    return collected


def review_terraform_plan(value: Mapping[str, Any]) -> tuple[TerraformFinding, ...]:
    """Review supported IAM policies in ``terraform show -json`` plan output.

    Only planned managed ``aws_iam_policy`` and ``aws_iam_role_policy`` resources
    are reviewed. Unknown or malformed policy values fail closed. Trust policies,
    attachments, effective permissions, and provider behavior are not evaluated.
    """
    if not isinstance(value, Mapping):
        raise TerraformPolicyError("plan must be an object")
    format_version = value.get("format_version")
    if not isinstance(format_version, str) or not format_version.startswith("1."):
        raise TerraformPolicyError("format_version must be a supported 1.x string")
    planned_values = value.get("planned_values")
    if not isinstance(planned_values, Mapping):
        raise TerraformPolicyError("planned_values must be an object")
    root_module = planned_values.get("root_module")
    if not isinstance(root_module, Mapping):
        raise TerraformPolicyError("planned_values.root_module must be an object")

    findings: list[TerraformFinding] = []
    seen_addresses: set[str] = set()
    for resource in _module_resources(root_module, "root module"):
        resource_type = resource.get("type")
        if resource_type not in SUPPORTED_RESOURCE_TYPES:
            continue
        address = resource.get("address")
        if not isinstance(address, str) or not address.strip():
            raise TerraformPolicyError("supported resource needs a non-empty address")
        if address in seen_addresses:
            raise TerraformPolicyError(f"duplicate supported resource address: {address}")
        seen_addresses.add(address)
        if resource.get("mode") != "managed":
            raise TerraformPolicyError(f"resource {address} must use managed mode")
        values = resource.get("values")
        if not isinstance(values, Mapping):
            raise TerraformPolicyError(f"resource {address} values must be an object")
        document = _policy_document(address, values.get("policy"))
        name = values.get("name")
        if not isinstance(name, str) or not name.strip():
            name = address
        try:
            policy_findings = review_identity_policy(document)
        except IamPolicyError as exc:
            raise TerraformPolicyError(f"resource {address}: {exc}") from exc
        findings.extend(
            TerraformFinding(
                address=address,
                policy_name=name,
                code=item.code,
                statement=item.statement,
                message=item.message,
            )
            for item in policy_findings
        )
    return tuple(findings)
