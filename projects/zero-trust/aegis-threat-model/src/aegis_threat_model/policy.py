"""Fixture oracle for the least-privilege Rego policy contract."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Literal, Mapping


Effect = Literal["allow", "deny", "step_up"]
Sensitivity = Literal["low", "medium", "high"]


class PolicyContractError(ValueError):
    """Raised when policy data or a case would require an implicit assumption."""


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise PolicyContractError(f"{field_name} must be an object")
    return value


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise PolicyContractError(f"{field_name} must be a non-empty string")
    return value.strip()


def _exact_fields(value: Mapping[str, Any], expected: set[str], field_name: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise PolicyContractError(f"{field_name} is missing fields: {', '.join(missing)}")
    if extra:
        raise PolicyContractError(f"{field_name} has unknown fields: {', '.join(extra)}")


def _roles(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise PolicyContractError(f"{field_name} must be a non-empty list")
    roles = tuple(_text(item, field_name) for item in value)
    if len(roles) != len(set(roles)):
        raise PolicyContractError(f"{field_name} must not contain duplicates")
    return tuple(sorted(roles))


@dataclass(frozen=True, slots=True)
class ToolRule:
    tool_name: str
    roles: tuple[str, ...]
    sensitivity: Sensitivity


@dataclass(frozen=True, slots=True)
class PolicyData:
    step_up_risk: int
    agent_roles: Mapping[str, tuple[str, ...]]
    tools: Mapping[str, ToolRule]

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyData":
        value = _mapping(value, "policy data")
        _exact_fields(
            value,
            {"schema_version", "thresholds", "agent_roles", "tools"},
            "policy data",
        )
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise PolicyContractError("policy data schema_version must be 1")

        thresholds = _mapping(value["thresholds"], "thresholds")
        _exact_fields(thresholds, {"step_up_risk"}, "thresholds")
        step_up_risk = thresholds["step_up_risk"]
        if type(step_up_risk) is not int or not 0 <= step_up_risk <= 100:
            raise PolicyContractError("step_up_risk must be an integer from 0 to 100")

        raw_agent_roles = _mapping(value["agent_roles"], "agent_roles")
        if not raw_agent_roles:
            raise PolicyContractError("agent_roles must not be empty")
        agent_roles: dict[str, tuple[str, ...]] = {}
        for agent_id, raw_roles in raw_agent_roles.items():
            normalized_id = _text(agent_id, "agent_id")
            agent_roles[normalized_id] = _roles(
                raw_roles,
                f"agent_roles.{normalized_id}",
            )

        raw_tools = _mapping(value["tools"], "tools")
        if not raw_tools:
            raise PolicyContractError("tools must not be empty")
        tools: dict[str, ToolRule] = {}
        for tool_name, raw_rule in raw_tools.items():
            normalized_name = _text(tool_name, "tool_name")
            rule = _mapping(raw_rule, f"tools.{normalized_name}")
            _exact_fields(rule, {"roles", "sensitivity"}, f"tools.{normalized_name}")
            sensitivity = _text(
                rule["sensitivity"],
                f"tools.{normalized_name}.sensitivity",
            )
            if sensitivity not in {"low", "medium", "high"}:
                raise PolicyContractError(
                    f"tools.{normalized_name}.sensitivity is not supported"
                )
            tools[normalized_name] = ToolRule(
                tool_name=normalized_name,
                roles=_roles(rule["roles"], f"tools.{normalized_name}.roles"),
                sensitivity=sensitivity,
            )

        declared_roles = {role for roles in agent_roles.values() for role in roles}
        unused_roles = sorted(
            {role for rule in tools.values() for role in rule.roles} - declared_roles
        )
        if unused_roles:
            raise PolicyContractError(
                f"tool rules reference undeclared roles: {', '.join(unused_roles)}"
            )
        return cls(
            step_up_risk=step_up_risk,
            agent_roles=MappingProxyType(dict(sorted(agent_roles.items()))),
            tools=MappingProxyType(dict(sorted(tools.items()))),
        )


@dataclass(frozen=True, slots=True)
class PolicyInput:
    agent_id: str
    tool_name: str
    risk_score: int
    step_up_token_valid: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "tool_name": self.tool_name,
            "risk_score": self.risk_score,
            "step_up_token_valid": self.step_up_token_valid,
        }

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "PolicyInput":
        value = _mapping(value, "case input")
        _exact_fields(
            value,
            {"agent_id", "tool_name", "risk_score", "step_up_token_valid"},
            "case input",
        )
        risk_score = value["risk_score"]
        if type(risk_score) is not int or not 0 <= risk_score <= 100:
            raise PolicyContractError("risk_score must be an integer from 0 to 100")
        if type(value["step_up_token_valid"]) is not bool:
            raise PolicyContractError("step_up_token_valid must be a boolean")
        return cls(
            agent_id=_text(value["agent_id"], "agent_id"),
            tool_name=_text(value["tool_name"], "tool_name"),
            risk_score=risk_score,
            step_up_token_valid=value["step_up_token_valid"],
        )


@dataclass(frozen=True, slots=True)
class PolicyDecision:
    effect: Effect
    reason: str

    def to_dict(self) -> dict[str, str]:
        return {"effect": self.effect, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class PolicyCase:
    case_id: str
    policy_input: PolicyInput
    expected: PolicyDecision


def decide(policy: PolicyData, policy_input: PolicyInput) -> PolicyDecision:
    """Evaluate the fixture contract mirrored by the Rego policy."""

    rule = policy.tools.get(policy_input.tool_name)
    if rule is None:
        return PolicyDecision("deny", "unknown_tool")
    roles = set(policy.agent_roles.get(policy_input.agent_id, ()))
    if not roles.intersection(rule.roles):
        return PolicyDecision("deny", "role_not_allowed")
    if (
        rule.sensitivity == "high"
        and policy_input.risk_score >= policy.step_up_risk
        and not policy_input.step_up_token_valid
    ):
        return PolicyDecision("step_up", "step_up_required")
    return PolicyDecision("allow", "authorized")


def parse_case_suite(value: Mapping[str, Any]) -> tuple[PolicyCase, ...]:
    value = _mapping(value, "case suite")
    _exact_fields(value, {"schema_version", "cases"}, "case suite")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise PolicyContractError("case suite schema_version must be 1")
    raw_cases = value["cases"]
    if not isinstance(raw_cases, list) or not raw_cases:
        raise PolicyContractError("cases must be a non-empty list")

    cases: list[PolicyCase] = []
    case_ids: set[str] = set()
    for index, raw_case in enumerate(raw_cases):
        item = _mapping(raw_case, f"cases[{index}]")
        _exact_fields(item, {"case_id", "input", "expected"}, f"cases[{index}]")
        case_id = _text(item["case_id"], f"cases[{index}].case_id")
        if case_id in case_ids:
            raise PolicyContractError(f"duplicate case_id: {case_id}")
        case_ids.add(case_id)
        expected = _mapping(item["expected"], f"{case_id}.expected")
        _exact_fields(expected, {"effect", "reason"}, f"{case_id}.expected")
        effect = _text(expected["effect"], f"{case_id}.expected.effect")
        if effect not in {"allow", "deny", "step_up"}:
            raise PolicyContractError(f"{case_id}.expected.effect is not supported")
        cases.append(
            PolicyCase(
                case_id=case_id,
                policy_input=PolicyInput.from_dict(item["input"]),
                expected=PolicyDecision(
                    effect=effect,
                    reason=_text(expected["reason"], f"{case_id}.expected.reason"),
                ),
            )
        )
    return tuple(cases)


def evaluate_cases(
    policy: PolicyData,
    cases: tuple[PolicyCase, ...],
) -> dict[str, Any]:
    mismatches = []
    effects: Counter[str] = Counter()
    for case in cases:
        actual = decide(policy, case.policy_input)
        effects[actual.effect] += 1
        if actual != case.expected:
            mismatches.append(
                {
                    "case_id": case.case_id,
                    "expected": case.expected.to_dict(),
                    "actual": actual.to_dict(),
                }
            )
    return {
        "schema_version": 1,
        "case_count": len(cases),
        "matched_count": len(cases) - len(mismatches),
        "effects": dict(sorted(effects.items())),
        "mismatches": mismatches,
    }


def load_json(path: str | Path) -> Mapping[str, Any]:
    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise PolicyContractError(f"{source}: invalid JSON ({exc.msg})") from exc
    return _mapping(value, str(source))


def check_rego_structure(path: str | Path) -> None:
    """Check required policy anchors without claiming Rego execution."""

    source_path = Path(path)
    source = source_path.read_text(encoding="utf-8")
    required = (
        "package aegis.authorization",
        "import rego.v1",
        "default decision",
        "role_allowed",
        "requires_step_up",
        "step_up_token_valid",
    )
    missing = [fragment for fragment in required if fragment not in source]
    if missing:
        raise PolicyContractError(
            f"{source_path}: missing Rego contract anchors: {', '.join(missing)}"
        )
