"""Validate a local AWS cost and teardown plan without contacting AWS."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from pathlib import Path
from typing import Any, Mapping


MONEY_PATTERN = re.compile(r"^(0|[1-9][0-9]*)(\.[0-9]{1,2})?$")
IDENTIFIER_PATTERN = re.compile(r"^[a-z0-9][a-z0-9-]{2,63}$")
PLAN_FIELDS = {
    "schema_version",
    "project",
    "owner",
    "currency",
    "monthly_budget_usd",
    "alert_thresholds_percent",
    "controls",
    "resources",
}
CONTROL_FIELDS = {
    "root_mfa_confirmed",
    "budget_alert_configured",
    "unbounded_usage_allowed",
}
RESOURCE_FIELDS = {
    "resource_id",
    "service",
    "region",
    "monthly_cap_usd",
    "termination_condition",
    "teardown_steps",
    "verification",
}


class CostPlanError(ValueError):
    """Raised when a cost plan cannot enforce its stated budget boundary."""


def _exact_fields(value: Mapping[str, Any], expected: set[str], label: str) -> None:
    missing = sorted(expected - set(value))
    extra = sorted(set(value) - expected)
    if missing:
        raise CostPlanError(f"{label} is missing fields: {', '.join(missing)}")
    if extra:
        raise CostPlanError(f"{label} has unknown fields: {', '.join(extra)}")


def _text(value: Any, field_name: str, *, maximum: int = 256) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CostPlanError(f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise CostPlanError(f"{field_name} exceeds {maximum} characters")
    return normalized


def _money(value: Any, field_name: str, *, allow_zero: bool = True) -> Decimal:
    if not isinstance(value, str) or not MONEY_PATTERN.fullmatch(value):
        raise CostPlanError(f"{field_name} must be a USD string with at most two decimals")
    try:
        amount = Decimal(value)
    except InvalidOperation as exc:
        raise CostPlanError(f"{field_name} is not valid money") from exc
    if amount < 0 or (amount == 0 and not allow_zero):
        rule = "positive" if not allow_zero else "non-negative"
        raise CostPlanError(f"{field_name} must be {rule}")
    return amount.quantize(Decimal("0.01"))


def _canonical(value: Mapping[str, Any]) -> bytes:
    try:
        return json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise CostPlanError("cost plan must contain finite JSON values") from exc


@dataclass(frozen=True, slots=True)
class ResourcePlan:
    resource_id: str
    service: str
    region: str
    monthly_cap_usd: Decimal
    termination_condition: str
    teardown_steps: tuple[str, ...]
    verification: str


@dataclass(frozen=True, slots=True)
class CostPlanSummary:
    project: str
    owner: str
    monthly_budget_usd: Decimal
    planned_cap_usd: Decimal
    remaining_usd: Decimal
    alert_thresholds_percent: tuple[int, ...]
    resources: tuple[ResourcePlan, ...]
    plan_sha256: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "project": self.project,
            "owner": self.owner,
            "currency": "USD",
            "monthly_budget_usd": f"{self.monthly_budget_usd:.2f}",
            "planned_cap_usd": f"{self.planned_cap_usd:.2f}",
            "remaining_usd": f"{self.remaining_usd:.2f}",
            "alert_thresholds_percent": list(self.alert_thresholds_percent),
            "resource_ids": [item.resource_id for item in self.resources],
            "plan_sha256": self.plan_sha256,
        }


def _thresholds(value: Any) -> tuple[int, ...]:
    if not isinstance(value, list) or not value:
        raise CostPlanError("alert_thresholds_percent must be a non-empty list")
    if any(type(item) is not int or not 1 <= item <= 100 for item in value):
        raise CostPlanError("alert thresholds must be integers from 1 to 100")
    thresholds = tuple(value)
    if tuple(sorted(set(thresholds))) != thresholds:
        raise CostPlanError("alert thresholds must be unique and increasing")
    if thresholds[0] > 50 or thresholds[-1] != 100:
        raise CostPlanError("alerts must start at or below 50 percent and include 100 percent")
    return thresholds


def _controls(value: Any) -> None:
    if not isinstance(value, Mapping):
        raise CostPlanError("controls must be an object")
    _exact_fields(value, CONTROL_FIELDS, "controls")
    if any(type(value[field]) is not bool for field in CONTROL_FIELDS):
        raise CostPlanError("cost controls must be booleans")
    if not value["root_mfa_confirmed"]:
        raise CostPlanError("root MFA must be confirmed before the plan is ready")
    if not value["budget_alert_configured"]:
        raise CostPlanError("a budget alert must be configured before the plan is ready")
    if value["unbounded_usage_allowed"]:
        raise CostPlanError("unbounded usage cannot be allowed")


def _resource(value: Any, position: int) -> ResourcePlan:
    label = f"resource {position}"
    if not isinstance(value, Mapping):
        raise CostPlanError(f"{label} must be an object")
    _exact_fields(value, RESOURCE_FIELDS, label)
    resource_id = _text(value["resource_id"], f"{label}.resource_id", maximum=64)
    if not IDENTIFIER_PATTERN.fullmatch(resource_id):
        raise CostPlanError(f"{label}.resource_id has an invalid format")
    steps = value["teardown_steps"]
    if not isinstance(steps, list) or not steps:
        raise CostPlanError(f"{label}.teardown_steps must be a non-empty list")
    normalized_steps = tuple(
        _text(step, f"{label}.teardown_steps", maximum=256) for step in steps
    )
    if len(set(normalized_steps)) != len(normalized_steps):
        raise CostPlanError(f"{label}.teardown_steps must not contain duplicates")
    return ResourcePlan(
        resource_id=resource_id,
        service=_text(value["service"], f"{label}.service", maximum=128),
        region=_text(value["region"], f"{label}.region", maximum=64),
        monthly_cap_usd=_money(
            value["monthly_cap_usd"],
            f"{label}.monthly_cap_usd",
            allow_zero=False,
        ),
        termination_condition=_text(
            value["termination_condition"],
            f"{label}.termination_condition",
        ),
        teardown_steps=normalized_steps,
        verification=_text(value["verification"], f"{label}.verification"),
    )


def validate_cost_plan(value: Mapping[str, Any]) -> CostPlanSummary:
    """Validate one explicit monthly budget and teardown plan."""

    if not isinstance(value, Mapping):
        raise CostPlanError("cost plan must be an object")
    _exact_fields(value, PLAN_FIELDS, "cost plan")
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        raise CostPlanError("schema_version must be 1")
    if value["currency"] != "USD":
        raise CostPlanError("currency must be USD")
    project = _text(value["project"], "project", maximum=128)
    owner = _text(value["owner"], "owner", maximum=128)
    budget = _money(value["monthly_budget_usd"], "monthly_budget_usd", allow_zero=False)
    thresholds = _thresholds(value["alert_thresholds_percent"])
    _controls(value["controls"])
    resource_values = value["resources"]
    if not isinstance(resource_values, list) or not resource_values:
        raise CostPlanError("resources must be a non-empty list")
    resources = tuple(
        _resource(item, position)
        for position, item in enumerate(resource_values, start=1)
    )
    resource_ids = [item.resource_id for item in resources]
    if len(resource_ids) != len(set(resource_ids)):
        raise CostPlanError("resource_id values must be unique")
    planned = sum((item.monthly_cap_usd for item in resources), Decimal("0.00"))
    if planned > budget:
        raise CostPlanError("planned resource caps exceed the monthly budget")
    return CostPlanSummary(
        project=project,
        owner=owner,
        monthly_budget_usd=budget,
        planned_cap_usd=planned,
        remaining_usd=budget - planned,
        alert_thresholds_percent=thresholds,
        resources=resources,
        plan_sha256=hashlib.sha256(_canonical(value)).hexdigest(),
    )


def load_cost_plan(path: Path) -> CostPlanSummary:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise CostPlanError(f"cannot read cost plan {path}") from exc
    return validate_cost_plan(value)
