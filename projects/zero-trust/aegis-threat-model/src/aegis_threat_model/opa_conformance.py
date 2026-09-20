"""Run reviewed policy cases through an installed OPA executable."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Sequence

from .policy import PolicyCase, PolicyDecision


OPA_QUERY = "data.aegis.authorization.decision"


class OpaConformanceError(RuntimeError):
    """Raised when OPA cannot return one reviewable decision."""


@dataclass(frozen=True, slots=True)
class OpaCaseResult:
    case_id: str
    expected: PolicyDecision
    actual: PolicyDecision

    @property
    def matched(self) -> bool:
        return self.expected == self.actual

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "expected": self.expected.to_dict(),
            "actual": self.actual.to_dict(),
            "matched": self.matched,
        }


def _decision_from_result(value: Any) -> PolicyDecision:
    try:
        expressions = value["result"][0]["expressions"]
        decision = expressions[0]["value"]
    except (KeyError, IndexError, TypeError) as exc:
        raise OpaConformanceError("OPA result did not contain one decision") from exc
    if not isinstance(decision, dict) or set(decision) != {"effect", "reason"}:
        raise OpaConformanceError("OPA decision must contain effect and reason only")
    effect = decision["effect"]
    reason = decision["reason"]
    if effect not in {"allow", "deny", "step_up"}:
        raise OpaConformanceError("OPA decision effect is not supported")
    if not isinstance(reason, str) or not reason.strip():
        raise OpaConformanceError("OPA decision reason must be a non-empty string")
    return PolicyDecision(effect=effect, reason=reason.strip())


def evaluate_case_with_opa(
    case: PolicyCase,
    *,
    rego_path: str | Path,
    data_path: str | Path,
    opa_binary: str | Path = "opa",
    timeout_seconds: float = 5.0,
) -> PolicyDecision:
    """Evaluate one case using OPA without a server or network request."""

    if not isinstance(timeout_seconds, (int, float)) or timeout_seconds <= 0:
        raise OpaConformanceError("timeout_seconds must be positive")
    command = [
        str(opa_binary),
        "eval",
        "--format=json",
        "--data",
        str(Path(rego_path)),
        "--data",
        str(Path(data_path)),
        "--stdin-input",
        OPA_QUERY,
    ]
    try:
        completed = subprocess.run(
            command,
            input=json.dumps(case.policy_input.to_dict(), sort_keys=True),
            capture_output=True,
            check=False,
            text=True,
            timeout=float(timeout_seconds),
        )
    except FileNotFoundError as exc:
        raise OpaConformanceError(
            f"OPA executable was not found: {opa_binary}"
        ) from exc
    except subprocess.TimeoutExpired as exc:
        raise OpaConformanceError("OPA evaluation exceeded the timeout") from exc

    if completed.returncode != 0:
        detail = completed.stderr.strip().splitlines()
        suffix = f": {detail[0][:200]}" if detail else ""
        raise OpaConformanceError(f"OPA evaluation failed{suffix}")
    try:
        value = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:
        raise OpaConformanceError("OPA output was not valid JSON") from exc
    return _decision_from_result(value)


def run_opa_cases(
    cases: Sequence[PolicyCase],
    *,
    rego_path: str | Path,
    data_path: str | Path,
    opa_binary: str | Path = "opa",
    timeout_seconds: float = 5.0,
) -> dict[str, Any]:
    """Run cases in declared order and report every mismatch."""

    results = tuple(
        OpaCaseResult(
            case_id=case.case_id,
            expected=case.expected,
            actual=evaluate_case_with_opa(
                case,
                rego_path=rego_path,
                data_path=data_path,
                opa_binary=opa_binary,
                timeout_seconds=timeout_seconds,
            ),
        )
        for case in cases
    )
    mismatches = [result.to_dict() for result in results if not result.matched]
    return {
        "schema_version": 1,
        "engine": "opa",
        "query": OPA_QUERY,
        "case_count": len(results),
        "matched_count": len(results) - len(mismatches),
        "mismatches": mismatches,
    }
