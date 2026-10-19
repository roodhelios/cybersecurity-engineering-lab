"""Evaluate one local signed request through verification and policy."""

from __future__ import annotations

import argparse
import json
import sys
from functools import partial
from pathlib import Path
from typing import Any, Mapping, Sequence

from .authorization import authorize_signed_request
from .opa_conformance import evaluate_input_with_opa, OpaConformanceError
from .policy import PolicyContractError, PolicyData, load_json
from .verification import (
    AgentCredential,
    MemoryNonceStore,
    RequestFormatError,
    SignedToolRequest,
)


def _json_object(path: Path, field_name: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise RequestFormatError(f"{path}: invalid JSON ({exc.msg})") from exc
    if not isinstance(value, Mapping):
        raise RequestFormatError(f"{field_name} must be a JSON object")
    return value


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Check a local signed request before least-privilege policy"
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--credential", required=True, type=Path)
    parser.add_argument("--policy", required=True, type=Path)
    parser.add_argument("--risk-score", required=True, type=int)
    parser.add_argument("--step-up-token-valid", action="store_true")
    parser.add_argument("--now", required=True, type=int)
    parser.add_argument("--max-skew", type=int, default=60)
    parser.add_argument("--nonce-ttl", type=int, default=300)
    parser.add_argument("--opa", type=Path, help="use an installed OPA executable, never fall back to the oracle")
    parser.add_argument("--rego", type=Path, help="trusted local Rego policy, required with --opa")
    args = parser.parse_args(argv)
    if (args.opa is None) != (args.rego is None):
        parser.error("--opa and --rego must be supplied together")

    try:
        request = SignedToolRequest.from_dict(_json_object(args.request, "request"))
        credential = AgentCredential.from_dict(
            _json_object(args.credential, "credential")
        )
        policy = PolicyData.from_dict(load_json(args.policy))
        evaluator = None if args.opa is None else partial(evaluate_input_with_opa,
            opa_binary=args.opa, rego_path=args.rego, data_path=args.policy)
        decision = authorize_signed_request(
            request,
            credential=credential,
            nonces=MemoryNonceStore(),
            policy=policy,
            risk_score=args.risk_score,
            step_up_token_valid=args.step_up_token_valid,
            now=args.now,
            max_skew_seconds=args.max_skew,
            nonce_ttl_seconds=args.nonce_ttl,
            policy_evaluator=evaluator,
        )
    except (OSError, PolicyContractError, RequestFormatError, ValueError, OpaConformanceError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    result = decision.to_dict()
    if args.opa is not None:
        result["policy_engine"] = "opa" if decision.stage == "policy" else "not_evaluated"
    print(json.dumps(result, sort_keys=True))
    return 0 if decision.effect == "allow" else 1


if __name__ == "__main__":
    raise SystemExit(main())
