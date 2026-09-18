"""Verify one local signed-request fixture without contacting a service."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Mapping, Sequence

from .verification import (
    AgentCredential,
    MemoryNonceStore,
    RequestFormatError,
    SignedToolRequest,
    verify_request,
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
        description="Verify a local Ed25519 request fixture and reserve its nonce"
    )
    parser.add_argument("--request", required=True, type=Path)
    parser.add_argument("--credential", required=True, type=Path)
    parser.add_argument("--now", required=True, type=int)
    parser.add_argument("--max-skew", type=int, default=60)
    parser.add_argument("--nonce-ttl", type=int, default=300)
    args = parser.parse_args(argv)

    try:
        request = SignedToolRequest.from_dict(_json_object(args.request, "request"))
        credential = AgentCredential.from_dict(
            _json_object(args.credential, "credential")
        )
        decision = verify_request(
            request,
            credential=credential,
            nonces=MemoryNonceStore(),
            now=args.now,
            max_skew_seconds=args.max_skew,
            nonce_ttl_seconds=args.nonce_ttl,
        )
    except (OSError, RequestFormatError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    print(json.dumps(decision.to_dict(), sort_keys=True))
    return 0 if decision.allowed else 1


if __name__ == "__main__":
    raise SystemExit(main())
