"""Local Ed25519 request verification with bounded replay protection."""

from __future__ import annotations

import base64
import binascii
import json
from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


MAX_IDENTIFIER_LENGTH = 128
MAX_NONCE_LENGTH = 128
MIN_NONCE_LENGTH = 16
MAX_ARGUMENT_BYTES = 16_384


class RequestFormatError(ValueError):
    """Raised when a request or credential cannot be represented safely."""


def _text(value: Any, field_name: str, *, maximum: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise RequestFormatError(f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise RequestFormatError(f"{field_name} exceeds {maximum} characters")
    return normalized


def _canonical_arguments(value: Any) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RequestFormatError("tool_args must be an object")
    try:
        encoded = json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise RequestFormatError("tool_args must contain finite JSON values") from exc
    if len(encoded) > MAX_ARGUMENT_BYTES:
        raise RequestFormatError(
            f"tool_args canonical form exceeds {MAX_ARGUMENT_BYTES} bytes"
        )
    return MappingProxyType(dict(value))


@dataclass(frozen=True, slots=True)
class SignedToolRequest:
    agent_id: str
    session_id: str
    tool_name: str
    tool_args: Mapping[str, Any]
    timestamp: int
    nonce: str
    signature_b64: str

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "SignedToolRequest":
        if not isinstance(value, Mapping):
            raise RequestFormatError("request must be an object")
        expected = {
            "agent_id",
            "session_id",
            "tool_name",
            "tool_args",
            "timestamp",
            "nonce",
            "signature_b64",
        }
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        if missing:
            raise RequestFormatError(f"request is missing fields: {', '.join(missing)}")
        if extra:
            raise RequestFormatError(f"request has unknown fields: {', '.join(extra)}")
        timestamp = value["timestamp"]
        if type(timestamp) is not int or timestamp < 0:
            raise RequestFormatError("timestamp must be a non-negative integer")
        nonce = _text(value["nonce"], "nonce", maximum=MAX_NONCE_LENGTH)
        if len(nonce) < MIN_NONCE_LENGTH:
            raise RequestFormatError(
                f"nonce must contain at least {MIN_NONCE_LENGTH} characters"
            )
        return cls(
            agent_id=_text(
                value["agent_id"], "agent_id", maximum=MAX_IDENTIFIER_LENGTH
            ),
            session_id=_text(
                value["session_id"], "session_id", maximum=MAX_IDENTIFIER_LENGTH
            ),
            tool_name=_text(
                value["tool_name"], "tool_name", maximum=MAX_IDENTIFIER_LENGTH
            ),
            tool_args=_canonical_arguments(value["tool_args"]),
            timestamp=timestamp,
            nonce=nonce,
            signature_b64=_text(
                value["signature_b64"], "signature_b64", maximum=256
            ),
        )


@dataclass(frozen=True, slots=True)
class AgentCredential:
    agent_id: str
    status: str
    public_key_b64: str
    key_version: int

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AgentCredential":
        if not isinstance(value, Mapping):
            raise RequestFormatError("credential must be an object")
        expected = {"agent_id", "status", "public_key_b64", "key_version"}
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        if missing:
            raise RequestFormatError(f"credential is missing fields: {', '.join(missing)}")
        if extra:
            raise RequestFormatError(
                f"credential has unknown fields: {', '.join(extra)}"
            )
        key_version = value["key_version"]
        if type(key_version) is not int or key_version < 1:
            raise RequestFormatError("key_version must be a positive integer")
        return cls(
            agent_id=_text(
                value["agent_id"], "agent_id", maximum=MAX_IDENTIFIER_LENGTH
            ),
            status=_text(value["status"], "status", maximum=32).lower(),
            public_key_b64=_text(
                value["public_key_b64"], "public_key_b64", maximum=128
            ),
            key_version=key_version,
        )


@dataclass(frozen=True, slots=True)
class VerificationDecision:
    allowed: bool
    reason: str
    key_version: int | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "allowed": self.allowed,
            "reason": self.reason,
            "key_version": self.key_version,
        }


class NonceStore(Protocol):
    def reserve(self, key: str, *, expires_at: int, now: int) -> bool:
        """Atomically reserve a nonce key until the supplied expiry."""


class MemoryNonceStore:
    """Single-process nonce store for deterministic local tests and examples."""

    def __init__(self) -> None:
        self._expirations: dict[str, int] = {}

    def reserve(self, key: str, *, expires_at: int, now: int) -> bool:
        self._expirations = {
            item: expiry for item, expiry in self._expirations.items() if expiry > now
        }
        if key in self._expirations:
            return False
        self._expirations[key] = expires_at
        return True


def canonical_request(request: SignedToolRequest) -> bytes:
    """Serialize exactly the fields covered by the request signature."""

    return json.dumps(
        {
            "agent_id": request.agent_id,
            "nonce": request.nonce,
            "session_id": request.session_id,
            "timestamp": request.timestamp,
            "tool_args": dict(request.tool_args),
            "tool_name": request.tool_name,
        },
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")


def _verified_signature(request: SignedToolRequest, public_key_b64: str) -> bool:
    try:
        public_key = base64.b64decode(public_key_b64, validate=True)
        signature = base64.b64decode(request.signature_b64, validate=True)
        if len(public_key) != 32 or len(signature) != 64:
            return False
        Ed25519PublicKey.from_public_bytes(public_key).verify(
            signature,
            canonical_request(request),
        )
    except (binascii.Error, InvalidSignature, TypeError, ValueError):
        return False
    return True


def verify_request(
    request: SignedToolRequest,
    *,
    credential: AgentCredential | None,
    nonces: NonceStore,
    now: int,
    max_skew_seconds: int = 60,
    nonce_ttl_seconds: int = 300,
) -> VerificationDecision:
    """Verify identity, time, signature, and one-time nonce in fail-closed order."""

    if type(now) is not int or now < 0:
        raise ValueError("now must be a non-negative integer")
    if type(max_skew_seconds) is not int or max_skew_seconds < 0:
        raise ValueError("max_skew_seconds must be a non-negative integer")
    if type(nonce_ttl_seconds) is not int or nonce_ttl_seconds < 2 * max_skew_seconds:
        raise ValueError("nonce_ttl_seconds must cover twice the accepted clock skew")
    if credential is None or credential.agent_id != request.agent_id:
        return VerificationDecision(False, "unknown_agent")
    if credential.status != "active":
        return VerificationDecision(False, "agent_not_active")
    if type(request.timestamp) is not int or request.timestamp < 0:
        return VerificationDecision(False, "invalid_timestamp")
    if abs(now - request.timestamp) > max_skew_seconds:
        return VerificationDecision(False, "stale_timestamp")
    if not isinstance(request.nonce, str) or not (
        MIN_NONCE_LENGTH <= len(request.nonce) <= MAX_NONCE_LENGTH
    ):
        return VerificationDecision(False, "invalid_nonce")
    if not _verified_signature(request, credential.public_key_b64):
        return VerificationDecision(False, "invalid_signature")

    nonce_key = f"{request.agent_id}:{request.nonce}"
    if not nonces.reserve(
        nonce_key,
        expires_at=now + nonce_ttl_seconds,
        now=now,
    ):
        return VerificationDecision(False, "replay_detected")
    return VerificationDecision(True, "verified", credential.key_version)
