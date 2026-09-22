"""Versioned, hash-linked audit records for local authorization decisions."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Iterable, Literal, Mapping


AuditEffect = Literal["allow", "deny", "step_up"]
AuditStage = Literal["verification", "policy"]
SHA256_PATTERN = re.compile(r"^[0-9a-f]{64}$")
AUDIT_FIELDS = {
    "schema_version",
    "sequence",
    "recorded_at",
    "request_id",
    "agent_id",
    "session_id",
    "tool_name",
    "effect",
    "reason",
    "stage",
    "key_version",
    "previous_hash",
    "record_hash",
}


class AuditChainError(ValueError):
    """Raised when an audit record cannot preserve chain integrity."""


def _text(value: Any, field_name: str, *, maximum: int = 128) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AuditChainError(f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if len(normalized) > maximum:
        raise AuditChainError(f"{field_name} exceeds {maximum} characters")
    return normalized


def _timestamp(value: Any) -> str:
    text = _text(value, "recorded_at", maximum=64)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AuditChainError("recorded_at must be an ISO 8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise AuditChainError("recorded_at must include a UTC offset")
    return parsed.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


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
        raise AuditChainError("audit record must contain finite JSON values") from exc


def _hash(value: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


@dataclass(frozen=True, slots=True)
class AuditRecord:
    sequence: int
    recorded_at: str
    request_id: str
    agent_id: str
    session_id: str
    tool_name: str
    effect: AuditEffect
    reason: str
    stage: AuditStage
    key_version: int | None
    previous_hash: str | None
    record_hash: str

    def unsigned_dict(self) -> dict[str, Any]:
        return {
            "schema_version": 1,
            "sequence": self.sequence,
            "recorded_at": self.recorded_at,
            "request_id": self.request_id,
            "agent_id": self.agent_id,
            "session_id": self.session_id,
            "tool_name": self.tool_name,
            "effect": self.effect,
            "reason": self.reason,
            "stage": self.stage,
            "key_version": self.key_version,
            "previous_hash": self.previous_hash,
        }

    def to_dict(self) -> dict[str, Any]:
        return {**self.unsigned_dict(), "record_hash": self.record_hash}

    @classmethod
    def from_dict(cls, value: Mapping[str, Any]) -> "AuditRecord":
        if not isinstance(value, Mapping):
            raise AuditChainError("audit record must be an object")
        missing = sorted(AUDIT_FIELDS - set(value))
        extra = sorted(set(value) - AUDIT_FIELDS)
        if missing:
            raise AuditChainError(f"audit record is missing fields: {', '.join(missing)}")
        if extra:
            raise AuditChainError(f"audit record has unknown fields: {', '.join(extra)}")
        if type(value["schema_version"]) is not int or value["schema_version"] != 1:
            raise AuditChainError("schema_version must be 1")
        sequence = value["sequence"]
        if type(sequence) is not int or sequence < 1:
            raise AuditChainError("sequence must be a positive integer")
        effect = value["effect"]
        if effect not in {"allow", "deny", "step_up"}:
            raise AuditChainError("effect is not supported")
        stage = value["stage"]
        if stage not in {"verification", "policy"}:
            raise AuditChainError("stage is not supported")
        if stage == "verification" and effect != "deny":
            raise AuditChainError("verification records must have a deny effect")
        key_version = value["key_version"]
        if key_version is not None and (type(key_version) is not int or key_version < 1):
            raise AuditChainError("key_version must be null or a positive integer")
        if stage == "policy" and key_version is None:
            raise AuditChainError("policy records require a verified key_version")
        previous_hash = value["previous_hash"]
        if previous_hash is not None and not (
            isinstance(previous_hash, str) and SHA256_PATTERN.fullmatch(previous_hash)
        ):
            raise AuditChainError("previous_hash must be null or lowercase SHA-256")
        record_hash = value["record_hash"]
        if not isinstance(record_hash, str) or not SHA256_PATTERN.fullmatch(record_hash):
            raise AuditChainError("record_hash must be lowercase SHA-256")
        record = cls(
            sequence=sequence,
            recorded_at=_timestamp(value["recorded_at"]),
            request_id=_text(value["request_id"], "request_id"),
            agent_id=_text(value["agent_id"], "agent_id"),
            session_id=_text(value["session_id"], "session_id"),
            tool_name=_text(value["tool_name"], "tool_name"),
            effect=effect,
            reason=_text(value["reason"], "reason"),
            stage=stage,
            key_version=key_version,
            previous_hash=previous_hash,
            record_hash=record_hash,
        )
        if _hash(record.unsigned_dict()) != record.record_hash:
            raise AuditChainError(
                f"audit record {record.sequence} failed its SHA-256 integrity check"
            )
        return record


def build_audit_record(
    *,
    sequence: int,
    recorded_at: str,
    request_id: str,
    agent_id: str,
    session_id: str,
    tool_name: str,
    effect: AuditEffect,
    reason: str,
    stage: AuditStage,
    key_version: int | None,
    previous_hash: str | None,
) -> AuditRecord:
    """Build one record and compute its digest over every evidence field."""

    candidate = {
        "schema_version": 1,
        "sequence": sequence,
        "recorded_at": _timestamp(recorded_at),
        "request_id": request_id,
        "agent_id": agent_id,
        "session_id": session_id,
        "tool_name": tool_name,
        "effect": effect,
        "reason": reason,
        "stage": stage,
        "key_version": key_version,
        "previous_hash": previous_hash,
        "record_hash": "0" * 64,
    }
    unsigned = {key: value for key, value in candidate.items() if key != "record_hash"}
    unchecked = AuditRecord.from_dict(
        {**candidate, "record_hash": _hash(unsigned)}
    )
    return unchecked


def verify_audit_chain(records: Iterable[AuditRecord]) -> dict[str, Any]:
    """Verify sequence, hash links, time order, and request identity uniqueness."""

    material = tuple(records)
    if not material:
        raise AuditChainError("audit chain must contain at least one record")
    seen_request_ids: set[str] = set()
    previous: AuditRecord | None = None
    for expected_sequence, record in enumerate(material, start=1):
        if record.sequence != expected_sequence:
            raise AuditChainError(
                f"audit sequence must be contiguous at record {expected_sequence}"
            )
        expected_hash = None if previous is None else previous.record_hash
        if record.previous_hash != expected_hash:
            raise AuditChainError(
                f"audit record {record.sequence} has an invalid previous_hash"
            )
        if record.request_id in seen_request_ids:
            raise AuditChainError(f"duplicate request_id: {record.request_id}")
        if previous is not None and record.recorded_at < previous.recorded_at:
            raise AuditChainError(
                f"audit record {record.sequence} moves backward in time"
            )
        seen_request_ids.add(record.request_id)
        previous = record
    assert previous is not None
    return {
        "schema_version": 1,
        "record_count": len(material),
        "first_recorded_at": material[0].recorded_at,
        "last_recorded_at": material[-1].recorded_at,
        "head_hash": previous.record_hash,
    }


def parse_json_lines(lines: Iterable[str]) -> tuple[AuditRecord, ...]:
    records = []
    for line_number, raw in enumerate(lines, start=1):
        if not raw.strip():
            continue
        try:
            value = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise AuditChainError(
                f"line {line_number}: invalid JSON ({exc.msg})"
            ) from exc
        try:
            records.append(AuditRecord.from_dict(value))
        except AuditChainError as exc:
            raise AuditChainError(f"line {line_number}: {exc}") from exc
    return tuple(records)
