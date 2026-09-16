"""Validation for a scoped, reference-linked threat catalog."""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any, Mapping


STRIDE_CATEGORIES = {
    "spoofing",
    "tampering",
    "repudiation",
    "information_disclosure",
    "denial_of_service",
    "elevation_of_privilege",
}


class ThreatModelError(ValueError):
    """Raised when the catalog cannot be reviewed without guessing."""


def _mapping(value: Any, field_name: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ThreatModelError(f"{field_name} must be an object")
    return value


def _records(value: Any, field_name: str) -> tuple[Mapping[str, Any], ...]:
    if not isinstance(value, list) or not value:
        raise ThreatModelError(f"{field_name} must be a non-empty list")
    return tuple(_mapping(item, f"{field_name} item") for item in value)


def _text(value: Any, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ThreatModelError(f"{field_name} must be a non-empty string")
    return value.strip()


def _text_list(value: Any, field_name: str) -> tuple[str, ...]:
    if not isinstance(value, list) or not value:
        raise ThreatModelError(f"{field_name} must be a non-empty list")
    items = tuple(_text(item, field_name) for item in value)
    if len(items) != len(set(items)):
        raise ThreatModelError(f"{field_name} must not contain duplicates")
    return items


def _index(records: tuple[Mapping[str, Any], ...], field_name: str) -> Mapping[str, str]:
    indexed: dict[str, str] = {}
    for record in records:
        record_id = _text(record.get("id"), f"{field_name}.id")
        description = _text(record.get("description"), f"{field_name}.description")
        if record_id in indexed:
            raise ThreatModelError(f"duplicate {field_name} id: {record_id}")
        indexed[record_id] = description
    return MappingProxyType(indexed)


def _require_references(
    values: tuple[str, ...],
    known: Mapping[str, str],
    field_name: str,
) -> None:
    missing = sorted(set(values) - set(known))
    if missing:
        raise ThreatModelError(f"{field_name} has unknown references: {', '.join(missing)}")


@dataclass(frozen=True, slots=True)
class Threat:
    threat_id: str
    title: str
    stride: str
    boundary: str
    assets: tuple[str, ...]
    entry_points: tuple[str, ...]
    abuse_case: str
    controls: tuple[str, ...]
    evidence: tuple[str, ...]
    residual_risk: str


@dataclass(frozen=True, slots=True)
class ThreatCatalog:
    system: str
    included_scope: tuple[str, ...]
    excluded_scope: tuple[str, ...]
    assets: Mapping[str, str]
    boundaries: Mapping[str, str]
    controls: Mapping[str, str]
    evidence: Mapping[str, str]
    threats: tuple[Threat, ...]

    def summary(self) -> dict[str, Any]:
        category_counts = Counter(threat.stride for threat in self.threats)
        return {
            "schema_version": 1,
            "system": self.system,
            "counts": {
                "assets": len(self.assets),
                "trust_boundaries": len(self.boundaries),
                "controls": len(self.controls),
                "evidence_items": len(self.evidence),
                "threats": len(self.threats),
            },
            "threats_by_stride": dict(sorted(category_counts.items())),
        }


def parse_catalog(value: Mapping[str, Any]) -> ThreatCatalog:
    """Parse the versioned catalog and resolve every threat reference."""

    value = _mapping(value, "catalog")
    if type(value.get("schema_version")) is not int or value["schema_version"] != 1:
        raise ThreatModelError("schema_version must be 1")

    scope = _mapping(value.get("scope"), "scope")
    included_scope = _text_list(scope.get("included"), "scope.included")
    excluded_scope = _text_list(scope.get("excluded"), "scope.excluded")
    overlap = sorted(set(included_scope) & set(excluded_scope))
    if overlap:
        raise ThreatModelError(f"scope entries cannot be both included and excluded: {overlap[0]}")

    assets = _index(_records(value.get("assets"), "assets"), "asset")
    boundaries = _index(
        _records(value.get("trust_boundaries"), "trust_boundaries"),
        "trust_boundary",
    )
    controls = _index(_records(value.get("controls"), "controls"), "control")
    evidence = _index(_records(value.get("evidence"), "evidence"), "evidence")

    threats: list[Threat] = []
    threat_ids: set[str] = set()
    for record in _records(value.get("threats"), "threats"):
        threat_id = _text(record.get("id"), "threat.id")
        if threat_id in threat_ids:
            raise ThreatModelError(f"duplicate threat id: {threat_id}")
        threat_ids.add(threat_id)

        stride = _text(record.get("stride"), f"{threat_id}.stride")
        if stride not in STRIDE_CATEGORIES:
            raise ThreatModelError(f"{threat_id}.stride is not a supported STRIDE category")
        boundary = _text(record.get("boundary"), f"{threat_id}.boundary")
        threat_assets = _text_list(record.get("assets"), f"{threat_id}.assets")
        threat_controls = _text_list(record.get("controls"), f"{threat_id}.controls")
        threat_evidence = _text_list(record.get("evidence"), f"{threat_id}.evidence")

        _require_references((boundary,), boundaries, f"{threat_id}.boundary")
        _require_references(threat_assets, assets, f"{threat_id}.assets")
        _require_references(threat_controls, controls, f"{threat_id}.controls")
        _require_references(threat_evidence, evidence, f"{threat_id}.evidence")

        threats.append(
            Threat(
                threat_id=threat_id,
                title=_text(record.get("title"), f"{threat_id}.title"),
                stride=stride,
                boundary=boundary,
                assets=threat_assets,
                entry_points=_text_list(
                    record.get("entry_points"), f"{threat_id}.entry_points"
                ),
                abuse_case=_text(record.get("abuse_case"), f"{threat_id}.abuse_case"),
                controls=threat_controls,
                evidence=threat_evidence,
                residual_risk=_text(
                    record.get("residual_risk"), f"{threat_id}.residual_risk"
                ),
            )
        )

    return ThreatCatalog(
        system=_text(value.get("system"), "system"),
        included_scope=included_scope,
        excluded_scope=excluded_scope,
        assets=assets,
        boundaries=boundaries,
        controls=controls,
        evidence=evidence,
        threats=tuple(threats),
    )


def load_catalog(path: str | Path) -> ThreatCatalog:
    """Load a UTF-8 JSON catalog from a local path."""

    source = Path(path)
    try:
        value = json.loads(source.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ThreatModelError(f"{source}: invalid JSON ({exc.msg})") from exc
    return parse_catalog(value)
