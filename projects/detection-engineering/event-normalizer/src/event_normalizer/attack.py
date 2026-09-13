"""Conservative MITRE ATT&CK candidates backed by event evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Literal, Mapping

from .models import NormalizedEvent


Confidence = Literal["low", "medium", "high"]


@dataclass(frozen=True, slots=True)
class AttackCandidate:
    """A possible ATT&CK mapping with the evidence used to produce it."""

    technique_id: str
    technique_name: str
    tactic: str
    confidence: Confidence
    evidence: tuple[str, ...]
    rule_id: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "technique_name": self.technique_name,
            "tactic": self.tactic,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "rule_id": self.rule_id,
        }


TECHNIQUES: Mapping[str, tuple[str, str]] = {
    "T1046": ("Network Service Discovery", "Discovery"),
    "T1190": ("Exploit Public-Facing Application", "Initial Access"),
    "T1059": ("Command and Scripting Interpreter", "Execution"),
    "T1505.003": ("Web Shell", "Persistence"),
}

_TECHNIQUE_PATTERN = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_METADATA_KEYS = {
    "mitre_technique_id",
    "mitre_attack_technique_id",
    "attack_technique_id",
}


def _metadata_values(value: Any) -> tuple[str, ...]:
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(item for item in value if isinstance(item, str))
    return ()


def _explicit_metadata_candidates(event: NormalizedEvent) -> list[AttackCandidate]:
    if event.source != "suricata" or event.event_type != "alert":
        return []

    alert = event.raw.get("alert")
    if not isinstance(alert, Mapping):
        return []
    metadata = alert.get("metadata")
    if not isinstance(metadata, Mapping):
        return []

    candidates: list[AttackCandidate] = []
    seen: set[str] = set()
    for key, value in metadata.items():
        if str(key).lower() not in _METADATA_KEYS:
            continue
        for entry in _metadata_values(value):
            for match in _TECHNIQUE_PATTERN.findall(entry.upper()):
                technique_id = match.upper()
                if technique_id in seen or technique_id not in TECHNIQUES:
                    continue
                seen.add(technique_id)
                name, tactic = TECHNIQUES[technique_id]
                candidates.append(
                    AttackCandidate(
                        technique_id=technique_id,
                        technique_name=name,
                        tactic=tactic,
                        confidence="medium",
                        evidence=(f"alert.metadata.{key}={entry}",),
                        rule_id="suricata-explicit-technique-metadata",
                    )
                )
    return candidates


def _zeek_incomplete_syn_candidate(event: NormalizedEvent) -> AttackCandidate | None:
    if event.source != "zeek" or event.event_type != "conn":
        return None
    if event.raw.get("conn_state") != "S0" or event.raw.get("history") != "S":
        return None
    if not event.src_ip or not event.dest_ip or event.dest_port is None:
        return None

    name, tactic = TECHNIQUES["T1046"]
    return AttackCandidate(
        technique_id="T1046",
        technique_name=name,
        tactic=tactic,
        confidence="low",
        evidence=(
            "conn_state=S0",
            "history=S",
            f"destination={event.dest_ip}:{event.dest_port}",
        ),
        rule_id="zeek-single-incomplete-syn",
    )


def map_attack_candidates(event: NormalizedEvent) -> tuple[AttackCandidate, ...]:
    """Return evidence-backed candidates without treating them as confirmed attacks."""

    candidates = _explicit_metadata_candidates(event)
    zeek_candidate = _zeek_incomplete_syn_candidate(event)
    if zeek_candidate is not None:
        candidates.append(zeek_candidate)
    return tuple(candidates)
