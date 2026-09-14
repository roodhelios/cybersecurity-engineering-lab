"""Normalize and conservatively enrich selected network-security events."""

from .attack import AttackCandidate, map_attack_candidates
from .correlation import (
    ConnectionCorrelation,
    CorrelationConfig,
    correlate_repeated_attempts,
)
from .models import NormalizedEvent
from .normalizer import NormalizationError, normalize_event

__all__ = [
    "AttackCandidate",
    "ConnectionCorrelation",
    "CorrelationConfig",
    "NormalizedEvent",
    "NormalizationError",
    "correlate_repeated_attempts",
    "map_attack_candidates",
    "normalize_event",
]
