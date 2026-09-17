"""Machine-readable threat model validation for the Aegis lab track."""

from .model import Threat, ThreatCatalog, ThreatModelError, load_catalog, parse_catalog
from .verification import (
    AgentCredential,
    MemoryNonceStore,
    RequestFormatError,
    SignedToolRequest,
    VerificationDecision,
    canonical_request,
    verify_request,
)

__all__ = [
    "AgentCredential",
    "MemoryNonceStore",
    "RequestFormatError",
    "SignedToolRequest",
    "Threat",
    "ThreatCatalog",
    "ThreatModelError",
    "VerificationDecision",
    "canonical_request",
    "load_catalog",
    "parse_catalog",
    "verify_request",
]
