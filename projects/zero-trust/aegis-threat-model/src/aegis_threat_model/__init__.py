"""Machine-readable threat model validation for the Aegis lab track."""

from .model import Threat, ThreatCatalog, ThreatModelError, load_catalog, parse_catalog
from .policy import (
    PolicyCase,
    PolicyContractError,
    PolicyData,
    PolicyDecision,
    PolicyInput,
    decide,
    evaluate_cases,
    parse_case_suite,
)
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
    "PolicyCase",
    "PolicyContractError",
    "PolicyData",
    "PolicyDecision",
    "PolicyInput",
    "RequestFormatError",
    "SignedToolRequest",
    "Threat",
    "ThreatCatalog",
    "ThreatModelError",
    "VerificationDecision",
    "canonical_request",
    "decide",
    "evaluate_cases",
    "load_catalog",
    "parse_catalog",
    "parse_case_suite",
    "verify_request",
]
