"""Machine-readable threat model validation for the Aegis lab track."""

from .authorization import AuthorizationDecision, authorize_signed_request
from .model import Threat, ThreatCatalog, ThreatModelError, load_catalog, parse_catalog
from .opa_conformance import (
    OpaCaseResult,
    OpaConformanceError,
    evaluate_case_with_opa,
    run_opa_cases,
)
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
    "AuthorizationDecision",
    "MemoryNonceStore",
    "OpaCaseResult",
    "OpaConformanceError",
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
    "authorize_signed_request",
    "decide",
    "evaluate_cases",
    "evaluate_case_with_opa",
    "load_catalog",
    "parse_catalog",
    "parse_case_suite",
    "run_opa_cases",
    "verify_request",
]
