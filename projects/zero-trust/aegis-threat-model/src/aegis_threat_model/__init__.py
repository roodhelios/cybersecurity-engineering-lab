"""Machine-readable threat model validation for the Aegis lab track."""

from .audit_chain import (
    AuditChainError,
    AuditRecord,
    build_audit_record,
    parse_json_lines,
    verify_audit_chain,
)

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
    "AuditChainError",
    "AuditRecord",
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
    "build_audit_record",
    "decide",
    "evaluate_cases",
    "evaluate_case_with_opa",
    "load_catalog",
    "parse_catalog",
    "parse_json_lines",
    "parse_case_suite",
    "run_opa_cases",
    "verify_audit_chain",
    "verify_request",
]
