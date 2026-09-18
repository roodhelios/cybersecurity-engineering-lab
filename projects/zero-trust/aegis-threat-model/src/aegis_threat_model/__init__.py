"""Machine-readable threat model validation for the Aegis lab track."""

from .model import Threat, ThreatCatalog, ThreatModelError, load_catalog, parse_catalog

__all__ = [
    "Threat",
    "ThreatCatalog",
    "ThreatModelError",
    "load_catalog",
    "parse_catalog",
]
