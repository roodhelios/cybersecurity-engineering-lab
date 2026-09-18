# Aegis Authorization Threat Catalog

This module is a portfolio-lab reimplementation of the threat-modeling work behind an
AI tool authorization proxy. It defines the security scope before adding request
verification or policy code to this repository.

The catalog covers signed tool requests, agent status and active keys, replay controls,
OPA decisions, step-up binding, and audit evidence. Model training, prompt safety,
third-party tool behavior, deployment availability, and human identity proofing remain
outside this milestone.

## Validate the catalog

From this directory:

```bash
PYTHONPATH=src python -m aegis_threat_model.cli model/threats.json
python -m unittest discover -s tests -v
```

The command validates every asset, trust-boundary, control, and evidence reference. It
then prints deterministic JSON counts by STRIDE category. A missing reference,
duplicate identifier, invalid category, or contradictory scope fails validation.

## What the evidence fields mean

The evidence entries in `model/threats.json` describe tests planned for later
milestones. They do not claim that request verification, OPA policy, step-up approval,
or audit integrity is implemented in this module. The catalog is the review contract
those controls will need to satisfy.

## Current limitations

- The validator checks structure and reference integrity, not whether a control is
  effective.
- STRIDE categories organize review but do not prove that every possible abuse case is
  represented.
- Rate limiting, deployment availability, and tool behavior stay outside the current
  scope.
- The catalog is local JSON and does not publish findings to another system.

## Next step

Implement signed request verification with timestamp and nonce validation, then replace
the planned signature and replay evidence entries with exact test identifiers.
