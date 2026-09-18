# Aegis Authorization Threat Catalog

This module is a portfolio-lab reimplementation of the authorization boundary behind
an AI tool proxy. It began with a machine-readable threat catalog and now verifies
local Ed25519 request fixtures before later policy work is added.

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

## Verify a signed request

Install this project in an isolated environment, then run the local fixture:

```bash
PYTHONPATH=src python -m aegis_threat_model.verify_cli \
  --request examples/signed-request.json \
  --credential examples/credential.json \
  --now 1789686000
```

The verifier checks the active credential, a symmetric clock window, Ed25519 signature,
and one-time nonce in that order. It verifies the signature before reserving the nonce,
so an invalid signature cannot consume a valid request's replay key. The in-memory
nonce store is intentionally limited to one local process. A service deployment would
need an atomic shared store.

## Review the OPA policy contract

`policy/aegis.rego` is a Rego v1 policy draft for explicit role-to-tool access,
deny-by-default behavior, and risk-based step-up on high-sensitivity tools. Its data and
eight synthetic cases are versioned beside it.

Run the Python fixture oracle and structural Rego check:

```bash
PYTHONPATH=src python -m aegis_threat_model.policy_cli \
  --data policy/data.json \
  --cases policy/cases.json \
  --rego policy/aegis.rego
```

The Python oracle makes expected decisions reviewable without a running policy service.
It is not an OPA interpreter and does not prove that the Rego engine returns the same
results. The roadmap item remains incomplete until the cases also run with `opa test`.

## What the evidence fields mean

The signature and replay evidence entries point to implemented tests. Policy, step-up,
and audit evidence remains marked as planned. The catalog is the review contract those
later controls will need to satisfy.

## Current limitations

- Verification uses an in-memory nonce store and does not prove distributed replay
  safety.
- Canonical request bytes use documented Python JSON serialization, not RFC 8785.
- Policy fixtures pass a Python reference evaluator, but Rego-native execution has not
  been run in this environment.
- STRIDE categories organize review but do not prove that every possible abuse case is
  represented.
- Rate limiting, deployment availability, and tool behavior stay outside the current
  scope.
- The catalog is local JSON and does not publish findings to another system.

## Next step

Add Rego-native tests that run the same eight cases with the OPA CLI, then mark the
least-privilege policy milestone complete only if both evaluators agree.
