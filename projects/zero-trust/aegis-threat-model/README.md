# Aegis Authorization Threat Catalog

This module is a portfolio-lab reimplementation of the authorization boundary behind
an AI tool proxy. It began with a machine-readable threat catalog and now verifies
local Ed25519 request fixtures and supports either a Python policy oracle or an
explicitly selected native OPA evaluator.

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

`policy/aegis.rego` is a Rego v1 policy for explicit role-to-tool access,
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
results.

When an OPA executable is installed, run the same cases through the real evaluator:

```bash
PYTHONPATH=src python -m aegis_threat_model.opa_conformance_cli \
  --opa opa \
  --data policy/data.json \
  --cases policy/cases.json \
  --rego policy/aegis.rego
```

The runner sends each fixture to `opa eval`, validates the returned decision shape, and
reports every mismatch. Unit tests use a local fake executable to test process, parsing,
and failure behavior. An additional integration test runs only when `opa` is present.
Native OPA 1.21.2 now matches all eight reviewed cases. The installed-OPA integration
test and combined authorization regressions also passed. See the exact binary and
policy digests, commands, and limitations in [validation evidence](docs/OPA_VALIDATION.md).

## Exercise the combined authorization boundary

The combined harness validates decision inputs, verifies the signed request, and only
then evaluates policy:

```bash
PYTHONPATH=src python -m aegis_threat_model.authorization_cli \
  --request examples/signed-request.json \
  --credential examples/credential.json \
  --policy policy/data.json \
  --risk-score 20 \
  --now 1789686000
```

Cross-control tests cover replay, malformed signatures, past and future clock skew,
signed role escalation, and high-risk step-up behavior. Verification failures never
reach policy evaluation. A request that passes signature checks can still be denied or
held for step-up by the least-privilege policy.

To use the real evaluator in this combined path, supply both native options:

```bash
PYTHONPATH=src python -m aegis_threat_model.authorization_cli \
  --request examples/signed-request.json --credential examples/credential.json \
  --policy policy/data.json --risk-score 20 --now 1789686000 \
  --opa /tmp/opa-1.21.2 --rego policy/aegis.rego
```

After acquiring the checked binary described in the validation guide, expect
`effect: allow`, `stage: policy`, and `policy_engine: opa`. The existing default still
uses the Python oracle and retains its output contract. When native mode is selected,
invalid signatures and replay stop before OPA, with `policy_engine: not_evaluated`.
Missing executables, evaluation failures, and malformed decisions fail with exit 2
and no success document. There is no fallback to the oracle. A policy denial or
step-up decision returns exit 1. Nonces are in memory; a policy outage can consume
the current request nonce, so retries need a fresh signed request. Only run trusted
local Rego and data files. This is not a sandbox for untrusted OPA policies.

## Verify append-only audit evidence

Authorization decisions can be stored as versioned JSON Lines records. Every record
contains a contiguous sequence, the previous record hash, and a SHA-256 digest over
all of its decision evidence:

```bash
PYTHONPATH=src python -m aegis_threat_model.audit_cli \
  examples/audit-records.jsonl
```

The verifier recomputes each record digest and checks the complete chain. It rejects a
missing or reordered sequence, a broken previous-hash link, a duplicate request ID,
time moving backward, and invalid combinations such as an allowed request at the
verification stage. The example is a synthetic fixture and is not evidence from a
running service.

`build_audit_record` creates the next record from explicit decision fields and a
caller-supplied previous hash. Durable append semantics, file locking, key management,
and external timestamping remain deployment concerns. A user who can replace the
whole file can replace both the records and their hashes.

## What the evidence fields mean

Signature, replay, and policy evidence entries point to implemented tests. Other
catalog entries still describe planned evidence; do not infer production step-up,
audit redaction, or deployment guarantees from the native policy check.

## Current limitations

- Verification uses an in-memory nonce store and does not prove distributed replay
  safety.
- Canonical request bytes use documented Python JSON serialization, not RFC 8785.
- Eight policy fixtures agree with native OPA 1.21.2. This is bounded conformance,
  not proof that every policy input or OPA version behaves identically.
- The combined harness defaults to the Python oracle; native execution is opt-in
  and uses a subprocess, not a deployed OPA server.
- Hash links expose edits within a retained audit file, but they do not protect against
  whole-file replacement without an independently stored head hash.
- STRIDE categories organize review but do not prove that every possible abuse case is
  represented.
- Rate limiting, deployment availability, and tool behavior stay outside the current
  scope.
- The catalog is local JSON and does not publish findings to another system.

## Next step

Expand boundary and malformed-input cases before changing the policy or OPA version.
Service deployment, distributed nonce storage, and independent step-up verification
remain outside the local native-policy evidence.
