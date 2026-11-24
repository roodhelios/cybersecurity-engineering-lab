# Prepare source claims without a custom signing script

The authenticated review needs one signature from each enrolled source. Previously
only the Python API could create these claims. `source_claims.py` now creates one
claim from a protected local seed and assembles a bundle only after the existing
authenticated review verifies every claim and original.

## Run the whole temporary workflow

From the repository root on POSIX with Python 3.11+ and the existing optional
PyNaCl dependency installed:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/asset-identity-review/demo_source_claims.py
```

Expected output:

```json
{"claim_count": 2, "group_count": 6, "received_report_reproduced": true, "source_truth_verified": false, "status": "source_claim_cli_exercise_passed", "temporary_keys_only": true, "unresolved_component_count": 1}
```

The exercise generates two fresh ephemeral keys in a private temporary directory,
creates two claim files through the real CLI parser, verifies and publishes a
bundle, creates a report and reproduces the received report. Everything is removed
when the exercise ends. The enrollment, source files and review instant are synthetic.
No collector, socket or remote service is used. The unresolved identity conflict
remains present.

## Sign one independently enrolled source

Use the separately reviewed [requirements and source enrollment](SOURCE_AUTH.md).
Provision a raw 32-byte Ed25519 seed through your own trusted process. This is the
seed, not a base64 string, JSON document or 64-byte expanded private key. Its file
must be owned by the current user, mode 0400 or 0600, regular and singly linked.
Symlinks, hard links, group access and other-user access reject. Protect its parent
directories and use a cooperative trusted local process. Do not put the seed value
in a command, environment variable, fixture or Git file.

With a trusted existing private output parent:

```bash
python projects/asset-intelligence/asset-identity-review/source_claims.py claim \
  /private/cloud.json --source-id cloud-export \
  --seed-file /private/keys/cloud.seed \
  --requirements /private/requirements.json \
  --expected-requirements-sha256 INDEPENDENT_REQUIREMENTS_SHA256 \
  --authority /private/authority.json \
  --expected-authority-sha256 INDEPENDENT_AUTHORITY_SHA256 \
  --scope owned --namespace SELECTED_NAMESPACE \
  --issued-at SELECTED_ISSUANCE --expires-at SELECTED_EXPIRY --at TRUSTED_REVIEW_INSTANT \
  --output /private/claims/cloud.json
```

Replace all placeholders, including the source ID, with the selected enrolled
context. Invalid placeholders reject. Repeat on the second source's signing host
using its own seed. Each claim validates the exact original, source grants,
capture bounds, matching enrolled key and permitted validity interval. The context
pins are checked before reading the seed. The seed is never included in the claim,
report or diagnostic. Python memory erasure is not guaranteed.

## Assemble a complete verified bundle

Collect only the claim files and ordered originals at the reviewer. No private
seed is required for this command:

```bash
python projects/asset-intelligence/asset-identity-review/source_claims.py bundle \
  /private/cloud.json /private/endpoint.json \
  --claims /private/claims/cloud.json /private/claims/endpoint.json \
  --requirements /private/requirements.json \
  --expected-requirements-sha256 INDEPENDENT_REQUIREMENTS_SHA256 \
  --authority /private/authority.json \
  --expected-authority-sha256 INDEPENDENT_AUTHORITY_SHA256 \
  --scope owned --namespace SELECTED_NAMESPACE --at TRUSTED_REVIEW_INSTANT \
  --output /private/reviews/new-bundle.json
```

Two to eight sources are required in requirements order. Claim order may differ,
but duplicate, missing, invalid, expired or revoked claims reject. Every signature,
pin, grant, capture constraint and grouping check must pass before a new bundle
exists. Unresolved identity conflicts are preserved, not treated as verification
failure. The bundle is not a report; use the existing `source_auth.py review` and
`verify` commands afterward, with independently reviewed context and artifact pins.

Both commands publish a new mode-0600 file without replacing an existing output.
They print a minimized status and artifact digest, never keys, signatures, source
IDs or paths. Claim input is bounded to 4 KiB, bundles to 32 KiB and each original
to 1 MiB. Failures return 2 with a fixed diagnostic. The existing POSIX bounded
no-follow reader and exclusive hard-link publication are reused.

This authenticates selected enrolled-key claims. It does not establish source
truth, physical collector identity, independent operators, latest policy/revocation,
accepted ownership or one-time execution. The tool does not generate operational
keys, enroll a new authority, scan systems or revoke credentials.

Run `python -m unittest discover -s projects/asset-intelligence/asset-identity-review/tests -v`
with PyNaCl available. Prepared with assistant support using synthetic inputs.
Next: distribute current enrollment and revocation through a separately trusted process.
