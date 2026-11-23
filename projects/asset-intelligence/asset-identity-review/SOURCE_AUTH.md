# Verify a collector key for each expected source

The constrained host review checks byte identities, source IDs and identifier grants,
but not who signed a supplied source. This separate workflow requires a claim from
each independently enrolled source key before applying the same constraints and
grouping. One source's key cannot silently cover another expected source.

From the repository root on POSIX with Python 3.11+, install the existing optional
authentication dependency in your virtual environment if needed:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/asset-identity-review/source_auth.py demo
```

The complete in-memory synthetic exercise creates two ephemeral Ed25519 keys, enrolls
their public keys, signs the exact cloud/endpoint originals and verifies both before
running the existing constrained review. It opens no collector or sample and makes
no network request. No private key, signature, policy or identifier is printed/written.
Expected selected output:

```json
{
  "status": "authenticated_source_identity_exercise_passed",
  "collector_key_claims_verified": true,
  "source_truth_verified": false,
  "record_count": 7,
  "group_count": 6,
  "unresolved_component_count": 1
}
```

The conflict remains unresolved. Authentication does not choose which host claim is
correct, accept ownership or turn separate keys into independent physical collectors.

## Enroll and sign explicitly

Continue using the exact [source requirements](SOURCE_REQUIREMENTS.md). Prepare a
separate private authority file with exactly `schema_version: 1`, matching `scope`
and `namespace`, `maximum_validity_seconds` (integer 1 to 86400), and `sources`.
Its 2 to 8 entries must cover precisely the expected source IDs. Each has exactly
`source_id`, `key_id`, canonical 32-byte `public_key_b64`, `status` (`active` or
`revoked`), and timezone-aware `not_before`/`not_after` bounds. Source IDs, key IDs
and public keys must each be unique. This version supports one current key per
source; rotation replaces the reviewed enrollment and requires new claims.

Independently establish each source/key binding and retain the authority byte pin
through a trusted channel. Public keys supplied only alongside untrusted data do
not establish enrollment. Distinct keys alone do not establish operator independence.
Do not commit real seeds, operational sources, enrollments or reports.

The `create_claim` API accepts one original, requirements bytes, authority bytes,
their independent pins, explicit scope/namespace/source ID, an in-memory PyNaCl
`SigningKey`, issuance/expiry and a trusted `at` instant. It confirms the key matches
that source enrollment and validates that source's original/grants/capture bounds.
The module's `exercise()` shows this flow with temporary keys. Secret loading/export
and a real collector service are not implemented by the CLI.

The signed version-1 claim binds its dedicated purpose/domain, scope/namespace,
source ID/key ID, original digest, exact requirements and authority digests, issued
and expiry instants. No incoming inline public key or algorithm selection is used.
A bundle has exactly `schema_version: 1` and `claims`, with one unique claim per
expected source. Claim order may vary; original source order must still match the
reviewed requirements. Policy/requirements changes require new matching claims.

## Retain a permitted authenticated review

With independently reviewed files and pins, choose a new output under a trusted
existing private parent:

```bash
python projects/asset-intelligence/asset-identity-review/source_auth.py review \
  /private/cloud.json /private/endpoint.json \
  --requirements /private/requirements.json \
  --expected-requirements-sha256 INDEPENDENT_REQUIREMENTS_SHA256 \
  --authority /private/source-authority.json \
  --expected-authority-sha256 INDEPENDENT_AUTHORITY_SHA256 \
  --bundle /private/source-claims.json --expected-bundle-sha256 INDEPENDENT_BUNDLE_SHA256 \
  --scope owned --namespace SELECTED_NAMESPACE --at TRUSTED_VERIFICATION_INSTANT \
  --output /private/reviews/new-authenticated-review.json
```

Placeholders are intentionally invalid. Requirements/authority/bundle pins precede
any parsing. Every signature, selected context, active-key interval and original pin
is checked before parsing any original or grouping. Capture claims must be no later
than issuance. The unchanged source constraints still enforce identifier grants,
collection windows, skew and whole-component conflict preservation.

The supplied verification instant must satisfy `issued_at <= at < expires_at` for
every claim. The interval must fit both the key bounds and policy maximum. Use a
trusted recipient clock/process; the claim does not select its own verification time.
Revoked keys reject. A current revocation cannot be inferred from an old pinned
policy, and repeated verification before expiry is allowed. There is no nonce store,
one-time action, latest-policy distribution or rollback-resistant enrollment.

Exit 0 means verification and report creation completed, including unresolved groups.
Stdout exposes counts, key-claim flag, false truth flag and report digest. The new
mode-0600 private report contains the source claims and complete constrained review.
Inputs remain unchanged, existing outputs are preserved and failures return 2 with
a fixed diagnostic. Requirements/authority/bundle limits are 16/16/32 KiB, each
original 1 MiB and report 16 MiB. Existing bounded POSIX no-follow readers and
exclusive publication are reused; trust ancestors and cooperative writers.

## What remains unverified

`collector_key_claims_verified` authenticates enrolled keys' exact claims. It does
not prove physical collector identity, truthful timestamps, original data truth,
independence, complete collection, accepted asset identity or ownership. The nested
unsigned review's `source_authenticity_verified` remains false with its original
meaning. Only the separate key-claim flag is new. No live collector, remediation,
database schema or existing unsigned/CSV/saved-osquery behavior changes.

Tests use real ephemeral signatures with socket creation blocked, including wrong
source keys, incomplete/substituted inputs, revocation, time bounds, all pins before
parsing, valid signatures with ungranted identifiers, preserved conflicts and private
CLI handling. Run `python -m unittest discover -s projects/asset-intelligence/asset-identity-review/tests`.
Prepared with assistant support and synthetic inputs. Next: trusted current enrollment
distribution and independent collection-process evidence before operational authority.
