# Select signed source policy revisions locally

The source signature workflow previously required a manually selected authority
pin on every run. A recipient could silently select an older policy again.
`source_policy_state.py` adds signed policy updates and a pinned local selection
head. A review using that head takes its source authority from the selected update.
This is local revision selection, not proof that a policy is globally latest.

## Try the complete offline workflow

From the repository root, in a virtual environment:

```bash
python -m pip install -r projects/asset-intelligence/dns-review/requirements-auth.txt
python projects/asset-intelligence/asset-identity-review/demo_source_policy_state.py
python -m unittest discover -s projects/asset-intelligence/asset-identity-review/tests
```

The demo creates fresh temporary issuer/source keys, native Ed25519 signatures,
two policy revisions, source claims, a bundle and a recipient report. It exercises
the `issue`, `initialize`, `review` and `advance` CLIs without network calls.
Expected output includes:

```json
{"status":"source_policy_state_exercise_passed","selected_sequence":2,"group_count":6,"unresolved_component_count":1,"old_bundle_rejected":true,"global_latest_verified":false,"source_truth_verified":false,"temporary_keys_only":true}
```

The seven synthetic host records still form six groups with one unresolved
component. Revision 2 revokes one source key. The old bundle cannot authorize a
new selected-policy review. Temporary files and keys are removed on exit. The
fixture instant is November 17, 2026; it is not a claim about current collection.

## Trust inputs and signed format

Independently enroll and pin an issuer JSON file. Its exact fields are
`schema_version` (integer 1), `scope`, `namespace`, `audience`, `key_id`,
`public_key_b64` (canonical base64 of 32 raw bytes), `status` (`active` or `revoked`),
`not_before`, `not_after` (timezone-aware instants), and
`maximum_validity_seconds` (integer 1 to 86400). Scope is `synthetic`, `owned` or
`authorized`. Namespace, audience and key ID use bounded lowercase labels.
The issuer is distinct from the source keys in [source authority](SOURCE_AUTH.md).
Issuer enrollment, private key provisioning and trustworthy pin distribution are
external tasks. The tool does not manufacture operational trust roots.

An update binds purpose `lab-asset-source-policy-update-v1`, issuer and authority
byte hashes, scope, namespace, audience, issuer key ID, sequence, exact previous
update byte hash, and issued/expiry instants. Sequence 1 requires a null predecessor;
later sequences require a lowercase SHA-256. Ed25519 signs the purpose plus a null
byte and canonical unsigned JSON. Source-claim signatures have a different purpose.
All three input byte pins are checked before policy parsing. Duplicate JSON keys,
extra fields, booleans in integer fields and invalid windows reject.

## Use separately provisioned local inputs

Every command has `--help`, including these subcommands:

```bash
python projects/asset-intelligence/asset-identity-review/source_policy_state.py issue --help
python projects/asset-intelligence/asset-identity-review/source_policy_state.py initialize --help
python projects/asset-intelligence/asset-identity-review/source_policy_state.py advance --help
python projects/asset-intelligence/asset-identity-review/source_policy_state.py review --help
```

`issue` takes `--issuer`, `--expected-issuer-sha256`, `--authority`,
`--expected-authority-sha256`, `--scope`, `--namespace`, `--audience`, `--at`,
`--seed-file`, `--sequence`, `--issued-at`, `--expires-at` and a new `--output`.
For sequences after 1, also supply `--previous-update-sha256`. The seed must be an
owned, singly linked regular file containing exactly 32 raw bytes with mode 0400
or 0600. Pins are checked before seed access. Never put seeds in arguments or Git.

`initialize` takes the same public context, plus `--update`,
`--expected-update-sha256` and a new `--state`. It accepts sequence 1 only and never
overwrites an existing state. `advance` additionally requires the independently
retained `--expected-state-sha256`. It requires sequence plus one and the exact
selected previous update hash. Save the returned new state pin through a trusted
channel before the next operation. Reading a hash from an untrusted state file
and accepting it as the expected pin defeats rollback detection.

`review` takes that state and pin, issuer and pin, explicit scope/namespace/audience/
instant, ordered original sources, requirements and bundle with their independent
pins, and a new private output. It holds the state read lock through complete
source signature and constrained grouping validation. The report wraps the full
authenticated review with the selected sequence and exact state/update/authority
hashes. Source truth, collector independence and global freshness remain unverified.
The older direct `source_auth.py` interface remains available for explicitly pinned
historical policy reviews; it does not inherit this selection automatically.

## Storage and limits

State retains exact authority/update UTF-8 text, their hashes, selected sequence,
context, previous state hash and local acceptance instant. That instant is not a
signed clock attestation. State is bounded to 128 KiB, update to 8 KiB and issuer/
authority to 16 KiB each. Files are owned, singly linked, mode 0600 and no-follow.
A stable sibling `.lock` file uses POSIX `flock`. Concurrent cooperating writers
with the same state pin have one winner. Keep the parent directory private and
trusted; do not delete/replace the lock file or edit state outside this protocol.
An exclusive initialization publishes without overwrite. An advance writes and
fsyncs a private temporary file, then atomically replaces state. Pre-replacement
failures preserve the old file. Directory durability after power loss, network
filesystem lock semantics and malicious same-user writers are not established.

An expired head blocks review but can accept a valid current signed successor.
Its old signature is checked at its signed issuance instant only to link history;
the new update must validate at the independently supplied current instant. The
issuer pin stays fixed. Root rotation and full historical chain replay are absent.
Restoring an old state rejects against the newer retained pin. Resetting the store,
repinning an old file, cloned stores, dishonest issuer choices, stale external pins
or an incorrect clock are outside this guarantee. No global ordering or exclusivity
is established. Invalid CLI operations return 2 with a fixed redacted diagnostic.

Prepared with assistant support. Next: define independently authenticated issuer
rotation and checkpoint delivery before using this workflow for operational policy.
