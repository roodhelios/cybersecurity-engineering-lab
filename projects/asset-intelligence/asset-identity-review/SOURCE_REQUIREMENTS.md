# Constrain an identity review to reviewed source claims

The ordinary mock review accepts either supported strong identifier kind from every
supplied source. A recipient may intend a source to assert only hardware IDs, or may
expect a particular source set and capture window. This separate workflow checks
those independently reviewed requirements before any identifier grouping.

From the repository root, with Python 3.11+ on POSIX and no dependencies:

```bash
python -S projects/asset-intelligence/asset-identity-review/source_review.py demo
```

Expect `source_constrained_identity_exercise_passed`, seven records, six groups,
`ungranted_identifier_rejected: true` and `source_authenticity_verified: false`.
The synthetic exercise preserves the existing unresolved conflict. It also rejects
an endpoint source asserting a cloud identifier when a modified reviewed policy
permits that source to assert only hardware identifiers. The ordinary review would
have grouped that matching claim; the constrained workflow rejects before grouping.
No network, collector, notification or remediation runs.

## Review requirements independently

The [public fixture](examples/source-requirements.json) binds the exact ordered
cloud/endpoint originals, permitted identifier kinds and their supplied time bounds.
For permitted real input, prepare a private requirements file with exactly:

- Integer `schema_version: 1`, matching `scope` and `namespace`.
- Timezone-aware `observed_not_before` and `observed_not_after`, inclusive and ordered.
- Integer `max_capture_skew_seconds` from 0 to 86400.
- An ordered `sources` list of 2 to 8 unique source IDs, each with exactly
  `source_id`, lowercase `expected_original_sha256` and `allowed_identifier_kinds`.

Allowed kinds are `cloud_resource_id` and `hardware_id`. An empty kind list permits
only records without strong identifiers. Unknown or duplicate kinds reject. Source
IDs/namespace use the existing bounded label grammar. Input order must match the
requirements. Missing/extra sources, substituted bytes, ungranted kinds and source
capture claims outside either time bound reject the entire review. A skew of zero
requires equal supplied capture instants; equivalent timezone spellings compare equal.
Empty source inventories do not prove real collection coverage.

Establish each expected original digest from the reviewed collection, then review
the source IDs, identifier grants and capture requirements. Retain the requirements
byte pin independently before accepting received files. Copying pins or grants from
untrusted received files repeats their claims. This is operator review and byte
matching, not source authentication or a signature/enrollment service. No system
clock, source independence or real collector authority is established.

## Retain the public synthetic review

The fixed pin below identifies only the bundled public synthetic requirements.
Choose a new output under an existing trusted private parent:

```bash
review_dir=$(mktemp -d)
python -S projects/asset-intelligence/asset-identity-review/source_review.py review \
  projects/asset-intelligence/asset-identity-review/examples/cloud.json \
  projects/asset-intelligence/asset-identity-review/examples/endpoint.json \
  --requirements projects/asset-intelligence/asset-identity-review/examples/source-requirements.json \
  --expected-requirements-sha256 d423c56649a7f7cfbf2972a747085612544f83d48c289ae88c419771989b661e \
  --scope synthetic --namespace synthetic-assets --output "$review_dir/review.json"
```

Expect `source_constrained_identity_review_created`, seven records, six groups and
one unresolved component. Stdout contains aggregate counts and the requirements
digest, not source IDs, addresses, hostnames or paths. The private report contains
the complete existing review, exact reviewed requirements and observed claim skew.
These include sensitive operational identifiers, timestamps and linkable digests.
Keep real files outside Git. Existing files are preserved; originals are read-only.

The requirements pin is checked before parsing it. Every ordered original pin is
checked before parsing any original. Source context, identifier grants and capture
bounds are checked before grouping. The command writes a new mode-0600 report only
after every check passes. Failures return 2 with a fixed diagnostic and no new report.
The legacy mock review, saved osquery adapter and CSV formats remain unchanged.
This constrained command takes the mock source contract, not a raw osquery export.

Requirements are bounded to 16 KiB, each original to 1 MiB and rendered report to
16 MiB. The existing bounded POSIX regular no-follow reads/exclusive publication
boundary is reused. Trusted ancestors and cooperative writers are needed; there
is no file locking, encryption or crash-durability claim. Pins identify bytes, not
source truth, actual inventory completeness, current state, physical identity,
accepted asset ownership or remediation. Source IDs and capture times remain claims.

Tests cover the pre-grouping rejection, all pins before source parsing, exact ordered
coverage, windows/skew/timezone boundaries, malformed requirements, empty inventories,
private CLI publication and preservation of legacy conflicts. Socket creation is
blocked. Prepared with assistant support and synthetic fixtures. The separate
[per-source signature workflow](SOURCE_AUTH.md) now authenticates exact source-key
claims before these constraints, without changing this unsigned format. Next:
independently distribute current enrollment/requirements and review the collection
process before treating source IDs or capture times as operational authority.
