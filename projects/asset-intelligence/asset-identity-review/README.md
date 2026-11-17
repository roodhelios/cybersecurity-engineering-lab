# Review mock asset identity claims

This is the first bounded host-identity workflow beyond the lab's DNS snapshots.
It compares explicitly supplied mock sources, groups equal strong identifiers and
keeps contradictory components unresolved. It never discovers or contacts assets.
Existing DNS formats and workflows are unchanged. Prepared with assistant support.

The separate [saved osquery review](OSQUERY_REVIEW.md) accepts a native-format
`system_info` JSON array under an independently pinned collection-context file.
Run `python -m lab run osquery-hosts` for the complete synthetic exercise. This is
a saved-file adapter, not a collector or authenticated source enrollment.

From the repository root, use Python 3.11 or newer on POSIX with no dependencies:

```bash
python -m lab run asset-identity
```

Expect `mock_asset_identity_exercise_passed`, seven records, six review groups,
one matched group and one unresolved component. The cloud and endpoint fixtures
agree on one EC2 ARN. Two records share only an IP/hostname and stay separate. Two
others agree on an ARN but disagree on hardware ID and remain separate, linked to
one conflict finding. Only documentation addresses and synthetic IDs are used.

## Retain a complete review

```bash
review_dir=$(mktemp -d)
python projects/asset-intelligence/asset-identity-review/asset_review.py review \
  projects/asset-intelligence/asset-identity-review/examples/cloud.json \
  projects/asset-intelligence/asset-identity-review/examples/endpoint.json \
  --namespace synthetic-assets --scope synthetic --output "$review_dir/review.json"
```

The new report is mode 0600; existing files are preserved. Stdout contains counts
and `mock_asset_identity_review_created`, without asset IDs, hostnames or addresses.
The report retains sensitive claims, source byte digests, declared capture times,
one-based input/row references and every normalized observation. Keep permitted real
inputs and reports private and outside Git. Remove the temporary directory when no
retention is needed. Exit 0 includes unresolved findings; exit 2 publishes nothing
new and returns a fixed diagnostic without raw private fields or paths.

## Input and identity contract

Supply two to eight UTF-8 JSON documents, each at most 1 MiB with exactly:
`schema_version: 1`, `scope`, `namespace`, `source_id`, `captured_at`, and `assets`.
The namespace and scope must match the independently selected command arguments.
Scopes are `synthetic`, `owned`, or `authorized`; they remain caller claims. Namespace
and unique source IDs use 3 to 64 lowercase ASCII letters, digits or hyphens, starting
with a letter. Capture times need a timezone and are normalized to UTC. They are not
authenticated or checked for freshness. Each source has zero to 1,000 asset records.

Each record has exactly `source_record_id`, `kind: host`, `identifiers`, `hostname`
and `ip_addresses`. Record IDs are unique within a source, use 1 to 128 ASCII letters,
digits, dots, underscores or hyphens, and start with a letter/digit. Identifiers may
contain only `cloud_resource_id` and `hardware_id`, or be empty. Cloud identity is a
literal commercial-partition EC2 instance ARN in the supported region-name subset.
Hardware IDs use the record-ID grammar and compare exactly, including case. Their
meaning and uniqueness are supplied by the source, not validated by this program.

Hostname is null or an ASCII DNS-style name, normalized to lowercase without one
trailing dot. Up to 32 unscoped IPv4/IPv6 literals are normalized and deduplicated.
Hostnames and IPs are attributes, never identity keys. A record without strong IDs
remains a separate source record even if all its attributes match another record.
Unknown/duplicate fields, bad types/literals, repeated source/record IDs, mismatched
context, malformed/non-finite JSON or any oversized source reject the whole review.
Empty sources mean no supplied records, not absence of real assets.

Equal strong IDs form connected candidate components within the declared namespace.
Before grouping, every component is checked for multiple different values of the
same identifier kind. A conflict, including a transitive one, splits the entire
component back into individual records and creates `conflicting-identity-claims`
with the references and conflicting values. Nothing chooses a winning source.
Clean matching components retain all hostname/address claims, not a selected truth.
Group/finding digests bind the declared context and review references. They are
review-local identifiers, not persistent asset IDs or a signed evidence system.

This is not general entity resolution, a native collector, authenticated source
independence, accepted ownership, calibrated risk or remediation. A wrong shared
strong ID can still produce a false group, and a changed namespace cannot prove
permission. Different capture times can describe different states; this workflow
does not infer freshness or temporal identity. Trusted POSIX ancestor paths and
cooperative file handling are required; this is not same-user isolation, file locking
or power-loss-safe publication. No network lookup, malware, cloud account, notification
or live remediation is involved.

```bash
python -m unittest discover -s projects/asset-intelligence/asset-identity-review/tests -v
```

Next: define independent source enrollment and time/collection requirements before
using these mock identifier claims as operational asset identity.
