# Review a saved osquery host export

This separate workflow converts a supplied `system_info` JSON array into the existing
host-claim schema and reviews it with one to seven explicitly supplied peer sources.
It never starts osquery, runs a collector or sends a network request. Only `uuid` and
`hostname` are projected, based on the [upstream table definition](https://github.com/osquery/osquery/blob/master/specs/system_info.table).
Other osquery tables, log envelopes and live collection are unsupported.

## Try the complete synthetic example

From the repository root, with Python 3.11+ on POSIX and no package installation:

```bash
python -S -m lab run osquery-hosts
```

Expect `osquery_host_review_exercise_passed`, four records, three groups, one matched
group, zero conflicting components and two rejected negative cases. One native row's
UUID matches a supplied peer hardware claim. A shared hostname alone stays separate.
Unselected synthetic serial and CPU fields are absent. This checks supplied fixture
consistency, not authenticated source truth or physical host identity.

## Pin the collection context separately

For an already saved owned or authorized file, review a context with exactly these fields:

```json
{
  "schema_version": 1,
  "export_kind": "osquery-system-info",
  "namespace": "reviewed-assets",
  "scope": "authorized",
  "source_id": "saved-osquery",
  "captured_at": "2026-11-17T12:00:00Z",
  "expected_export_sha256": "REPLACE_WITH_THE_EXACT_ORIGINAL_BYTE_SHA256"
}
```

The placeholder is intentionally invalid. Use the reviewed original's lowercase
64-digit byte digest. Independently review its claimed source, namespace, scope and
capture time, then retain and distribute the context pin separately from incoming
files. Computing an operational pin from an untrusted context beside the export does
not establish trust. Pins authenticate neither collector nor permission, and capture
time is a supplied claim. Source enrollment, freshness, authority, complete coverage
and independent peer provenance require an external review process.

Peer files follow the [existing host contract](README.md), with matching scope/namespace
and distinct source IDs. Canonical UUID strings can match a peer's `hardware_id`;
generic peer hardware IDs remain case-sensitive. There is no serial or hostname
fallback. Cloned or wrong nonzero UUIDs can still falsely group records.

## Retain a private fixture review

For this public synthetic context only, use the fixed reviewed pin below. Choose a
new destination in a trusted private directory whose parent already exists:

```bash
python projects/asset-intelligence/asset-identity-review/osquery_review.py \
  projects/asset-intelligence/asset-identity-review/examples/osquery-system-info.json \
  --context projects/asset-intelligence/asset-identity-review/examples/osquery-context.json \
  --expected-context-sha256 6d7de76558e24c812d5d60966cdf10f6c646c9c237f81710bdd93ba53aec576d \
  --peer-source projects/asset-intelligence/asset-identity-review/examples/osquery-peer.json \
  --output /private/review/new-host-review.json
```

Exit 0 prints only status and aggregate record/group counts. The complete report is
written to a new mode-0600 file, preserving existing files and original inputs.
Failures return 2 with no partial success or raw parser/path details. Operational
reports contain private hostnames, UUIDs, peer claims and linkable digests. Keep them
and the originals outside Git.

`native_import` records the original export/context digests, normalized collection
claims, selected fields and the derived-source digest. Original row N maps to
`system-info-row-N` in input 1. `inputs[0].original_sha256` binds converted source bytes,
not the raw osquery export; the lineage block distinguishes them. Unknown columns
are omitted, not evidence of absence. No addresses are inferred. Contradictory connected
identifier components retain individual observations and a finding under existing rules.

## Bounds and remaining work

Each export/peer is limited to 1 MiB. Native arrays need 1 to 1000 rows, each with a
hyphenated UUID and hostname field (null is permitted by the host contract). UUIDs
normalize case; duplicate, nil and all-ones values reject the whole import. Hostnames
follow the existing ASCII DNS contract. Unknown columns are allowed, but duplicate
JSON keys and non-finite values anywhere reject the file. Context is limited to
64 KiB, retained report to 16 MiB. One native export and one to seven peers are required.

POSIX no-follow, nonblocking regular reads and exclusive publication reuse the host
tool boundary. Trusted ancestors and cooperative inputs remain necessary. There is
no source locking, same-user isolation or power-loss guarantee. Retain originals,
peer order, context pin and trusted source revision to rerun under current code.
No signed report, existing-report verifier, historical dispatch, live collector,
source enrollment or accepted ownership is added.

```bash
python -S -m unittest discover -s projects/asset-intelligence/asset-identity-review/tests -v
```

Next: define independently maintained source authority and collection coverage before
treating a native-format match as operational inventory. Prepared with assistant support
and generated original synthetic fixtures.
