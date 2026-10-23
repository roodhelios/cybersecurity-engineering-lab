# Scoped DNS observation review

Compare two saved hostname-to-address snapshots without sending DNS queries. This
starts the lab's asset-intelligence milestone with explicit scope, normalized host
records, provenance references, and an address-change review. Risk scoring, ownership,
remediation, collection, and broader asset correlation remain unimplemented here.

From the repository root, use Python 3.11 or newer and the standard library:

```bash
python projects/asset-intelligence/dns-review/dns_review.py \
  projects/asset-intelligence/dns-review/examples/before.json \
  projects/asset-intelligence/dns-review/examples/after.json \
  --scope projects/asset-intelligence/dns-review/examples/scope.json
```

The synthetic result has three observed hostnames: one changed, one first observed,
and one not observed in the current snapshot. A fourth allowed hostname was not
observed in either snapshot. `web.example.test` changes from `192.0.2.10` to
`192.0.2.11`. The new hostname also claims the old address, but shared addresses
never merge host identities. Each record links one-based row indexes in the two
input arrays, and the report retains exact input and scope SHA-256 digests.

## Input contract

Scope is an exact JSON object with `schema_version: 1`, a caller-supplied `scope`
(`synthetic`, `owned`, or `authorized`), and 1 to 1,000 `allowed_hosts`. Every observed
hostname must occur in that explicit list. Scope is a claim, not proof of permission.

Each snapshot has exactly `schema_version: 1`, `observed_at` (timezone-aware ISO 8601),
and `records`. Each record contains exactly `hostname` and `addresses`. Addresses is
a non-empty list of at most 32 literal IPv4 or IPv6 addresses. An absent hostname
means it was not observed in that snapshot. This format does not encode NXDOMAIN,
empty DNS answers, TTLs, CNAMEs, or resolver status, and does not parse native DNS logs.
Do not translate a DNS error into an empty address list or treat an omitted row as
an authoritative negative answer.

ASCII hostname labels are normalized to lowercase with one optional trailing dot
removed. Unicode and wildcard names, invalid labels, scoped IPv6 addresses, duplicate
normalized hostnames, and duplicate normalized addresses are rejected. Arrays are
limited to 1,000 records; each file is limited to 1 MiB. Current time must be strictly
later than baseline time after UTC normalization. Duplicate JSON fields, unknown
fields, non-finite values, and any out-of-scope row reject the whole comparison.

## Read the result

`changed` and `unchanged` apply only when both snapshots contain the hostname.
`addresses_added` and `addresses_removed` are populated only for a comparison between
two observed address sets. First observations and missing current observations carry
empty change arrays and retain their available address set separately. Missing rows
do not prove asset removal, DNS failure, or collection completeness. Changes may be
routine infrastructure or resolver differences, not compromise or ownership evidence.

Add `--output NEW_FILE.json` to create a private 0600 result on POSIX. The parent
must exist, the output path must be fresh, and existing files are never overwritten.
Otherwise JSON goes to stdout. Input files must be regular local files; symlinks and
FIFOs are rejected. Exit 0 means the complete comparison was produced, including
changes that need review. Exit 2 produces no success document or new output.

Hostnames and addresses can be sensitive. Use only authorized local records, keep
real inputs and outputs private and outside Git, and retain original files if row
references must be checked. Digests do not authenticate a collector. No network
request, ownership lookup, scan, enrichment, or remediation action is performed.

## Validate

```bash
python -m unittest discover -s projects/asset-intelligence/dns-review/tests -v
```

Tests use synthetic names and documentation addresses. Next: define reviewed finding
and ownership inputs before attaching risk or remediation claims to these records.
This is a local lab implementation with assistant support.
