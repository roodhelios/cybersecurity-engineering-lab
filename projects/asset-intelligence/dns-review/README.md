# Scoped DNS observation review

Compare two saved hostname-to-address snapshots without sending DNS queries. This
starts the lab's asset-intelligence milestone with explicit scope, normalized host
records, provenance references, and an address-change review. Reviewed address rules and team routing are available below. Risk scoring, accepted
ownership, remediation, collection, and broader asset correlation remain unimplemented here.

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
empty DNS answers, TTLs, CNAMEs, or resolver status, and does not directly parse native DNS logs. The importer below converts a saved
Zeek JSON subset first.
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


## Review expected addresses and route a mismatch

Supply a separately reviewed policy instead of treating every address change as a
security finding:

```bash
python projects/asset-intelligence/dns-review/dns_policy_review.py \
  projects/asset-intelligence/dns-review/examples/before.json \
  projects/asset-intelligence/dns-review/examples/after.json \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --policy projects/asset-intelligence/dns-review/examples/review-policy.json
```

Expect one `reviewed_dns_address_mismatch` for `web.example.test`, routed to review
team `web-platform`. The current observation claims `192.0.2.11`; the rule expects
`192.0.2.10`. The finding includes the current snapshot row and policy rule index.
It does not infer severity, compromise, accepted ownership, or a remediation action.
The missing worker and unseen host remain `not_observed_current`; the new host has
`no_review_rule`. Neither state produces an address-mismatch finding.

Policy JSON has exactly `schema_version: 1` and `rules`. Every rule has `hostname`,
`review_team` (a 1 to 64 character team identifier), and 1 to 32 unique normalized
`expected_addresses`. Rules must be unique and stay within the explicit hostname
scope. Policy inputs have the same 1 MiB bound as observations and at most 1,000
rules. A matching address set returns `matches_reviewed_addresses`; an observed
mismatch lists unexpected and expected-but-not-observed addresses. Expectations and
team names are supplied policy, not a discovery or ownership lookup. Policies may
be stale or wrong, so review them before acting. No team is contacted.

`--output NEW_FILE.json` uses the same private, exclusive publication contract as
the comparison command. The full comparison and exact policy digest remain in the
output so a reviewer can trace the finding. These digests do not authenticate policy
approval. Next: design assessment provenance before introducing risk scores.


## Import a saved Zeek DNS log

Convert saved JSON Lines from Zeek into a compatible snapshot, without contacting a
resolver or requiring a running Zeek installation:

```bash
python projects/asset-intelligence/dns-review/zeek_dns_import.py \
  projects/asset-intelligence/dns-review/examples/zeek-dns.jsonl \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --record-type A --observed-at 2026-10-24T00:00:00Z \
  --output /tmp/zeek-dns-current.json
python projects/asset-intelligence/dns-review/dns_review.py \
  projects/asset-intelligence/dns-review/examples/before.json /tmp/zeek-dns-current.json \
  --scope projects/asset-intelligence/dns-review/examples/scope.json
```

The fabricated log imports the latest `web.example.test` address, `192.0.2.11`.
The comparison reports its change from the baseline. The worker's latest NXDOMAIN
response is counted as unsuitable and omitted, rather than inventing an empty address
set or reusing an older answer. A receipt on stdout includes the exact source and
scope digests, selected source lines, omitted latest responses, and filtered counts.
Retain that receipt privately with the original log when source references matter.
The snapshot is a new 0600 file; existing output is never overwritten.

Select `A` or `AAAA` explicitly, and compare only the same address family and collection
context. The importer does not combine families or infer collection completeness.
For each scoped query it selects the greatest transaction `ts`, regardless of file
order. Conflicting latest responses at equal timestamps fail instead of selecting an
arbitrary row. Identical latest responses retain all their source-line references.
Addresses are normalized and deduplicated. Older address sets are never unioned into
the latest response. The caller supplies an observation end at or after every selected
transaction; Zeek transaction time is not proof of answer time or snapshot completeness.

Required fields for scoped rows of the selected type are numeric `ts`, numeric
`qtype`, Internet `qclass: 1`, numeric `rcode`, and boolean `TC` and `rejected`.
Optional `qtype_name` must agree with the selection. Successful responses need a
nonempty answer array with at most 32 literal addresses of the selected family.
Truncated, rejected, negative, absent-answer, CNAME-containing, and wrong-family
latest responses are omitted with reasons. Alias answers are not assigned to the
query hostname because the flattened answer list does not establish that attribution.
Unknown metadata is ignored and never copied; out-of-scope queries and other record
types are counted separately. Invalid JSON, duplicate keys, malformed required fields,
non-finite values, rows over 64 KiB, more than 1,000 rows or a file over 1 MiB fail the
whole import. TSV, arbitrary DNS records, resolver-specific views and TTL expiry are
unsupported. No source authentication or authorization is inferred from these files.

Field semantics follow [Zeek's DNS log documentation](https://docs.zeek.org/en/current/reference/logs/dns.html).
Tests use synthetic JSON only; no live Zeek collection or third-party DNS was tested.


## Run the saved-log policy workflow in one command

Use one explicit address family for both collection windows, and retain the imported
snapshots, source-line receipts and policy findings in one private report:

```bash
python projects/asset-intelligence/dns-review/zeek_dns_workflow.py \
  projects/asset-intelligence/dns-review/examples/zeek-dns-before.jsonl \
  projects/asset-intelligence/dns-review/examples/zeek-dns.jsonl \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --policy projects/asset-intelligence/dns-review/examples/review-policy.json \
  --record-type A --previous-observed-at 2026-10-23T00:00:00Z \
  --current-observed-at 2026-10-24T00:00:00Z --output /tmp/dns-policy-workflow.json
```

Expect `review_created` and one finding, routed to `web-platform`. The report contains
both import receipts, both generated snapshots and the complete existing policy review.
The current web address comes from native log line 2. The worker's latest negative
response remains an omitted observation. The single `record-type` option prevents
accidentally comparing A imports with AAAA imports. The same scope applies to both logs.

Every stage must succeed before the complete 0600 report is published. Invalid trailing
log data, policy violations, collection-time errors or an existing output produce exit 2
with no success result or partial publication. Limits and omission rules from the importer
and policy reviewer remain in force; generated snapshots must also fit the existing
1 MiB snapshot contract. Existing commands retain their interfaces. Source metadata is
sensitive, so keep real logs and reports private and outside Git. No DNS query, team
notification, risk score, accepted ownership or remediation is added by this workflow.
