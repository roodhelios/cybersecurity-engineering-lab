# Scoped DNS observation review

Compare two saved hostname-to-address snapshots without sending DNS queries. This
starts the lab's asset-intelligence milestone with explicit scope, normalized host
records, provenance references, and an address-change review. Reviewed address rules and team routing are available below. Explicit risk triage for reviewed mismatches is available below. Accepted
ownership, remediation, collection and broader asset correlation remain unimplemented here.

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

## Verify a retained workflow

After creating `/tmp/dns-policy-workflow.json` above, reproduce the report in another
process using the original logs, scope and policy:

```bash
python projects/asset-intelligence/dns-review/zeek_dns_workflow_verify.py \
  /tmp/dns-policy-workflow.json \
  projects/asset-intelligence/dns-review/examples/zeek-dns-before.jsonl \
  projects/asset-intelligence/dns-review/examples/zeek-dns.jsonl \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --policy projects/asset-intelligence/dns-review/examples/review-policy.json
```

Expect `workflow_reproduced`, `finding_count: 1` and `record_type: A`. The verifier
reimports both logs and recomputes the complete policy review, not just stored digests.
It compares every retained field, including source-line references, omissions,
snapshots and counts. JSON whitespace/key ordering may differ; values and their types
must match. The result includes the checked report's exact byte digest.

If the report contains optional risk or team-response layers, supply their exact
original files with the same `--assessment` and `--ownership-responses` options used
to create it. Missing or extra optional inputs fail. A retained queue is recomputed
automatically. Changed source, scope, policy or optional-input bytes fail even when
their JSON meaning is unchanged. A changed finding, risk score, team response, queue
item, source receipt or extra field also fails. No input file is rewritten.

The report is limited to 16 MiB and must be a regular local file, not a symlink or
FIFO. Other inputs retain the 1 MiB bound. Exit 2 emits no success JSON and sanitized
error text. Successful stdout contains only counts, flags, address-family selection
and the report digest, without hostnames, addresses, team labels or raw logs.

Recorded collection ends, address family and optional-layer selection remain supplied
claims. Reproduction does not authenticate those choices, source truth, policy
approval or team acceptance. It uses the current implementation, not a frozen historic
model. Removing an optional layer creates a different report; this verifier does not
enforce an externally required review policy. Retain the original source checkout and
inputs, keep real evidence private, and review the scope before sharing a handoff.


## Add explicit risk-review facts

The workflow can score current mismatch findings when separately reviewed facts are
supplied. Add this option to the complete saved-log command above, with a fresh output:

```bash
--assessment projects/asset-intelligence/dns-review/examples/risk-assessments.json
```

The synthetic web finding gets risk score **95**: high business impact 50, public
exposure 25, unreviewed change 20. `risk_review` retains each factor, uncapped total,
cap adjustment, review reference, assessment row and exact input digest. The existing
policy finding and review-team routing remain present. Missing facts produce
`unassessed` with no score, rather than assuming low risk. Default workflow output
remains unchanged when the option is omitted.

These are explicit model-v1 lab weights, not probabilities or vulnerability severity:

| Input | Points |
| --- | --- |
| Business impact | low 10, moderate 30, high 50 |
| Service exposure | internal 0, restricted 10, public 25 |
| Change authorization | approved -20, unreviewed 20, denied 35 |

Scores clamp to 0 through 100. Bands are routine below 40, priority from 40 through 69,
and urgent from 70. Both clipping and band boundaries are tested. An approved change
can reduce triage but never dismisses the underlying address-policy mismatch.

Assessment JSON has exactly `schema_version: 1` and `assessments`, an array of at most
1,000 entries and 1 MiB. Each entry has exactly `hostname`, `current_addresses`,
`observed_at`, `business_impact`, `service_exposure`, `change_authorization` and
`review_reference`. The example shows the complete shape. Each hostname must identify
one unique current mismatch; its normalized address set and observation time must match
the current snapshot. Stale, unmatched, ambiguous, unknown or malformed facts reject
the entire workflow before output. Review references are bounded technical labels,
not proof of a person, approval or accepted ownership. Scope and every supplied fact
remain claims. This adds no enrichment, notification, exploit test or remediation.

## Record an explicit team response

Routing a mismatch to a team does not record whether that team accepts the review.
The saved-log workflow now accepts `--ownership-responses examples/ownership-responses.json`
(in this directory). Add that option to the workflow command above, using a new output
path. For the committed fixtures, expect one `accepted_claim`, zero pending responses,
and the same mismatch finding. `--assessment` can be used at the same time; team
responses never change the risk calculation.

The input has `schema_version: 1` and a `responses` list. Each response contains
`finding_sha256`, `team`, `decision` (`accepted` or `declined`), `reviewed_at` and a
bounded `review_reference`. Generate the digest with
`dns_ownership_review.finding_digest(review, finding)` from the returned workflow's
`review` and selected finding. It binds the full finding, policy digest, current
observation time and addresses. A changed policy, finding or observation requires a
new response. Only the routed team is supported; reassignment needs a new policy.
Missing responses remain `pending`; duplicates, stale digests, wrong teams and times
before the observation fail before publication.

The response is a supplied claim. It does not authenticate a team member, establish
asset ownership, dismiss a finding, grant access or send a notification. Authentication,
independent acceptance evidence and remediation remain unfinished.

## Prioritize the next local review

Add `--queue` to the saved-log workflow. From this directory, a complete fixture run is:

```bash
python zeek_dns_workflow.py examples/zeek-dns-before.jsonl examples/zeek-dns.jsonl \
  --scope examples/scope.json --policy examples/review-policy.json \
  --previous-observed-at 2026-10-23T00:00:00Z --current-observed-at 2026-10-24T00:00:00Z \
  --record-type A --assessment examples/risk-assessments.json \
  --ownership-responses examples/ownership-responses.json --queue --output /tmp/new-dns-queue.json
```

Choose an unused output path. Expect `review_queue` with one urgent item at score 95
and `next_review: review_proposed_remediation`. Its supplied team response remains
`accepted_claim`, not authenticated acceptance. Without a response, the suggestion is
`request_team_response`; a decline yields `resolve_declined_routing`. Without risk
facts, the finding stays in `unassessed` with no score and `supply_assessment_facts`.

Scored items sort by urgent, priority and routine, then descending score and hostname.
Unassessed items form a separate final bucket; this does not classify them as low risk.
Each item retains its finding digest, routing, response claim, and any supplied score
factors/reference. `band_counts` makes missing assessment coverage visible. An empty
finding set has empty work and zero counts. The original findings and scores remain.

This is a review queue with suggested next steps. It adds no approved remediation,
deadlines, ownership proof, notification or execution. Authenticated handoff and
remediation evidence remain unfinished.
