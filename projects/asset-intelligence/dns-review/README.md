# Scoped DNS observation review

Compare two saved hostname-to-address snapshots without sending DNS queries. This
starts the lab's asset-intelligence milestone with explicit scope, normalized host
records, provenance references, and an address-change review. Reviewed address rules and team routing are available below. Explicit risk triage for reviewed mismatches is available below. Accepted
ownership, remediation, collection and broader asset correlation remain unimplemented here.

For a complete synthetic handoff that requires recipient approval and authorized
reviewer signatures, see [finding-scoped reviewer authority](#require-finding-scoped-reviewer-authority).

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


## Require independent handoff layers

A self-consistent report can omit every optional review layer and still reproduce.
The recipient can now require selected layers and an address family from a separate,
independently trusted requirements file:

```json
{
  "schema_version": 1,
  "record_type": "A",
  "required_layers": ["risk_review", "ownership_review", "review_queue"]
}
```

From the repository root, enter this project folder and create a new private report
(use a fresh output path if the example was already run):

```bash
cd projects/asset-intelligence/dns-review
python zeek_dns_workflow.py examples/zeek-dns-before.jsonl examples/zeek-dns.jsonl \
  --scope examples/scope.json --policy examples/review-policy.json \
  --previous-observed-at 2026-10-23T00:00:00Z \
  --current-observed-at 2026-10-24T00:00:00Z --record-type A \
  --assessment examples/risk-assessments.json \
  --ownership-responses examples/ownership-responses.json --queue \
  --output /tmp/dns-required-handoff.json
python zeek_dns_workflow_verify.py /tmp/dns-required-handoff.json \
  examples/zeek-dns-before.jsonl examples/zeek-dns.jsonl \
  --scope examples/scope.json --policy examples/review-policy.json \
  --assessment examples/risk-assessments.json \
  --ownership-responses examples/ownership-responses.json \
  --requirements examples/handoff-requirements.json
```

The bundled requirements demand all three optional layers. A report that reproduces
but omits any required layer exits 2 with no success document. A matching report
returns `workflow_reproduced`, `requirements_checked: true` and the exact requirements
file SHA-256, while the full original-input reproduction still runs. All inputs and
the report remain unchanged. Without the flag, the prior verifier interface and
output remain unchanged.

The version-1 requirements object has exactly the three fields above. Schema version must be
integer 1, record type is A or AAAA, and required_layers is a list of zero to three
unique supported names. An empty list still enforces the record type. Unknown or
duplicate fields/layers, wrong types and files over 1 MiB are rejected. The CLI uses
the same bounded regular-file reader and rejects symlinks and special files.

Choose the requirements independently of the sender's report. An attacker able to
replace the requirements can weaken them; the digest records bytes, not policy
authenticity or approval. Layer presence and reproducibility do not prove every
finding was assessed or accepted, authenticate team claims, establish complete
discovery, or prove remediation. This checks required evidence structure, not an
external service's authorization. No DNS query, lookup or notification is sent.

For approval by a locally pinned recipient key, use the separate signed-requirements
command below. Independent key enrollment/distribution and reviewer authority remain
unfinished; the unsigned command does not gain approval merely by retaining a digest.


### Require complete finding review coverage

Version 1 requires presence of review layers, even if their findings remain unassessed
or pending. To require complete coverage of the reproduced mismatch findings, use:

```json
{
  "schema_version": 2,
  "record_type": "A",
  "required_layers": ["risk_review", "ownership_review", "review_queue"],
  "finding_coverage": {"risk_assessed": true, "team_responded": true}
}
```

After creating the complete retained report in the preceding example, repeat its
verification command with `--requirements examples/handoff-requirements-complete.json`.
Expect `workflow_reproduced` and `requirements_checked: true`. A report rebuilt from
empty assessment or response lists still reproduces, but fails this recipient policy.
No success JSON is emitted on coverage failure, and no input file is modified.

Version 2 has exactly these four top-level fields. `finding_coverage` has exactly the
two shown boolean flags; integer or string substitutes are rejected. A true flag must
also name its corresponding layer in `required_layers`. A false flag keeps that
finding-level requirement disabled; layer-presence requirements still apply.
Full report reproduction precedes coverage checks, so a forged score, response status
or count cannot replace recomputation from the separately supplied review inputs.
The requirements digest continues to bind exact bytes, not recipient approval.

`risk_assessed` requires every reproduced finding's status to be `scored`.
`team_responded` requires every finding's observation-bound response to be either
`accepted_claim` or `declined_claim`. A decline counts as a response, not acceptance.
Pending responses and unassessed risk do not meet the respective true flag. An empty
finding set meets both coverage requirements when the required layers are present;
it does not establish complete collection or absence of real problems.

These checks do not authenticate reviewers, accept asset ownership, dismiss findings,
validate risk calibration or prove remediation. Requirements must be selected and
protected independently of the sender. Version 1 and no-requirements verification
keep their existing behavior; saved workflow report formats are unchanged.

## Verify recipient-signed requirements

The existing verifier accepts independently selected unsigned requirement files.
For a recipient that requires signed approval, install the optional native Ed25519
dependency and run the complete local exercise from this project directory:

```bash
python -m pip install -r requirements-auth.txt
python demo_authorized_handoff.py
```

Expect `authorized_handoff_exercise_passed`, `finding_count: 1`,
`negative_cases_rejected: 4`, `native_ed25519: true` and `inputs_unchanged: true`.
The exercise creates one ephemeral signing key in memory, a temporary authority file,
an approval and a complete synthetic workflow. It runs both API and file-based CLI
verification, then rejects altered requirements, a revoked key, expiry and a forged
report. Its October 27 verification instant is explicitly supplied. All temporary
files are discarded; no private key is written, source is collected or network used.
Trusting a self-created demo key is not evidence of real recipient enrollment.

For separately retained handoff files, use the mandatory-approval command:

```bash
python dns_authorized_handoff.py workflow.json before.jsonl after.jsonl \
  --scope scope.json --policy review-policy.json \
  --requirements handoff-requirements.json --approval recipient-approval.json \
  --authority-policy trusted-recipient-authorities.json \
  --assessment risk-assessments.json --ownership-responses ownership-responses.json
```

Use exactly the optional assessment/response inputs retained by the workflow. This
command requires approval and authority files; it never falls back to unsigned
verification. Omit `--at` for the current UTC clock. `--at YYYY-MM-DDTHH:MM:SSZ`
is for explicit offline fixture/review instants and is labeled `explicit_fixture`
in output; it does not prove an approval is currently valid. Missing crypto support,
invalid approvals and reproduction/coverage failures emit no success JSON.

Obtain the authority file independently of the handoff sender. Version 1 has exactly
`schema_version: 1`, `authority_type: dns-recipient-authorities`, `audience`,
`maximum_validity_seconds` and `keys`. Audience and key IDs use 3 to 64 lowercase
letters/digits/hyphens, starting with a letter. The lifetime limit is an integer from
1 to 604800 seconds. Each of 1 to 16 unique keys has exactly `key_id`,
`public_key_b64` and `status`. The public key is canonical base64 for 32 raw bytes;
status is `active`, `retired` or `revoked`. Repeated key IDs or public-key bytes fail,
so an active alias cannot override a retired/revoked pin. Only an active pinned key is accepted.
No key embedded in a report or approval can replace that pin.

An approval has exactly `schema_version: 1`,
`approval_type: dns-recipient-requirements`, `key_id`, `audience`, `issued_at`,
`expires_at`, `requirements_sha256`, `scope_sha256`, `review_policy_sha256` and
`signature_b64`. Times are canonical whole-second UTC strings ending in Z.
The verification instant must satisfy `issued_at <= now < expires_at`, and the full
positive validity duration must fit the authority policy's limit. Hashes bind exact
requirement, scope and address-policy bytes, including whitespace. The detached
64-byte Ed25519 signature covers the canonical unsigned approval fields with the
domain prefix `cybersecurity-engineering-lab:dns-recipient-requirements:v1` followed
by one zero byte. Duplicate/unknown JSON fields and noncanonical encodings fail.

`create_approval` is the issuer API for a separately managed PyNaCl `SigningKey`.
It signs in memory and verifies the result against the intended local authority file
before returning approval bytes. The demo shows the API with a throwaway key. This
project does not provide production key enrollment, private-key loading/storage or
a signing service. Never put real private keys in examples, Git or command arguments.

After approval verification, every saved workflow field is reproduced and the signed
requirements are applied to that rebuilt result. Output adds
`recipient_authority_checked: true`, key ID, audience, issue/expiry/check instants,
approval and authority-file digests, and `verification_time_source`. It excludes
source records, public keys and signatures. Identifiers, times and digests remain
operational metadata; keep them non-sensitive and retain real handoffs privately.
No input is changed, DNS query sent, notification delivered or remediation performed.

This authenticates possession of the private key corresponding to an active local
pin. It does not establish the named recipient's real identity or the authority file's
authenticity/freshness. Protect that file independently, refresh revocation state and
rotate pins through an independently authenticated process. A replaced or stale trust
file can authorize the wrong key or miss revocation. Approvals are reusable within
their validity window, not one-time tokens; there is no replay ledger, network key
lookup, rollback-resistant policy version or historical trust replay. Signing
requirements binds review context, not source truth, collection completeness, risk
calibration, team-response authorship, accepted ownership or remediation. Those
claims need the separate reviewer verifier below. Enrollment and distribution
contracts remain unfinished.

The optional dependency is [PyNaCl 1.6.2](https://pypi.org/project/PyNaCl/1.6.2/).
The implementation uses its documented [SigningKey and VerifyKey API](https://pynacl.readthedocs.io/en/latest/signing/),
not custom Ed25519 arithmetic. Run the full DNS suite with PyNaCl installed:
`python -m unittest discover -s tests -q`. Without it, signature tests are explicitly
skipped and the authorized command fails closed; the unsigned workflow still works.

## Require finding-scoped reviewer authority

From the repository root, after installing the optional dependency above:

```bash
python projects/asset-intelligence/dns-review/demo_reviewer_handoff.py
```

Expect `reviewer_handoff_exercise_passed`, `finding_count: 1`,
`attestation_count: 2`, `negative_cases_rejected: 4` and `inputs_unchanged: true`.
The exercise builds the full saved-log workflow, recipient approval and explicit
risk/team grants using three separate ephemeral keys. It verifies natively through
the API and actual file-based CLI, rejects missing/altered attestations, revocation
and a wrong reviewer-policy pin, and preserves all temporary inputs. No private
keys are written to disk, no network or signing service is contacted and all files
are discarded. Discarding Python references does not establish memory erasure.

This solves a distinct handoff gap: a report with revised risk or team-response
claims can reproduce and satisfy unchanged recipient requirements. Requirement
approval never signed those supplied review records. The new verifier adds exactly
one authorized `risk` and one authorized `team-response` signature per reproduced
finding. It requires 1 to 1000 findings, both complete review layers and all existing
recipient-approval checks. There is no unsigned or partial-coverage fallback.

The separate reviewer policy has exactly `schema_version: 1`,
`authority_type: dns-reviewer-authorities`, `audience`,
`maximum_validity_seconds` and `keys`. Its audience must match the recipient policy.
Its positive lifetime limit is at most 604800 seconds. Each of 1 to 16 keys has
exactly `key_id`, `public_key_b64`, `status` and `grants`. Key IDs, public-key encoding,
unique IDs/public bytes and active-only use follow the recipient-authority rules.
Each grant has exactly `finding_sha256`, `role` and `team`. Finding digests use the
existing `dns_ownership_review.finding_digest` contract, which binds the address
policy, exact finding, observation instant and current address set. A risk grant
uses `team: null`; a team-response grant names the exact routed team, as a non-empty
bounded string (at most 64 characters, no control characters). There are at most
2000 total grants, with no duplicate grants within a key and no wildcards.

The detached bundle is `{"schema_version": 1, "attestations": [...]}`. Each
attestation has exactly `schema_version: 1`, `attestation_type: dns-finding-review`,
`key_id`, `audience`, `issued_at`, `expires_at`, `finding_sha256`, `role`,
`review_record_sha256` and `signature_b64`. The record digest covers canonical JSON
of the entire original assessment or team-response record, including review reference.
Whitespace/order outside JSON values does not matter to that digest. It does not
sign a score alone or substitute a hostname for the finding revision.
The signature domain is `cybersecurity-engineering-lab:dns-finding-review:v1`
followed by one zero byte and canonical unsigned attestation fields. Time/encoding
rules follow recipient approvals, and issuance cannot precede the record's claimed
observation or review time. Duplicate/unknown fields, non-finite values, missing,
extra, repeated, wrong-role or wrong-team attestations fail. Each input policy or
bundle remains bounded to 1 MiB. Existing source/report limits still apply.

`create_attestation` is an issuer API accepting a separately managed in-memory
PyNaCl `SigningKey`, explicit finding/role/team grant and original review record.
It verifies the signature and grant before returning a dictionary. The helper does
not independently establish that a supplied record is true; recipient verification
still reproduces the complete workflow. No production key loader, enrollment,
signing service or issuer identity directory is implemented. Use only temporary
keys for the demo and never commit private keys or place them in CLI arguments.

For retained authorized inputs, independently enroll the keys and distribute the
reviewer policy's exact SHA-256 through a trusted channel. Do not treat a policy
and digest delivered together by an untrusted sender as an independent trust pin.
Retain the earlier workflow/approval inputs and invoke the new verifier:

```bash
python dns_reviewer_handoff.py report.json before.jsonl after.jsonl \
  --scope scope.json --policy review-policy.json \
  --requirements handoff-requirements.json --approval recipient-approval.json \
  --authority-policy recipient-authorities.json --reviewer-policy reviewer-authorities.json \
  --expected-reviewer-policy-sha256 INDEPENDENTLY_TRUSTED_REVIEWER_POLICY_SHA256 \
  --attestations reviewer-attestations.json --assessment risk-assessments.json \
  --ownership-responses ownership-responses.json --at 2026-10-28T12:00:00Z
```

Run this command from the project directory. The digest placeholder must be replaced
with the independently trusted lowercase SHA-256, not inferred from the report.
`--at` is an explicit fixture clock; omit it for the current UTC clock with your
own authorized data. Both clocks remain trusted host inputs, not timestamp proofs.
Success adds `reviewer_authority_checked: true` and a `reviewer_authority` summary
with `attestation_count`, `risk_attestation_count`, `team_response_attestation_count`,
policy and bundle digests. It retains the existing workflow status and recipient
summary. No raw records, hostnames, addresses, team strings, public keys or signatures
reach stdout. Keep counts, identifiers, times and digests private as operational metadata.
Invalid input returns code 2 with no success output and a generic error.

Every existing report field reproduces before reviewer signatures are accepted.
Nothing mutates the report, source files, risk scores, queues or the existing
`accepted_claim`/`declined_claim` labels. The policy authorizes enrolled keys for
claims; it does not establish a natural person's identity, independent judgment,
source truth, accepted asset ownership or remediation. A policy may grant one key
both roles; separation of duties and multi-reviewer quorums are not enforced.
Stale policy plus matching old pin can miss revocation. Policy enrollment, trusted
distribution/freshness, key rotation and clock integrity remain external. Valid
attestations can be reused during their window; no replay ledger or rollback-resistant
policy version is implemented. The aggregate verification summary is unsigned.

```bash
python -m unittest discover -s tests -p test_dns_reviewer_handoff.py -v
```
