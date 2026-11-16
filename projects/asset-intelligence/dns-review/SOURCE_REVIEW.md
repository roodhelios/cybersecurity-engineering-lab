# Review aligned saved DNS snapshots

The chronological comparator asks what changed between two times. This command
instead compares two to eight explicitly supplied snapshots whose `observed_at`
claims name the same UTC instant. It groups each exact normalized hostname's
complete address sets without selecting an authoritative answer or merging names
that share an address. It uses only the existing bounded snapshot and scope formats.

From the repository root, use Python 3.11 or newer on POSIX:

```bash
python -m lab run dns-sources
```

Expect `dns_source_review_exercise_passed` with three supplied inputs, two distinct
input byte digests, and `identical_input_groups: [[1, 3]]`. It also reports
`recipient_status: dns_source_review_reproduced` and `changed_original: rejected`.
The synthetic exercise
reports one hostname in each status: `agreement`, `disagreement`,
`single_observation` and `not_observed`. It creates no files or network connections.
The third input is deliberately a copy, not independent corroboration.

## Retain a private review

```bash
review_dir=$(mktemp -d)
python projects/asset-intelligence/dns-review/dns_sources_review.py \
  projects/asset-intelligence/dns-review/examples/after.json \
  projects/asset-intelligence/dns-review/examples/alternate-view.json \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --output "$review_dir/review.json"
```

Expect stdout status `dns_source_review_written`, two supplied inputs, two distinct
input byte digests, the same four status counts, and `output_sha256`. Stdout omits
hostnames, addresses and file paths. The complete report is a new private 0600 file;
existing destinations are preserved. Remove your temporary directory when finished
or retain the report, original snapshots and scope privately outside Git.

For the fixture, `web.example.test` has two address groups, `192.0.2.11` from input
1 row 1 and `192.0.2.12` from input 2 row 1. `new.example.test` agrees on
`192.0.2.10`. `worker.example.test` is observed only in input 2, and
`unseen.example.test` is absent from both. The worker sharing the new host's address
never merges the two hostnames. Original one-based input and row indexes remain
attached to every group, even after hostname/address normalization and sorting.

| Status | Meaning |
| --- | --- |
| `agreement` | At least two supplied inputs observe the hostname and list the same complete address set. Other inputs may be missing it. |
| `disagreement` | Supplied observations contain more than one complete address set. No majority wins. |
| `single_observation` | Exactly one supplied input observes the hostname. |
| `not_observed` | No supplied input observes an allowed hostname. |

`missing_source_indexes` makes partial coverage explicit. `sources` binds ordered
input positions to exact byte digests and original record counts; the scope digest
and normalized observation time are also retained. `identical_input_groups` flags
repeated byte digests. This cannot establish that different bytes came from
different collectors. Reformatting a copy makes its byte digest different while
leaving the same claims. Neither form establishes independent corroboration.

## Reproduce a received review

The recipient supplies the exact ordered originals and scope, plus independently
retained SHA-256 pins for the report, every original and the scope. The verifier
checks pins before parsing, regenerates the complete report with the current
implementation and compares every field. It does not trust pins inside the report.
Changed counts, source-row references, types, unknown fields and input order fail.
JSON whitespace/key ordering can differ if the independent report pin names those
exact received bytes; array and input order remain significant.

For the locally generated fixture report above, record pins from your own trusted
creation context and run:

```bash
sha256_file() {
  python -c 'import hashlib, pathlib, sys; print(hashlib.sha256(pathlib.Path(sys.argv[1]).read_bytes()).hexdigest())' "$1"
}
report_pin=$(sha256_file "$review_dir/review.json")
scope_pin=$(sha256_file projects/asset-intelligence/dns-review/examples/scope.json)
first_pin=$(sha256_file projects/asset-intelligence/dns-review/examples/after.json)
second_pin=$(sha256_file projects/asset-intelligence/dns-review/examples/alternate-view.json)
python projects/asset-intelligence/dns-review/dns_sources_verify.py \
  "$review_dir/review.json" \
  projects/asset-intelligence/dns-review/examples/after.json \
  projects/asset-intelligence/dns-review/examples/alternate-view.json \
  --scope projects/asset-intelligence/dns-review/examples/scope.json \
  --expected-report-sha256 "$report_pin" --expected-scope-sha256 "$scope_pin" \
  --expected-input-sha256 "$first_pin" --expected-input-sha256 "$second_pin"
```

Expect `dns_source_review_reproduced`, two supplied inputs, two distinct input byte
digests and one hostname per status. The verifier reads bounded regular files,
writes nothing and emits counts/pin only, without hostname/address/path details.
A wrong report pin stops before original files are opened. Other failures return
exit 2 with a fixed diagnostic and no success JSON. Reports are limited to 32 MiB;
the existing 1 MiB snapshot/scope limits and two-to-eight input count still apply.
Leaf symlinks, directories and FIFOs are rejected; parent directories must be trusted.

For a real handoff, retain and distribute all pins separately through an independently
trusted channel. Computing fresh pins from untrusted received files authenticates
nothing. This example computes pins only for locally generated synthetic evidence.
Reproduction is against the current checkout, with no historical model dispatch,
source signature, time freshness, trusted latest-state service or independent
collector evidence. Review whether the pinned views/address families and context
were comparable before interpreting results. No key, service or network is used.

## Bounds and interpretation

Every snapshot and scope file is limited to 1 MiB, so at most 8 MiB of snapshot
bytes plus the scope is read. Existing limits of 1,000 allowed hosts/records and
32 literal addresses per observed hostname still apply. Duplicate fields, unknown
fields, non-finite values, out-of-scope names, duplicate normalized rows/addresses,
symlinks and non-regular inputs fail the entire command. Too few/many files and
different time claims also fail. Exit 2 prints a fixed error with no success report
or newly published file; exit 0 means the complete grouped review was written.

Snapshots must come from collection contexts you have reviewed as comparable,
including address family and DNS view. Same time claims do not establish
simultaneous collection. Agreement does not establish a correct answer or collector
authenticity. Disagreement can reflect collection context or legitimate views,
not compromise, severity or unauthorized change. Missing rows are not NXDOMAIN,
removal, failure or proof of incomplete collection. Hostnames are scoped comparison
keys, not general device identities. This command performs no queries, scans,
enrichment, risk scoring, team routing, notifications or remediation. Scope is a
caller claim, not permission proof. Prepared with assistant support and synthetic
local fixtures.
