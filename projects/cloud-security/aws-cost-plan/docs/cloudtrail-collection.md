# Review a saved CloudTrail collection as one case

CloudTrail can deliver duplicate events with the same `eventID`. AWS describes this
in its [CloudTrail FAQ](https://aws.amazon.com/cloudtrail/faqs/) and documents
[`eventID` and `recipientAccountID`](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-event-reference-record-contents.html).
The single-file importer remains useful for individual exports. The collection command
combines explicit saved files before triage and correlation, retaining every duplicate
copy's source location without counting it as another failed login.

## Run the synthetic example

Use Python 3.11 or newer and the standard library. From this project directory:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_case \
  examples/cloudtrail-collection-a.json examples/cloudtrail-collection-b.json \
  --account-id 111122223333 --case-id synthetic-collection --scope-note synthetic \
  --output /tmp/cloudtrail-case.json
```

Choose a new output path on POSIX. Expect a JSON summary with:

```json
{
  "input_count": 2,
  "supplied_event_count": 5,
  "unique_event_count": 4,
  "duplicate_copy_count": 1,
  "finding_count": 5,
  "login_candidate_count": 1,
  "status": "unreviewed",
  "containment": "not_performed",
  "recovery": "not_verified"
}
```

The actual summary also includes `schema_version` and the exact saved `case_sha256`.
The supplied account ID is an explicit synthetic example, not a verified AWS account.
The command does not authenticate, download logs, discover files, create cloud
resources or take response actions. Exit 0 means a case was published, even when
findings exist. Invalid input or publication failure exits 2 without a success summary.

## What the private case retains

The output is one complete mode-0600 JSON file, exclusively published without
replacing an existing path. No intermediate JSONL or separately lost receipt is needed.
All files are validated before publication. The case includes:

- `sources`: ordered input indices, exact raw-byte SHA-256 digests, byte counts,
  compression mode and each source's normalization receipt. Paths are not embedded.
- `normalized_jsonl`: the complete unique records, in first-seen input/record order.
  Unknown fields survive. The handoff's source digest binds these exact UTF-8 bytes.
- `event_sources`: each normalized line's input indices and one-based record numbers
  within the original `Records` arrays. Duplicate copies retain multiple references.
- `handoff`: chronologically sorted, line-linked triage using the existing rules,
  with containment and recovery explicitly unverified.
- `correlation`: the selected threshold/window and failed-login candidates. Each
  candidate's sorted `event_ids` has a parallel `source_lines` list linking the unique
  normalized records and, through `event_sources`, all retained original copies.

Stdout contains counts, state and a case digest. The private case contains raw event
fields, account/identity labels, source addresses and possibly sensitive data. It is
not a redacted artifact. Keep it and the original files outside Git. Privately retain
the ordered input list so input indices can be matched to the originals. Source
hashes and references do not authenticate a collector or validate CloudTrail signatures.

## Duplicate and scope rules

Every event must have the exact twelve-digit `recipientAccountID` supplied with
`--account-id`. Missing and different account claims reject the whole case. Split
other accounts into separate cases. This prevents accidental cross-account grouping;
it does not prove the supplied account label or authorize access to any account.

Within each source, existing import validation still rejects duplicate event IDs.
Across files, the same ID counts once only when the full canonical normalized record
matches. Object-key ordering and JSON formatting do not matter. Different values,
unknown fields or numeric representations for one ID reject the collection. No
preferred source is chosen and fields are not reconciled. IDs must be non-empty and
have no surrounding whitespace. `sharedEventID` is not a deduplication key.

The input list's order is meaningful: reversing it changes normalized line references
and case bytes. Repeat the same ordered inputs and settings for deterministic output.
Correlation still uses the existing principal/source heuristic, not an authenticated
identity model or calibrated compromise detector.

## Bounds and validation

Plain JSON and gzip are recognized by bytes, not filenames. The collection permits
1 to 32 explicitly supplied regular files, at most 16 MiB of total supplied bytes,
16 MiB of total normalized bytes before deduplication and 20,000 supplied records
including duplicate copies. Each source also retains the importer's 16 MiB expanded
limit and 65,536-character record limit. The final case is limited to 64 MiB.
An empty `Records` file produces an unreviewed empty case, not a clean-account claim.

```bash
python -m unittest discover -s tests -p 'test_cloudtrail_case.py' -v
python -m unittest discover -s tests -v
```

Coverage includes overlap reproduction against the existing correlator, gzip, matching
and conflicting copies, scope, original source references, retained-line reproduction,
collection bounds, private output/collisions and late failure without partial output.
These are local fixture tests. Live AWS collection, account state, telemetry completeness,
source authentication, historical model replay and response execution remain untested.

## Reproduce a retained case as the recipient

The saved case is untrusted input. Rebuild it from the original ordered files with
separately chosen review requirements, rather than trusting its counts or adopting
its threshold. For the quickstart case above, run from this project directory:

```bash
PYTHONPATH=src python -m aws_cost_plan.cloudtrail_case_verify /tmp/cloudtrail-case.json \
  examples/cloudtrail-collection-a.json examples/cloudtrail-collection-b.json \
  --account-id 111122223333 --case-id synthetic-collection --scope-note synthetic \
  --threshold 3 --window-seconds 300
```

Expect `status: case_reproduced`, four unique events, one duplicate copy, five
findings and one login candidate. The unsigned summary includes the exact case digest
and normalized-byte digest, but omits account IDs, case/scope labels, principals,
source addresses, file paths and raw event fields. The case and originals are unchanged.
Use `--output NEW_PATH` to retain this summary privately without overwriting a file.
Exit 0 means consistency under these requirements, not approval or a clean account.

All five context/settings flags are required. Obtain them through the review process;
do not blindly copy them from an untrusted report. Scope notes follow the builder's
trimmed-text contract. Reproduction checks every field: source receipts, complete
normalized records, duplicate-copy references, timeline, findings, correlation and
unreviewed containment/recovery state. Unexpected/missing fields, duplicate JSON
members, booleans or floats replacing integer fields, and non-finite numbers reject.
JSON formatting/key order may differ, but original source bytes and order must match.
Recompressing a gzip or reformatting a source requires rebuilding the case because
its original-byte receipt changes, even when normalized events are identical.

The case reader accepts one no-follow regular local file up to 64 MiB. Original-file
and aggregate bounds remain those of the builder. Failures exit 2 with fixed text,
no success summary and no new output. There are no AWS/API calls or response actions.

```bash
python -m unittest discover -s tests -p 'test_cloudtrail_case_verify.py' -v
```

This verifies current-implementation consistency against supplied bytes. It does not
authenticate source logs, recipient requirements or the unsigned summary; establish
telemetry completeness; prove collection scope; or implement historical model replay.
Retain the original files, review requirements and matching implementation checkout.
Next work is a portable retention procedure for those dependencies, with explicit
model/version support rather than guessing how an older case should be interpreted.
