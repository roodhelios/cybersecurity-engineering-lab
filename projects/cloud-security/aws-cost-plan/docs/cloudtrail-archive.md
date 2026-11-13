# Retain a CloudTrail case with its replay dependencies

A retained case previously required separately managed original exports and model
code. This archive keeps the exact case bytes, ordered original JSON/gzip bytes,
recipient settings and an allowlisted model-source snapshot together. Verification
reproduces the complete case after checking an independent archive pin and matching
trusted checkout. Prepared with assistant support.

## Run the temporary exercise

From the repository root, on POSIX with Python 3.11 or newer:

```bash
python -S projects/cloud-security/aws-cost-plan/demo_cloudtrail_archive.py
```

Expect `cloudtrail_archive_exercise_passed`, `originals_removed: true`, two inputs,
four unique events, one duplicate copy and three rejected negative cases. The exercise
uses original synthetic fixtures and temporary plain/gzip files, removes the case
and both originals, then reproduces from the archive. Wrong pins, changed archive
bytes and a different recipient threshold reject. All temporary files are discarded.
Network socket creation is blocked. No AWS account, credentials or service is needed.

## Create one private archive

First create and review a case using the [collection workflow](cloudtrail-collection.md).
Retain its exact case digest independently. From the project directory:

```bash
PYTHONPATH=src python -S -m aws_cost_plan.cloudtrail_archive create \
  /private/case.json /private/source-a.json /private/source-b.json.gz \
  --expected-case-sha256 CASE_PIN \
  --account-id 111122223333 --case-id synthetic-collection --scope-note synthetic \
  --threshold 3 --window-seconds 300 --output /private/new-case.zip
```

Uppercase pins are placeholders for independently retained lowercase SHA-256 values.
Use the original input order and your separately chosen recipient settings. The
command verifies the case pin before consuming originals, reproduces every case
field, assembles the archive, verifies it again, and publishes one complete mode-0600
file without overwriting an existing path. The parent directory must already exist
and be private with trusted ancestors. A symlink or other existing destination is
preserved. Success reports `cloudtrail_archive_created` and `archive_sha256` with
minimized counts. Retain that archive digest separately from incoming files.

## Verify after moving or removing the originals

Use a trusted checkout whose retained model source matches the archive:

```bash
PYTHONPATH=src python -S -m aws_cost_plan.cloudtrail_archive verify /private/new-case.zip \
  --expected-archive-sha256 ARCHIVE_PIN \
  --account-id 111122223333 --case-id synthetic-collection --scope-note synthetic \
  --threshold 3 --window-seconds 300
```

Expect `cloudtrail_archive_reproduced`, `model_source_matched: true`,
`archived_code_executed: false`, four unique events and one duplicate copy for the
quickstart fixtures. The case digest in the summary binds the exact retained case
bytes. Verification checks archive members and digests, original gzip bytes, exact
model bytes and all case fields under your explicit settings. The archive cannot
select your recipient threshold or account. Normal output omits paths, account and
case labels, principals, addresses and raw events. Failure exits 2 with fixed text
and no success JSON. Verification does not write or restore any files.

## Format and bounds

Version 1 uses a stored ZIP container with fixed member names and deterministic
metadata. There is no ZIP compression or encryption. Members are:

- `case.json`: the exact reviewed case, at most 64 MiB.
- `inputs/01.bin` to `inputs/32.bin`: original bytes in selected order, at most
  16 MiB combined. Original gzip compression is preserved. Existing 16 MiB expanded
  per-source and aggregate normalized/event bounds still apply during replay.
- `model/`: eight allowlisted Python files covering package initialization and
  CloudTrail case/import/triage/correlation/reproduction dependencies, at most 1 MiB
  combined. These bytes are data only and are never imported or executed.
- `manifest.json`: format version, exact recipient settings, input count and each
  member's byte size and SHA-256, at most 128 KiB.

The archive is capped at 96 MiB and 42 members. Its bounded classic central directory
is checked before ZIP member allocation. Duplicate names, unexpected paths, missing
entries, directory/symlink members, encryption, ZIP64, compressed members, comments
and trailing data reject. The verifier never extracts paths. A different model
snapshot fails even if its member digest is internally consistent. Matching hashes
alone do not replace complete case reproduction.

## Interpretation and remaining work

This is private retention, not a redacted report. Original records and case fields
may contain sensitive data or credentials. Keep archives outside Git. No scanner
or redactor is applied to user-supplied logs. Storage encryption, backups and access
control remain the operator's responsibility. Use trusted local filesystems; this
does not certify power-loss durability or atomic capture of several changing files.

Verification needs matching trusted code and the current supported Python runtime.
Do not execute archived code to make an old artifact pass. Source bytes help retain
the implementation for review, but do not provide a trusted executable environment
or historical model dispatch. No source/collector authenticity, pin freshness,
telemetry completeness, account state, containment or recovery is established.

Next: define a verified restore procedure and supported historical model policy
before adding automatic environment selection or replay.
