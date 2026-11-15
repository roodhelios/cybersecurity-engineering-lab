# Review an original Zeek text log

The existing importer and correlation CLI require an intermediate converted JSONL
file. This separate workflow captures one original plain or gzip text `conn.log`,
imports the supported subset and correlates it in memory before publishing one
complete private report. From `projects/detection-engineering/event-normalizer`,
on POSIX with Python 3.11+:

```bash
review_dir=$(mktemp -d)
PYTHONPATH=src python -m event_normalizer.zeek_review create \
  tests/fixtures/repeated_attempts.log --scope synthetic \
  --output "$review_dir/review.json"
```

Expect `zeek_text_review_created`, `events_read: 4`, `finding_count: 1` and the
exact report digest. Retain that digest through an independently trusted channel.
To reproduce in a separate process with the intended scope:

```bash
PYTHONPATH=src python -m event_normalizer.zeek_review verify \
  tests/fixtures/repeated_attempts.log "$review_dir/review.json" \
  --scope synthetic --expected-report-sha256 TRUSTED_REPORT_SHA256
```

Expect `zeek_text_review_reproduced`, four events, one finding and four evidence
references. Replace the placeholder with the independently retained digest, not a
self-reported value from an untrusted report. Existing destinations are preserved;
creation publishes a complete mode-0600 file. Both commands print counts/digests
without addresses or connection identifiers. Failures return 2 with fixed diagnostics
and no success JSON. Verification does not change either input.

The report has `report_type: original-zeek-connection-review`, scope, exact original
byte digest, original/expanded byte counts, compression and a nested evidence-bearing
correlation report. Each reference retains its converted event `line_number` and
canonical event digest, plus `original_line_number`. For the fixture these are
converted positions 1 to 4 and original text lines 8 to 11. Gzip references address
the decompressed text; the original digest still binds the compressed bytes. Header,
blank-line or gzip-header changes require a new report even if selected events agree.
Extra discarded columns remain covered by the original byte digest but do not become
normalized fields. Existing selected-field and correlation semantics are unchanged.

Original and expanded inputs are each bounded to 16 MiB; existing text-import line,
event, schema and value bounds also apply. Gzip CRC/truncation errors reject. Reports
are bounded to 16 MiB. The report pin is checked before JSON parsing and correlation;
full canonical comparison checks every finding, reference, count and metadata field.
Duplicate report members, non-finite values, unknown or changed fields reject. A
valid header-only source can reproduce zero events; this is not evidence of safety.
The new limits/format do not change the legacy importer or JSONL commands.

For a temporary synthetic gzip exercise from the repository root:

```bash
python -m lab run zeek-review
```

Expect `zeek_review_exercise_passed`, `original_lines: [8, 9, 10, 11]` and three
rejected cases: recompressed originals, edited source references and a wrong scope.
The exercise blocks network creation and starts no Zeek process. The underlying
format conventions are described in [Zeek's official log documentation](https://docs.zeek.org/en/current/tutorial/logs.html),
checked November 15, 2026; the importer supports only the [documented connection subset](../README.md#import-a-zeek-text-connection-log).

Use closed inputs, trusted private ancestors and cooperative writers. Reads reject
symlinks/nonregular files and capture one bounded byte string. This is not an atomic
live collector or a power-loss durability protocol. Reports contain operational
addresses/findings, so retain them privately outside Git. Pins prove byte equality,
not source truth, reviewer identity, pin freshness or compromise. Current-model
reproduction does not provide historical detector dispatch. Prepared with assistant support.
