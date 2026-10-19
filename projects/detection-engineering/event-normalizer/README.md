# Security Event Normalizer

A dependency-free Python module that converts selected Suricata EVE and Zeek JSON records into one typed representation.

## Supported input

- Suricata EVE records containing `timestamp` and `event_type`
- Zeek JSON records containing numeric `ts` and Zeek connection fields

The parser intentionally rejects unknown shapes instead of silently guessing. Original records are retained in the normalized object for later evidence and troubleshooting.

## Import a Zeek text connection log

Zeek commonly writes tab-separated logs with `#separator`, `#fields`, and `#types`
headers. A text `conn.log` cannot be passed directly to the JSON parser. From this
project directory, convert the included synthetic log first:

```bash
PYTHONPATH=src python -m event_normalizer.zeek_tsv tests/fixtures/repeated_attempts.log \
  > /tmp/zeek-review.jsonl
PYTHONPATH=src python -m event_normalizer.correlation_cli /tmp/zeek-review.jsonl --include-evidence
```

Expect four imported events and one medium-confidence T1046 candidate. No Zeek
process, packet capture, or network request runs. Choose a fresh private output path;
shell redirection can overwrite existing files. Retain the text log as well as the
converted file. Evidence references identify converted JSONL lines; each converted
record also includes `_zeek_tsv_line` pointing to its original text-log line. Report
digests cover converted records, not the original text-log bytes.

This is a connection subset importer, not a lossless general Zeek reader. It requires
`#path conn`, tab separation, and matching field/type headers for `ts`, `uid`,
`id.orig_h`, `id.orig_p`, `id.resp_h`, `id.resp_p`, `proto`, `conn_state`, and `history`.
Columns may be reordered; extra columns are deliberately discarded. Selected text
fields support printable ASCII and hexadecimal `\xHH` escapes. Unset state/history
become null, not inferred connection attempts. Addresses, ports, and finite timestamps
are validated. Other log types, repeated schemas, and concatenated rotated logs fail.
A valid header-only log imports zero records; a close header is optional for active
saved logs, but records after it fail.

The whole import is bounded to 16 Mi characters, 20,000 lines, 10,000 events, 1 Mi
characters per line, and 256 characters per selected value. Malformed tails and
unsupported input exit 2 without emitting partial JSONL. This does not establish
source authenticity or live Zeek integration. Header and type conventions follow
the [official Zeek log-format documentation](https://docs.zeek.org/en/current/tutorial/logs.html),
checked October 19, 2026.

## Normalize JSON Lines

Run the module directly with a file:

```bash
PYTHONPATH=src python -m event_normalizer tests/fixtures/mixed_events.jsonl
```

Write normalized records to another file:

```bash
PYTHONPATH=src python -m event_normalizer input.jsonl --output normalized.jsonl
```

Standard input and output are used when paths are omitted, so the command can also
participate in a pipeline:

```bash
cat input.jsonl | PYTHONPATH=src python -m event_normalizer > normalized.jsonl
```

Empty lines are ignored. Processing stops at the first malformed or unsupported
record with a source name and line number on standard error. Because processing is
streaming, records emitted before an error remain in the output.

## Add ATT&CK candidates

Use `--attack-mappings` to add conservative MITRE ATT&CK candidates:

```bash
PYTHONPATH=src python -m event_normalizer input.jsonl --attack-mappings
```

Every candidate includes a technique ID, tactic, confidence, rule ID, and the exact
event fields that caused the mapping. Explicit Suricata technique metadata receives
medium confidence. One incomplete Zeek SYN can produce only a low-confidence T1046
candidate because a single failed connection does not prove scanning.

## Correlate repeated attempts

Run the included inert Zeek fixture through normalization and correlation:

```bash
PYTHONPATH=src python -m event_normalizer.correlation_cli tests/fixtures/repeated_attempts.jsonl
```

The JSON report contains `events_read: 4`, `finding_count: 1`, and one medium-confidence
T1046 candidate for source `192.0.2.10` with four attempts against four target pairs.
It contains no raw records. No packets or network requests are sent. Standard input
is supported when the path is omitted or `-`; redirect stdout to retain the report.

The command validates the whole batch before printing a report. Invalid input exits
2 with a source name and line number, without a partial success report. Batches are
limited to 10,000 non-empty events and lines to 1 Mi characters, including the newline.
This is an in-memory analyst tool, not a high-volume streaming collector. Source and
destination addresses can still be sensitive; keep real reports outside Git.

Add `--include-evidence` to emit report version 2. Each finding then lists only the
supporting records, with their one-based input line numbers and `event_sha256`.
Blank lines still count toward line numbers; completed connections are excluded.
References follow the finding's timestamp/target order and retain duplicate records.
The digest covers the original parsed JSON event, serialized as sorted UTF-8 JSON
with compact separators and finite numbers. JSON whitespace and key order do not
affect it. It is not a byte digest of the source file or proof of authenticity.
Keep the original input for review. The default version 1 report and the API's
`to_dict()` output remain unchanged; API objects expose zero-based `event_indices`.

The Python API also groups repeated Zeek `S0` connections from one source:

```python
from event_normalizer import correlate_repeated_attempts

findings = correlate_repeated_attempts(normalized_events)
```

The default rule requires at least four incomplete SYN attempts against at least three
distinct destination and port pairs within 60 seconds. Windows are deterministic and
non-overlapping. A finding is a medium-confidence investigation candidate, not proof
of scanning or compromise.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Measure local normalization throughput

Run the deterministic benchmark without contacting external systems:

```bash
PYTHONPATH=src python -m event_normalizer.benchmark_cli --events 50000 --rounds 5
```

The command emits machine-readable JSON with every timing sample and a description of
excluded work. See [the throughput notes](docs/THROUGHPUT.md) for the recorded local
run and its limitations.

## Example

```python
from event_normalizer import normalize_event

event = normalize_event(
    {
        "timestamp": "2026-09-12T18:30:00Z",
        "event_type": "alert",
        "src_ip": "10.0.0.10",
        "src_port": 51514,
        "dest_ip": "10.0.0.20",
        "dest_port": 443,
        "alert": {"severity": 2},
    }
)

print(event.to_dict())
```

## Reproduce a saved correlation report

From this project directory, save the evidence-bearing report and check it in a
separate process using only Python's standard library:

```bash
PYTHONPATH=src python -m event_normalizer.correlation_cli tests/fixtures/repeated_attempts.jsonl \
  --include-evidence > /tmp/correlation-review.json
PYTHONPATH=src python -m event_normalizer.evidence_verify tests/fixtures/repeated_attempts.jsonl \
  /tmp/correlation-review.json
```

Expect `status: reproduced`, `events_read: 4`, `finding_count: 1`, and
`evidence_references: 4`. Keep authorized input and redirected reports private and
outside Git. The shell redirection above can replace an existing file; choose a new
path. Verification does not write either input. It requires the complete version 2
report, including finding fields, counts, ordering, source lines, and event digests.
JSON key order and whitespace inside a line may differ, but inserted blank lines
change source references. Version 1, duplicate report fields, unknown or changed
fields, malformed input, and reports exceeding 16 MiB fail with exit 2 and no success
document. Existing correlation batch limits still apply. Empty batches can reproduce
with zero findings. Reproduction establishes consistency with this implementation,
not independent detection accuracy, authentic source data, or proof of compromise.

## Limitations

- ATT&CK output contains investigation candidates, not confirmed attacker behavior.
- The mapper recognizes a small allowlist of technique IDs and ignores unknown IDs.
- Correlation covers Zeek `conn` records and the normalizer's `connection` fallback
  when `_path` and `log_type` are absent, with the exact `S0` and `S` evidence
  pair. It does not infer intent or inspect packet payloads.
- Correlation is an in-memory batch API and CLI. High-volume streaming is
  not implemented yet.
- Only a small common field set is mapped; vendor-specific data remains in `raw`.
- The normalization command processes one JSON value per line without a maximum
  line size. Its fail-fast errors can leave an output file containing the successfully
  processed prefix. The separate correlation command has batch and line limits and
  does not emit a partial success report.
- No external systems are contacted.
