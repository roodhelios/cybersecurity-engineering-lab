# Security Event Normalizer

A dependency-free Python module that converts selected Suricata EVE and Zeek JSON records into one typed representation.

## Supported input

- Suricata EVE records containing `timestamp` and `event_type`
- Zeek JSON records containing numeric `ts` and Zeek connection fields

The parser intentionally rejects unknown shapes instead of silently guessing. Original records are retained in the normalized object for later evidence and troubleshooting.

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

## Limitations

- ATT&CK output contains investigation candidates, not confirmed attacker behavior.
- The mapper recognizes a small allowlist of technique IDs and ignores unknown IDs.
- Correlation covers Zeek `conn` records and the normalizer's `connection` fallback
  when `_path` and `log_type` are absent, with the exact `S0` and `S` evidence
  pair. It does not infer intent or inspect packet payloads.
- Correlation is an in-memory batch API and CLI. High-volume streaming is
  not implemented yet.
- Only a small common field set is mapped; vendor-specific data remains in `raw`.
- The command processes one JSON value per line and does not currently enforce a maximum line size.
- Fail-fast errors can leave an output file containing the successfully processed prefix.
- No external systems are contacted.
