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

The Python API can group repeated Zeek `S0` connections from one source inside a
bounded time window:

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
- Correlation currently covers Zeek `conn` records with the exact `S0` and `S` evidence
  pair. It does not infer intent or inspect packet payloads.
- Correlation is an in-memory batch API. Input retention and high-volume streaming are
  not implemented yet.
- Only a small common field set is mapped; vendor-specific data remains in `raw`.
- The command processes one JSON value per line and does not currently enforce a maximum line size.
- Fail-fast errors can leave an output file containing the successfully processed prefix.
- No external systems are contacted.
