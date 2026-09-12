# Security Event Normalizer

A dependency-free Python module that converts selected Suricata EVE and Zeek JSON records into one typed representation.

## Supported input

- Suricata EVE records containing `timestamp` and `event_type`
- Zeek JSON records containing numeric `ts` and Zeek connection fields

The parser intentionally rejects unknown shapes instead of silently guessing. Original records are retained in the normalized object for later evidence and troubleshooting.

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

- This is schema normalization, not threat classification.
- Only a small common field set is mapped; vendor-specific data remains in `raw`.
- Input is trusted to be a decoded JSON object and is subject to configurable application-level size limits later.
- No external systems are contacted.
