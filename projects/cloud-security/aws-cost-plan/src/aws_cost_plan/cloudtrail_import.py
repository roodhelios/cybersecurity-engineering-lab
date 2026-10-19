"""Convert one local CloudTrail Records document to private canonical JSON Lines."""

import argparse
import gzip
import hashlib
import io
import json
import sys
import zlib
from pathlib import Path

from .cloudtrail_handoff import _read, _publish, MAX_BYTES, MAX_EVENTS, MAX_LINE
from .cloudtrail_triage import triage_event


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _constant(value):
    raise ValueError("non-finite JSON number")


def convert_records(raw):
    """Validate the whole batch before producing any normalized event bytes."""
    if len(raw) > MAX_BYTES:
        raise ValueError("compressed or plain input exceeds 16 MiB")
    compressed = raw.startswith(b"\x1f\x8b")
    if compressed:
        with gzip.GzipFile(fileobj=io.BytesIO(raw)) as source:
            data = source.read(MAX_BYTES + 1)
    else:
        data = raw
    if len(data) > MAX_BYTES:
        raise ValueError("expanded input exceeds 16 MiB")
    value = json.loads(data.decode("utf-8"), object_pairs_hook=_object, parse_constant=_constant)
    if not isinstance(value, dict) or set(value) != {"Records"}:
        raise ValueError("expected a CloudTrail Records envelope")
    records = value["Records"]
    if not isinstance(records, list) or len(records) > MAX_EVENTS:
        raise ValueError("Records must be a bounded array")
    lines, seen = [], set()
    for event in records:
        # Reuse the current downstream triage contract. Unknown event fields survive.
        triage_event(event)
        event_id = event.get("eventID")
        if not isinstance(event_id, str) or not event_id.strip() or event_id in seen:
            raise ValueError("expected unique non-empty event IDs")
        seen.add(event_id)
        line = json.dumps(event, ensure_ascii=True, sort_keys=True, allow_nan=False, separators=(",", ":"))
        if len(line) > MAX_LINE:
            raise ValueError("normalized record exceeds 65536 characters")
        lines.append(line)
    rendered = "".join(line + "\n" for line in lines)
    if len(rendered.encode("utf-8")) > MAX_BYTES:
        raise ValueError("normalized output exceeds 16 MiB")
    receipt = {"schema_version": 1, "format": "cloudtrail-records",
               "compression": "gzip" if compressed else "none", "event_count": len(lines),
               "input_sha256": hashlib.sha256(raw).hexdigest(),
               "normalized_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest()}
    return rendered, receipt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="owned or authorized local JSON or gzip file")
    parser.add_argument("--output", required=True, type=Path, help="new private JSONL file")
    args = parser.parse_args(argv)
    try:
        rendered, receipt = convert_records(_read(args.input))
        _publish(args.output, rendered)
    except (OSError, ValueError, UnicodeError, EOFError, zlib.error, RecursionError, OverflowError):
        print("error: CloudTrail import failed; review the local file and choose a new output path", file=sys.stderr)
        return 2
    print(json.dumps(receipt, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
