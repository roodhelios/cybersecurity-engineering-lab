"""Build a local, unreviewed CloudTrail handoff without taking response actions."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from .cloudtrail_triage import CloudTrailTriageError, triage_event

MAX_BYTES = 16 * 1024 * 1024
MAX_EVENTS = 20_000
MAX_LINE = 65_536


def build_handoff(data: bytes, *, case_id: str, scope_note: str) -> dict:
    """Link triage decisions to the exact supplied bytes, not a live account."""
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", case_id):
        raise CloudTrailTriageError("case ID must be 1 to 64 letters, numbers, dots, underscores, or hyphens")
    if not scope_note.strip() or len(scope_note) > 512:
        raise CloudTrailTriageError("scope note must contain 1 to 512 characters")
    if len(data) > MAX_BYTES:
        raise CloudTrailTriageError("input exceeds 16 MiB")
    timeline = []
    for line_number, line in enumerate(data.decode("utf-8").splitlines(), 1):
        if not line.strip():
            continue
        if len(line) > MAX_LINE or len(timeline) >= MAX_EVENTS:
            raise CloudTrailTriageError("input exceeds record limits")
        event = json.loads(line)
        findings = [finding.to_dict() for finding in triage_event(event)]
        timestamp = datetime.fromisoformat(event["eventTime"].replace("Z", "+00:00"))
        timeline.append({"source_line": line_number,
                         "event_time": timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
                         "event_name": event["eventName"], "findings": findings})
    # Tie-break on the source line so repeated timestamps remain independently reviewable.
    timeline.sort(key=lambda event: (datetime.fromisoformat(event["event_time"].replace("Z", "+00:00")),
                                     event["source_line"]))
    return {"schema_version": 1, "case_id": case_id, "scope_note": scope_note.strip(),
            "status": "unreviewed", "source_sha256": hashlib.sha256(data).hexdigest(),
            "source_bytes": len(data), "event_count": len(timeline),
            "finding_count": sum(len(event["findings"]) for event in timeline),
            "flagged_event_count": sum(bool(event["findings"]) for event in timeline),
            "timeline": timeline, "containment": "not_performed", "recovery": "not_verified",
            "review_required": ["Confirm collection scope and missing telemetry.",
                                "Compare flagged activity with approved changes.",
                                "Record owner approval before any response action."]}


def _read(path):
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    with os.fdopen(os.open(path, flags), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise CloudTrailTriageError("input must be a regular local file")
        data = source.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise CloudTrailTriageError("input exceeds 16 MiB")
    return data


def _publish(path, document):
    # Publish a complete private file without replacing an existing output.
    name = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".handoff-", delete=False) as output:
            name = output.name
            output.write(document)
            output.flush()
            os.fsync(output.fileno())
        os.link(name, path)
    finally:
        if name is not None:
            Path(name).unlink(missing_ok=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("events", type=Path)
    parser.add_argument("--case-id", required=True)
    parser.add_argument("--scope-note", required=True)
    parser.add_argument("--output", type=Path, help="new private JSON file; never overwrite")
    args = parser.parse_args(argv)
    try:
        result = build_handoff(_read(args.events), case_id=args.case_id, scope_note=args.scope_note)
        document = json.dumps(result, sort_keys=True, indent=2, allow_nan=False) + "\n"
        if args.output is None:
            print(document, end="")
        else:
            _publish(args.output, document)
    except (OSError, ValueError, UnicodeError, RecursionError, OverflowError):
        print("error: handoff failed; check local input, case metadata, and a new output path", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
