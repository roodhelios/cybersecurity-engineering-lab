"""Convert saved Linux IPv4 neighbor JSON snapshots into offline ARP observations."""

import argparse
import hashlib
import json
import os
import stat
import sys
import tempfile
from datetime import timezone
from pathlib import Path

from arp_consistency import (
    MAX_RECORDS, ObservationError, _object_without_duplicates,
    _parse_timestamp, parse_observation,
)

MAX_SNAPSHOT_BYTES = 4 * 1024 * 1024
MAX_SNAPSHOTS = 32


def _convert_snapshot(data: bytes, observed_at: str) -> tuple[list[dict], int, list[int]]:
    """Read a supplied timestamp, never infer capture time from file metadata."""
    timestamp = _parse_timestamp(observed_at).astimezone(timezone.utc).isoformat()
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise ObservationError("snapshot exceeds 4 MiB")
    rows = json.loads(data.decode("utf-8"), object_pairs_hook=_object_without_duplicates)
    if not isinstance(rows, list) or len(rows) > MAX_RECORDS:
        raise ObservationError("snapshot must be an array of at most 10000 rows")
    observations, unresolved, seen, source_rows = [], 0, set(), {}
    for number, row in enumerate(rows, 1):
        if not isinstance(row, dict) or not {"dst", "dev"} <= row.keys():
            raise ObservationError("neighbor row requires dst and dev")
        # Reuse the reviewer's address and interface contract even for unresolved rows.
        record = {"timestamp": timestamp, "interface": row["dev"], "ip": row["dst"],
                  "mac": row.get("lladdr", "00:00:00:00:00:00")}
        parsed = parse_observation(json.dumps(record), number)
        key = (parsed.interface, parsed.ip)
        if key in seen:
            raise ObservationError("duplicate interface and IP within one snapshot")
        seen.add(key)
        if "lladdr" not in row:
            state = row.get("state")
            if (not isinstance(state, list) or len(state) != 1
                    or state[0] not in ("INCOMPLETE", "FAILED")):
                raise ObservationError("missing MAC requires explicit INCOMPLETE or FAILED state")
            unresolved += 1
            continue
        record["mac"] = parsed.mac
        observations.append(record)
        source_rows[key] = number
    observations.sort(key=lambda item: (item["interface"], item["ip"]))
    rows = [source_rows[(record["interface"], record["ip"])] for record in observations]
    return observations, unresolved, rows


def convert_snapshot(data: bytes, observed_at: str) -> tuple[list[dict], int]:
    """Preserve the observation-only conversion interface."""
    records, unresolved, _ = _convert_snapshot(data, observed_at)
    return records, unresolved


def import_snapshots(snapshots) -> tuple[str, dict]:
    """Bind original bytes and row references to the exact generated JSON Lines."""
    if len(snapshots) > MAX_SNAPSHOTS:
        raise ObservationError("at most 32 snapshots are accepted")
    observations, skipped, previous = [], 0, None
    sources, references = [], []
    for index, (timestamp, path) in enumerate(snapshots, 1):
        current = _parse_timestamp(timestamp)
        if previous is not None and current <= previous:
            raise ObservationError("snapshot times must strictly increase")
        data = read_snapshot(Path(path))
        records, unresolved, rows = _convert_snapshot(data, timestamp)
        sources.append({
            "snapshot_index": index,
            "input_sha256": hashlib.sha256(data).hexdigest(),
            "observed_at": current.astimezone(timezone.utc).isoformat(),
            "observation_count": len(records),
            "unresolved_count": unresolved,
        })
        references.extend({"observation_line": len(observations) + offset,
                           "snapshot_index": index, "source_row": source_row}
                          for offset, source_row in enumerate(rows, 1))
        observations.extend(records)
        skipped += unresolved
        if len(observations) > MAX_RECORDS:
            raise ObservationError("combined observations exceed 10000 records")
        previous = current
    rendered = "".join(json.dumps(row, sort_keys=True) + "\n" for row in observations)
    receipt = {
        "schema_version": 1,
        "report_type": "neighbor-import-receipt",
        "observation_count": len(observations),
        "unresolved_count": skipped,
        "observations_sha256": hashlib.sha256(rendered.encode("utf-8")).hexdigest(),
        "snapshots": sources,
        "observation_references": references,
    }
    return rendered, receipt


def read_snapshot(path: Path) -> bytes:
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW
    with os.fdopen(os.open(path, flags), "rb") as source:
        if not stat.S_ISREG(os.fstat(source.fileno()).st_mode):
            raise ObservationError("snapshot must be a regular local file")
        return source.read(MAX_SNAPSHOT_BYTES + 1)


def publish(path: Path, rendered: str) -> None:
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", encoding="utf-8", dir=path.parent,
                                         prefix=".neighbor-import-", delete=False) as output:
            temporary = Path(output.name)
            output.write(rendered)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", nargs=2, action="append", required=True,
                        metavar=("OBSERVED_AT", "PATH"), help="repeat in chronological order")
    parser.add_argument("--output", type=Path, help="new private JSON Lines file; otherwise stdout")
    parser.add_argument("--format", choices=("observations", "receipt"), default="observations")
    parser.add_argument("--verify-receipt", type=Path,
                        help="reproduce a saved receipt before publishing observations")
    args = parser.parse_args(argv)
    try:
        if os.name != "posix":
            raise ObservationError("private snapshot import requires POSIX")
        if args.verify_receipt and args.format != "observations":
            raise ObservationError("receipt verification requires observations format")
        rendered, receipt = import_snapshots(args.snapshot)
        canonical_receipt = json.dumps(receipt, sort_keys=True, separators=(",", ":"))
        if args.verify_receipt:
            saved = read_snapshot(args.verify_receipt)
            if len(saved) > MAX_SNAPSHOT_BYTES:
                raise ObservationError("receipt exceeds 4 MiB")
            expected = json.loads(saved.decode("utf-8"),
                                  object_pairs_hook=_object_without_duplicates)
            if json.dumps(expected, sort_keys=True, separators=(",", ":")) != canonical_receipt:
                raise ObservationError("receipt does not reproduce from retained snapshots")
        if args.format == "receipt":
            rendered = json.dumps(receipt, sort_keys=True, indent=2) + "\n"
        if args.output:
            publish(args.output, rendered)
        else:
            print(rendered, end="")
        print(f"imported {receipt['observation_count']} observations; "
              f"skipped {receipt['unresolved_count']} unresolved rows",
              file=sys.stderr)
    except (OSError, ValueError, TypeError, UnicodeError, RecursionError, OverflowError):
        print("error: neighbor snapshots were not imported; check format, times, and output path",
              file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
