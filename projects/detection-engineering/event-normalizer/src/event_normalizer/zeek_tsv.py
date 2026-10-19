"""Import a bounded tab-separated Zeek conn.log into the existing JSONL pipeline."""

import argparse
import ipaddress
import json
import math
import re
import sys
from pathlib import Path

from .normalizer import normalize_event

MAX_LINE_CHARS = 1024 * 1024
MAX_LINES = 20000
MAX_EVENTS = 10000
MAX_INPUT_CHARS = 16 * 1024 * 1024
REQUIRED = {"ts": "time", "uid": "string", "id.orig_h": "addr", "id.orig_p": "port",
            "id.resp_h": "addr", "id.resp_p": "port", "proto": "enum",
            "conn_state": "string", "history": "string"}
ESCAPE = re.compile(r"\\x([0-9a-fA-F]{2})")


def _text(value):
    if "\\" in ESCAPE.sub("", value):
        raise ValueError("unsupported escape")
    decoded = ESCAPE.sub(lambda match: chr(int(match[1], 16)), value)
    if not decoded or any(not 32 <= ord(char) <= 126 for char in decoded):
        raise ValueError("selected fields must contain printable ASCII")
    return decoded


def _schema(headers):
    if not all(name in headers for name in ("separator", "path", "fields", "types")):
        raise ValueError("missing Zeek headers")
    fields, types = headers["fields"].split("\t"), headers["types"].split("\t")
    if len(fields) != len(types) or len(fields) != len(set(fields)):
        raise ValueError("invalid Zeek schema")
    declared = dict(zip(fields, types))
    if any(declared.get(key) != kind for key, kind in REQUIRED.items()):
        raise ValueError("unsupported Zeek connection schema")
    return fields


def import_conn_log(source):
    """Validate the whole selected connection subset before returning any records."""
    headers, events = {}, []
    closed = False
    characters = 0
    for number in range(1, MAX_LINES + 2):
        line = source.readline(MAX_LINE_CHARS + 1)
        if not line:
            break
        characters += len(line)
        if number > MAX_LINES or len(line) > MAX_LINE_CHARS or characters > MAX_INPUT_CHARS:
            raise ValueError("Zeek text input exceeds line limits")
        line = line.rstrip("\r\n")
        if not line:
            continue
        if closed:
            raise ValueError("data after Zeek close header")
        if line.startswith("#separator "):
            name, value = "separator", line[len("#separator "):]
        elif line.startswith("#"):
            name, separator, value = line[1:].partition("\t")
            if not separator:
                raise ValueError("invalid Zeek header")
        else:
            try:
                if len(events) >= MAX_EVENTS:
                    raise ValueError("too many Zeek events")
                fields = _schema(headers)
                values = line.split("\t")
                if len(values) != len(fields):
                    raise ValueError("Zeek column count or duplicate field")
                row = dict(zip(fields, values))
                event = {"_path": "conn", "_zeek_tsv_line": number}
                for key in REQUIRED:
                    value = row[key]
                    if len(value) > 256:
                        raise ValueError("selected Zeek field exceeds 256 characters")
                    if value == headers.get("unset_field", "-"):
                        if key not in {"conn_state", "history"}:
                            raise ValueError("required Zeek identity field is unset")
                        event[key] = None
                    elif key == "ts":
                        event[key] = float(value)
                        if not math.isfinite(event[key]):
                            raise ValueError("non-finite timestamp")
                    elif key.endswith("_p"):
                        if not value.isascii() or not value.isdecimal() or not 0 <= int(value) <= 65535:
                            raise ValueError("invalid port")
                        event[key] = int(value)
                    elif key.endswith("_h"):
                        event[key] = str(ipaddress.ip_address(value))
                    else:
                        event[key] = _text(value)
                normalize_event(event)
                events.append(event)
            except (ValueError, OverflowError) as exc:
                raise ValueError(f"invalid Zeek connection at line {number}") from exc
            continue
        if name not in {"separator", "set_separator", "empty_field", "unset_field", "path", "open", "close", "fields", "types"}:
            raise ValueError("unsupported Zeek header")
        if name in headers or (events and name != "close"):
            raise ValueError("repeated or late Zeek header")
        if name == "separator" and value != r"\x09":
            raise ValueError("only tab-separated Zeek logs are supported")
        if name == "path" and value != "conn":
            raise ValueError("only conn.log is supported")
        headers[name] = value
        closed = name == "close"
    _schema(headers)
    return events


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    try:
        with args.input.open(encoding="utf-8") as source:
            events = import_conn_log(source)
    except (OSError, ValueError, UnicodeError, OverflowError):
        print("error: cannot import the supported Zeek conn.log subset", file=sys.stderr)
        return 2
    for event in events:
        print(json.dumps(event, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
