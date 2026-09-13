"""Command-line interface for newline-delimited security events."""

from __future__ import annotations

import argparse
import json
import sys
from contextlib import ExitStack
from pathlib import Path
from typing import Sequence, TextIO

from .attack import map_attack_candidates
from .normalizer import NormalizationError, normalize_event


class JsonlInputError(ValueError):
    """Raised when a JSON Lines record cannot be decoded or normalized."""


def normalize_jsonl(
    source: TextIO,
    destination: TextIO,
    *,
    source_name: str = "<stdin>",
    include_attack_mappings: bool = False,
) -> int:
    """Normalize non-empty JSON Lines records and return the emitted count."""

    emitted = 0
    for line_number, line in enumerate(source, start=1):
        if not line.strip():
            continue

        try:
            raw_event = json.loads(line)
        except json.JSONDecodeError as exc:
            raise JsonlInputError(
                f"{source_name}:{line_number}: invalid JSON ({exc.msg})"
            ) from exc

        try:
            event = normalize_event(raw_event)
        except NormalizationError as exc:
            raise JsonlInputError(f"{source_name}:{line_number}: {exc}") from exc

        output = event.to_dict()
        if include_attack_mappings:
            output["attack_mappings"] = [
                candidate.to_dict() for candidate in map_attack_candidates(event)
            ]
        destination.write(json.dumps(output, sort_keys=True, separators=(",", ":")))
        destination.write("\n")
        emitted += 1

    return emitted


def _argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="security-event-normalizer",
        description="Normalize Suricata EVE and Zeek JSON Lines records.",
    )
    parser.add_argument(
        "input",
        nargs="?",
        default="-",
        help="input JSONL path, or - for standard input (default: -)",
    )
    parser.add_argument(
        "--attack-mappings",
        action="store_true",
        help="include conservative ATT&CK candidates and their evidence",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="-",
        help="output JSONL path, or - for standard output (default: -)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the JSON Lines command and return a process exit status."""

    args = _argument_parser().parse_args(argv)

    if args.input != "-" and args.output != "-":
        if Path(args.input).resolve() == Path(args.output).resolve():
            print("error: input and output paths must be different", file=sys.stderr)
            return 2

    try:
        with ExitStack() as stack:
            if args.input == "-":
                source = sys.stdin
                source_name = "<stdin>"
            else:
                source = stack.enter_context(
                    Path(args.input).open("r", encoding="utf-8")
                )
                source_name = args.input

            if args.output == "-":
                destination = sys.stdout
            else:
                destination = stack.enter_context(
                    Path(args.output).open("w", encoding="utf-8", newline="\n")
                )

            normalize_jsonl(
                source,
                destination,
                source_name=source_name,
                include_attack_mappings=args.attack_mappings,
            )
    except (JsonlInputError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 0
