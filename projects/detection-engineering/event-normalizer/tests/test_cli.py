"""Tests for the JSON Lines command-line interface."""

from __future__ import annotations

import io
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
FIXTURES = Path(__file__).parent / "fixtures"
sys.path.insert(0, str(SRC_ROOT))

from event_normalizer.cli import JsonlInputError, main, normalize_jsonl


class NormalizeJsonlTests(unittest.TestCase):
    def test_fixture_matches_golden_output(self) -> None:
        destination = io.StringIO()

        with (FIXTURES / "mixed_events.jsonl").open(encoding="utf-8") as source:
            emitted = normalize_jsonl(source, destination, source_name="fixture.jsonl")

        expected = (FIXTURES / "mixed_events.expected.jsonl").read_text(
            encoding="utf-8"
        )
        self.assertEqual(emitted, 2)
        self.assertEqual(destination.getvalue(), expected)

    def test_ignores_blank_lines(self) -> None:
        source = io.StringIO(
            '\n  \n{"timestamp":"2026-09-12T18:30:00Z","event_type":"flow"}\n'
        )
        destination = io.StringIO()

        emitted = normalize_jsonl(source, destination)

        self.assertEqual(emitted, 1)
        self.assertEqual(len(destination.getvalue().splitlines()), 1)

    def test_invalid_json_reports_source_and_line(self) -> None:
        destination = io.StringIO()

        with (FIXTURES / "invalid_events.jsonl").open(encoding="utf-8") as source:
            with self.assertRaisesRegex(
                JsonlInputError, r"invalid_events\.jsonl:2: invalid JSON"
            ):
                normalize_jsonl(
                    source,
                    destination,
                    source_name="invalid_events.jsonl",
                )

        self.assertEqual(len(destination.getvalue().splitlines()), 1)


class MainTests(unittest.TestCase):
    def test_writes_an_output_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "normalized.jsonl"

            status = main(
                [str(FIXTURES / "mixed_events.jsonl"), "--output", str(output)]
            )

            self.assertEqual(status, 0)
            self.assertEqual(
                output.read_text(encoding="utf-8"),
                (FIXTURES / "mixed_events.expected.jsonl").read_text(
                    encoding="utf-8"
                ),
            )

    def test_rejects_same_input_and_output_path(self) -> None:
        path = FIXTURES / "mixed_events.jsonl"

        with patch("sys.stderr", new_callable=io.StringIO) as stderr:
            status = main([str(path), "--output", str(path)])

        self.assertEqual(status, 2)
        self.assertIn("input and output paths must be different", stderr.getvalue())

    def test_module_entrypoint_emits_golden_output(self) -> None:
        environment = os.environ.copy()
        existing_pythonpath = environment.get("PYTHONPATH")
        environment["PYTHONPATH"] = os.pathsep.join(
            part for part in (str(SRC_ROOT), existing_pythonpath) if part
        )

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "event_normalizer",
                str(FIXTURES / "mixed_events.jsonl"),
            ],
            cwd=PROJECT_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            result.stdout,
            (FIXTURES / "mixed_events.expected.jsonl").read_text(encoding="utf-8"),
        )


if __name__ == "__main__":
    unittest.main()
