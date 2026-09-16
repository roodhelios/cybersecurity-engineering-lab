"""Tests for the scoped Aegis threat catalog."""

from __future__ import annotations

import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from aegis_threat_model.cli import main
from aegis_threat_model.model import ThreatModelError, load_catalog, parse_catalog


CATALOG_PATH = PROJECT_ROOT / "model" / "threats.json"


def catalog_dict() -> dict:
    return json.loads(CATALOG_PATH.read_text(encoding="utf-8"))


class ThreatCatalogTests(unittest.TestCase):
    def test_repository_catalog_resolves_every_reference(self) -> None:
        catalog = load_catalog(CATALOG_PATH)

        self.assertEqual(len(catalog.threats), 7)
        self.assertEqual(catalog.threats[0].threat_id, "TM-001")
        self.assertIn("asset:agent-identity", catalog.assets)

    def test_summary_counts_stride_categories(self) -> None:
        summary = load_catalog(CATALOG_PATH).summary()

        self.assertEqual(summary["counts"]["threats"], 7)
        self.assertEqual(summary["threats_by_stride"]["spoofing"], 2)
        self.assertEqual(summary["threats_by_stride"]["repudiation"], 1)

    def test_rejects_duplicate_control_identifier(self) -> None:
        value = catalog_dict()
        value["controls"].append(copy.deepcopy(value["controls"][0]))

        with self.assertRaisesRegex(ThreatModelError, "duplicate control id"):
            parse_catalog(value)

    def test_rejects_unknown_control_reference(self) -> None:
        value = catalog_dict()
        value["threats"][0]["controls"].append("control:not-defined")

        with self.assertRaisesRegex(ThreatModelError, "unknown references"):
            parse_catalog(value)

    def test_rejects_unknown_stride_category(self) -> None:
        value = catalog_dict()
        value["threats"][0]["stride"] = "persistence"

        with self.assertRaisesRegex(ThreatModelError, "not a supported STRIDE"):
            parse_catalog(value)

    def test_rejects_scope_overlap(self) -> None:
        value = catalog_dict()
        value["scope"]["excluded"].append(value["scope"]["included"][0])

        with self.assertRaisesRegex(ThreatModelError, "both included and excluded"):
            parse_catalog(value)

    def test_cli_writes_machine_readable_summary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "summary.json"
            status = main([str(CATALOG_PATH), "--output", str(output)])
            summary = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(summary["counts"]["threats"], 7)


if __name__ == "__main__":
    unittest.main()
