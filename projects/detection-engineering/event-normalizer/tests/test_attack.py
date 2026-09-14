"""Tests for evidence-backed ATT&CK candidate mapping."""

from __future__ import annotations

import io
import json
import sys
import unittest
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from event_normalizer import map_attack_candidates, normalize_event
from event_normalizer.cli import normalize_jsonl


class AttackMappingTests(unittest.TestCase):
    def test_maps_explicit_suricata_metadata(self) -> None:
        event = normalize_event(
            {
                "timestamp": "2026-09-13T18:30:00Z",
                "event_type": "alert",
                "alert": {
                    "signature": "Synthetic web exploit alert",
                    "metadata": {"mitre_technique_id": ["T1190"]},
                },
            }
        )

        candidates = map_attack_candidates(event)

        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0].technique_id, "T1190")
        self.assertEqual(candidates[0].confidence, "medium")
        self.assertIn("alert.metadata", candidates[0].evidence[0])

    def test_ignores_unrecognized_metadata_ids(self) -> None:
        event = normalize_event(
            {
                "timestamp": "2026-09-13T18:30:00Z",
                "event_type": "alert",
                "alert": {"metadata": {"mitre_technique_id": ["T9999"]}},
            }
        )

        self.assertEqual(map_attack_candidates(event), ())

    def test_marks_single_incomplete_syn_as_low_confidence(self) -> None:
        event = normalize_event(
            {
                "ts": 1789324200.0,
                "uid": "Csynthetic-s0",
                "_path": "conn",
                "id.orig_h": "192.0.2.10",
                "id.orig_p": 53000,
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 22,
                "proto": "tcp",
                "conn_state": "S0",
                "history": "S",
            }
        )

        candidates = map_attack_candidates(event)

        self.assertEqual(candidates[0].technique_id, "T1046")
        self.assertEqual(candidates[0].confidence, "low")
        self.assertIn("conn_state=S0", candidates[0].evidence)

    def test_does_not_map_completed_connection(self) -> None:
        event = normalize_event(
            {
                "ts": 1789324200.0,
                "uid": "Csynthetic-sf",
                "_path": "conn",
                "id.orig_h": "192.0.2.10",
                "id.resp_h": "198.51.100.20",
                "id.resp_p": 443,
                "conn_state": "SF",
                "history": "ShADadFf",
            }
        )

        self.assertEqual(map_attack_candidates(event), ())

    def test_jsonl_enrichment_is_opt_in(self) -> None:
        source = io.StringIO(
            json.dumps(
                {
                    "timestamp": "2026-09-13T18:30:00Z",
                    "event_type": "alert",
                    "alert": {"metadata": {"mitre_technique_id": ["T1190"]}},
                }
            )
            + "\n"
        )
        destination = io.StringIO()

        normalize_jsonl(source, destination, include_attack_mappings=True)

        output = json.loads(destination.getvalue())
        self.assertEqual(output["attack_mappings"][0]["technique_id"], "T1190")
        self.assertEqual(output["attack_mappings"][0]["confidence"], "medium")


if __name__ == "__main__":
    unittest.main()
