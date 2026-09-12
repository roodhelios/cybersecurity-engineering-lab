"""Unit tests for supported event formats and failure behavior."""

from __future__ import annotations

import sys
import unittest
from datetime import timezone
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from event_normalizer import NormalizationError, normalize_event


class NormalizeEventTests(unittest.TestCase):
    def test_normalizes_suricata_alert(self) -> None:
        raw = {
            "timestamp": "2026-09-12T18:30:00.123456Z",
            "event_type": "alert",
            "src_ip": "10.0.0.10",
            "src_port": 51514,
            "dest_ip": "10.0.0.20",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {"severity": 2, "signature": "Synthetic test alert"},
        }

        event = normalize_event(raw)

        self.assertEqual(event.source, "suricata")
        self.assertEqual(event.event_type, "alert")
        self.assertEqual(event.dest_port, 443)
        self.assertEqual(event.severity, 2)
        self.assertEqual(event.timestamp.tzinfo, timezone.utc)
        self.assertEqual(event.raw, raw)

    def test_normalizes_zeek_connection(self) -> None:
        raw = {
            "ts": 1789237800.5,
            "uid": "Csynthetic123",
            "_path": "conn",
            "id.orig_h": "192.0.2.10",
            "id.orig_p": 53123,
            "id.resp_h": "198.51.100.20",
            "id.resp_p": 53,
            "proto": "udp",
        }

        event = normalize_event(raw)

        self.assertEqual(event.source, "zeek")
        self.assertEqual(event.event_type, "conn")
        self.assertEqual(event.src_ip, "192.0.2.10")
        self.assertEqual(event.dest_ip, "198.51.100.20")
        self.assertEqual(event.dest_port, 53)
        self.assertEqual(event.protocol, "udp")

    def test_converts_offset_timestamp_to_utc(self) -> None:
        event = normalize_event(
            {
                "timestamp": "2026-09-12T14:30:00-04:00",
                "event_type": "flow",
            }
        )

        self.assertEqual(event.timestamp.isoformat(), "2026-09-12T18:30:00+00:00")

    def test_rejects_naive_timestamp(self) -> None:
        with self.assertRaisesRegex(NormalizationError, "include a timezone"):
            normalize_event(
                {"timestamp": "2026-09-12T18:30:00", "event_type": "flow"}
            )

    def test_rejects_out_of_range_port(self) -> None:
        with self.assertRaisesRegex(NormalizationError, "0 to 65535"):
            normalize_event(
                {
                    "timestamp": "2026-09-12T18:30:00Z",
                    "event_type": "flow",
                    "dest_port": 70000,
                }
            )

    def test_rejects_unknown_event_shape(self) -> None:
        with self.assertRaisesRegex(NormalizationError, "unsupported event shape"):
            normalize_event({"message": "not enough schema information"})


if __name__ == "__main__":
    unittest.main()
