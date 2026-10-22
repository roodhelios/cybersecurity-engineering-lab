import importlib.util
import json
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "arp_consistency.py"
SPEC = importlib.util.spec_from_file_location("arp_consistency", MODULE_PATH)
arp_consistency = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
sys.modules[SPEC.name] = arp_consistency
SPEC.loader.exec_module(arp_consistency)


def observation(timestamp, ip="192.0.2.10", mac="02:00:00:00:00:10", interface="lab0"):
    return json.dumps({"timestamp": timestamp, "interface": interface, "ip": ip, "mac": mac})


def lease(starts_at="2026-10-21T12:00:45Z", ends_at="2026-10-21T13:00:00Z",
          ip="192.0.2.10", mac="02:00:00:00:00:99", interface="lab0"):
    return json.dumps({"starts_at": starts_at, "ends_at": ends_at,
                       "interface": interface, "ip": ip, "mac": mac})


def forwarding_entry(captured_at="2026-10-21T12:00:50Z",
                     mac="02:00:00:00:00:99", interface="lab0", port="swp7"):
    return json.dumps({"captured_at": captured_at, "interface": interface,
                       "mac": mac, "port": port})


def port_policy(mac="02:00:00:00:00:99", interface="lab0",
                allowed_ports=None):
    return json.dumps({"interface": interface, "mac": mac,
                       "allowed_ports": allowed_ports or ["swp7"]})


class ArpConsistencyTests(unittest.TestCase):
    def test_reports_recent_mapping_change_with_source_lines(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ])

        self.assertEqual(report["observation_count"], 2)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0], {
            "type": "ip_mac_mapping_change",
            "confidence": "medium",
            "interface": "lab0",
            "ip": "192.0.2.10",
            "previous_mac": "02:00:00:00:00:10",
            "current_mac": "02:00:00:00:00:99",
            "previous_line": 1,
            "current_line": 2,
            "elapsed_seconds": 60,
        })
        self.assertIn("not proof", report["interpretation"])
        self.assertNotIn("lease_reconciliation", report)
        self.assertNotIn("lease_status", report["findings"][0])

    def test_matching_lease_marks_expected_reassignment(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ], leases=[lease()])
        self.assertEqual(report["findings"][0]["lease_status"], "expected_reassignment")
        self.assertEqual(report["findings"][0]["lease_line"], 1)
        self.assertEqual(report["lease_reconciliation"], {
            "lease_count": 1,
            "expected_reassignments": 1,
            "unexplained_changes": 0,
        })

    def test_recent_forwarding_entry_links_current_mac_and_port(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ], forwarding_entries=[forwarding_entry()])
        self.assertEqual(report["findings"][0]["forwarding_status"],
                         "current_mac_observed")
        self.assertEqual(report["findings"][0]["forwarding_line"], 1)
        self.assertEqual(report["findings"][0]["current_port"], "swp7")
        self.assertEqual(report["forwarding_reconciliation"], {
            "entry_count": 1,
            "current_mac_observed": 1,
            "no_recent_current_mac": 0,
            "max_age_seconds": 300,
            "port_moves_observed": 0,
            "stable_ports": 0,
            "insufficient_port_history": 1,
        })

    def test_two_recent_forwarding_snapshots_report_port_move(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ], forwarding_entries=[
            forwarding_entry(captured_at="2026-10-21T12:00:20Z", port="swp3"),
            forwarding_entry(captured_at="2026-10-21T12:00:50Z", port="swp7"),
        ])

        finding = report["findings"][0]
        self.assertEqual(finding["port_history_status"], "port_move_observed")
        self.assertEqual(finding["previous_port"], "swp3")
        self.assertEqual(finding["current_port"], "swp7")
        self.assertEqual(finding["previous_forwarding_line"], 1)
        self.assertEqual(finding["forwarding_line"], 2)
        self.assertEqual(finding["port_history_elapsed_seconds"], 30)
        self.assertEqual(report["forwarding_reconciliation"]["port_moves_observed"], 1)

    def test_port_policy_marks_expected_and_unexpected_current_ports(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        expected = arp_consistency.review_lines(
            observations,
            forwarding_entries=[forwarding_entry()],
            port_policy=[port_policy()],
        )
        unexpected = arp_consistency.review_lines(
            observations,
            forwarding_entries=[forwarding_entry(port="swp8")],
            port_policy=[port_policy()],
        )

        self.assertEqual(expected["findings"][0]["port_policy_status"],
                         "expected_port")
        self.assertEqual(expected["findings"][0]["port_policy_line"], 1)
        self.assertEqual(expected["port_policy_reconciliation"], {
            "rule_count": 1,
            "expected_ports": 1,
            "unexpected_ports": 0,
            "no_matching_rule": 0,
            "no_recent_forwarding_evidence": 0,
        })
        self.assertEqual(unexpected["findings"][0]["port_policy_status"],
                         "unexpected_port")
        self.assertEqual(
            unexpected["port_policy_reconciliation"]["unexpected_ports"], 1
        )

    def test_port_policy_distinguishes_missing_rule_and_missing_evidence(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        missing_rule = arp_consistency.review_lines(
            observations,
            forwarding_entries=[forwarding_entry()],
            port_policy=[port_policy(mac="02:00:00:00:00:98")],
        )
        missing_evidence = arp_consistency.review_lines(
            observations,
            forwarding_entries=[],
            port_policy=[port_policy()],
        )

        self.assertEqual(missing_rule["findings"][0]["port_policy_status"],
                         "no_matching_rule")
        self.assertEqual(missing_evidence["findings"][0]["port_policy_status"],
                         "no_recent_forwarding_evidence")

    def test_rejects_ambiguous_port_policy(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        with self.assertRaisesRegex(arp_consistency.ObservationError,
                                    "requires forwarding input"):
            arp_consistency.review_lines(observations, port_policy=[port_policy()])
        with self.assertRaisesRegex(arp_consistency.ObservationError,
                                    "sorted and unique"):
            arp_consistency.review_lines(
                observations,
                forwarding_entries=[],
                port_policy=[port_policy(allowed_ports=["swp8", "swp7"])],
            )
        with self.assertRaisesRegex(arp_consistency.ObservationError,
                                    "duplicate rule"):
            arp_consistency.review_lines(
                observations,
                forwarding_entries=[],
                port_policy=[port_policy(), port_policy()],
            )

    def test_same_port_and_stale_history_are_distinguished(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        stable = arp_consistency.review_lines(observations, forwarding_entries=[
            forwarding_entry(captured_at="2026-10-21T12:00:20Z", port="swp7"),
            forwarding_entry(captured_at="2026-10-21T12:00:50Z", port="swp7"),
        ])
        stale = arp_consistency.review_lines(observations, forwarding_entries=[
            forwarding_entry(captured_at="2026-10-21T11:55:00Z", port="swp3"),
            forwarding_entry(captured_at="2026-10-21T12:00:50Z", port="swp7"),
        ])

        self.assertEqual(stable["findings"][0]["port_history_status"], "stable_port")
        self.assertEqual(stable["forwarding_reconciliation"]["stable_ports"], 1)
        self.assertEqual(stale["findings"][0]["port_history_status"],
                         "insufficient_history")
        self.assertEqual(stale["forwarding_reconciliation"]["port_moves_observed"], 0)

    def test_future_stale_or_wrong_forwarding_entry_is_not_linked(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        for unmatched in (
            forwarding_entry(captured_at="2026-10-21T12:01:01Z"),
            forwarding_entry(captured_at="2026-10-21T11:55:59Z"),
            forwarding_entry(mac="02:00:00:00:00:98"),
        ):
            with self.subTest(entry=unmatched):
                report = arp_consistency.review_lines(
                    observations, forwarding_entries=[unmatched]
                )
                self.assertEqual(
                    report["findings"][0]["forwarding_status"],
                    "no_recent_current_mac",
                )
                self.assertEqual(
                    report["findings"][0]["port_history_status"],
                    "insufficient_history",
                )
                self.assertEqual(
                    report["forwarding_reconciliation"]["no_recent_current_mac"], 1
                )

    def test_rejects_ambiguous_forwarding_entries_and_age(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        with self.assertRaisesRegex(arp_consistency.ObservationError,
                                    "duplicate capture time"):
            arp_consistency.review_lines(
                observations,
                forwarding_entries=[forwarding_entry(), forwarding_entry(port="swp8")],
            )
        with self.assertRaisesRegex(arp_consistency.ObservationError,
                                    "forwarding max age"):
            arp_consistency.review_lines(
                observations, forwarding_entries=[], forwarding_max_age_seconds=0
            )

    def test_expired_or_wrong_mac_lease_does_not_explain_change(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        for unmatched in (
            lease(ends_at="2026-10-21T12:00:59Z"),
            lease(mac="02:00:00:00:00:98"),
        ):
            with self.subTest(lease=unmatched):
                report = arp_consistency.review_lines(observations, leases=[unmatched])
                self.assertEqual(
                    report["findings"][0]["lease_status"], "unexplained_change"
                )
                self.assertEqual(report["lease_reconciliation"]["unexplained_changes"], 1)

    def test_rejects_ambiguous_and_inverted_leases(self):
        observations = [
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z", mac="02:00:00:00:00:99"),
        ]
        with self.assertRaisesRegex(arp_consistency.ObservationError, "overlapping DHCP leases"):
            arp_consistency.review_lines(observations, leases=[lease(), lease()])
        with self.assertRaisesRegex(arp_consistency.ObservationError, "ends_at must not precede"):
            arp_consistency.review_lines(
                observations,
                leases=[lease(starts_at="2026-10-21T13:00:00Z",
                              ends_at="2026-10-21T12:00:00Z")],
            )

    def test_same_mapping_and_different_interfaces_do_not_conflict(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:01:00Z"),
            observation("2026-10-21T12:01:30Z", mac="02:00:00:00:00:99", interface="lab1"),
        ])
        self.assertEqual(report["findings"], [])

    def test_change_after_window_is_not_reported(self):
        report = arp_consistency.review_lines([
            observation("2026-10-21T12:00:00Z"),
            observation("2026-10-21T12:06:00Z", mac="02:00:00:00:00:99"),
        ])
        self.assertEqual(report["findings"], [])

    def test_rejects_duplicate_fields_and_backward_time(self):
        duplicate = '{"timestamp":"2026-10-21T12:00:00Z","interface":"lab0","ip":"192.0.2.10","mac":"02:00:00:00:00:10","mac":"02:00:00:00:00:11"}'
        with self.assertRaisesRegex(arp_consistency.ObservationError, "duplicate JSON field"):
            arp_consistency.review_lines([duplicate])
        with self.assertRaisesRegex(arp_consistency.ObservationError, "must not move backward"):
            arp_consistency.review_lines([
                observation("2026-10-21T12:01:00Z"),
                observation("2026-10-21T12:00:00Z"),
            ])

    def test_enforces_window_and_record_bounds(self):
        with self.assertRaisesRegex(arp_consistency.ObservationError, "between 1 and 3600"):
            arp_consistency.review_lines([], window_seconds=0)
        repeated = observation("2026-10-21T12:00:00Z")
        with self.assertRaisesRegex(arp_consistency.ObservationError, "exceeds 10000 records"):
            arp_consistency.review_lines(repeated for _ in range(10_001))

    def test_rejects_ambiguous_addresses_and_unknown_fields(self):
        with self.assertRaisesRegex(arp_consistency.ObservationError, "canonical IPv4"):
            arp_consistency.review_lines([observation("2026-10-21T12:00:00Z", ip="192.0.2.010")])
        with self.assertRaisesRegex(arp_consistency.ObservationError, "unknown field"):
            arp_consistency.review_lines([
                '{"timestamp":"2026-10-21T12:00:00Z","interface":"lab0","ip":"192.0.2.10","mac":"02:00:00:00:00:10","note":"private"}'
            ])

    def test_cli_emits_no_report_for_invalid_input(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.jsonl"
            path.write_text("not json\n", encoding="utf-8")
            output, error = StringIO(), StringIO()
            with redirect_stdout(output), redirect_stderr(error):
                result = arp_consistency.main([str(path)])
        self.assertEqual(result, 2)
        self.assertEqual(output.getvalue(), "")
        self.assertIn("line 1: invalid JSON", error.getvalue())

    def test_fixture_runs_end_to_end(self):
        fixture = Path(__file__).resolve().parents[1] / "examples/arp-observations.jsonl"
        leases = fixture.with_name("dhcp-leases.jsonl")
        forwarding = fixture.with_name("switch-forwarding.jsonl")
        policy = fixture.with_name("expected-ports.jsonl")
        output = StringIO()
        with redirect_stdout(output):
            result = arp_consistency.main([
                str(fixture),
                "--leases", str(leases),
                "--forwarding-table", str(forwarding),
                "--port-policy", str(policy),
            ])
        report = json.loads(output.getvalue())
        self.assertEqual(result, 0)
        self.assertEqual(report["observation_count"], 3)
        self.assertEqual(report["finding_count"], 1)
        self.assertEqual(report["findings"][0]["lease_status"], "expected_reassignment")
        self.assertEqual(report["findings"][0]["forwarding_status"],
                         "current_mac_observed")
        self.assertEqual(report["findings"][0]["port_history_status"],
                         "port_move_observed")
        self.assertEqual(report["findings"][0]["previous_port"], "swp3")
        self.assertEqual(report["findings"][0]["current_port"], "swp7")
        self.assertEqual(report["findings"][0]["port_policy_status"],
                         "expected_port")


if __name__ == "__main__":
    unittest.main()
