"""Text-log imports must feed the same normalizer and correlation rules."""

import json
import sys
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr
from io import StringIO
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from event_normalizer.zeek_tsv import import_conn_log, main
from event_normalizer.correlation_cli import correlate_jsonl

FIXTURE = Path(__file__).parent / "fixtures/repeated_attempts.log"


class ZeekTextTests(unittest.TestCase):
    def setUp(self):
        self.text = FIXTURE.read_text()

    def test_fixture_normalizes_and_correlates(self):
        events = import_conn_log(StringIO(self.text))
        self.assertEqual([e["_zeek_tsv_line"] for e in events], [8, 9, 10, 11])
        report = correlate_jsonl(StringIO("\n".join(map(json.dumps, events))))
        self.assertEqual((report["events_read"], report["finding_count"]), (4, 1))
        self.assertEqual(report["findings"][0]["attempt_count"], 4)

    def test_declared_order_extra_columns_and_escaped_text(self):
        rows = self.text.splitlines()
        rows[5] += "\tservice"
        rows[6] += "\tstring"
        for index in range(7, 11):
            rows[index] += "\thttp"
        rows[7] = rows[7].replace("fixture-1", r"\x66ixture-1")
        result = import_conn_log(StringIO("\n".join(rows)))
        self.assertEqual(result[0]["uid"], "fixture-1")
        self.assertNotIn("service", result[0])
        self.assertEqual(result[0]["id.resp_p"], 22)

    def test_optional_unset_history_does_not_invent_attempts(self):
        text = self.text.replace("\tS0\tS", "\t-\t-")
        rows = import_conn_log(StringIO(text))
        self.assertIsNone(rows[0]["history"])
        self.assertEqual(correlate_jsonl(StringIO("\n".join(map(json.dumps, rows))))["finding_count"], 0)

    def test_column_order_is_selected_from_headers(self):
        rows = self.text.splitlines()
        for index in (5, 6):
            columns = rows[index].split("\t")
            rows[index] = "\t".join([columns[0], *reversed(columns[1:])])
        for index in range(7, 11):
            rows[index] = "\t".join(reversed(rows[index].split("\t")))
        self.assertEqual(import_conn_log(StringIO("\n".join(rows))), import_conn_log(StringIO(self.text)))

    def test_invalid_headers_columns_and_values_fail(self):
        for text in (self.text.replace(r"\x09", r"\x2c"),
                     self.text.replace("#path\tconn", "#path\thttp"),
                     self.text.replace("port", "string", 1),
                     self.text.replace("#types", "#fields"),
                     self.text.replace("\t51000\t", "\t1.5\t"),
                     self.text.replace("192.0.2.10", "999.0.0.1"),
                     self.text.replace("1789408800", "nan"),
                     self.text.replace("fixture-1", r"bad\x0aUID"),
                     self.text.replace("fixture-1", r"bad\qUID"),
                     self.text.replace("\tfixture-1", ""),
                     self.text + "late-data\n", ""):
            with self.subTest(text=text[:40]), self.assertRaises(ValueError):
                import_conn_log(StringIO(text))

    def test_line_batch_limits(self):
        for setting, value in (("MAX_LINE_CHARS", 10), ("MAX_LINES", 3), ("MAX_EVENTS", 2), ("MAX_INPUT_CHARS", 10)):
            with patch(f"event_normalizer.zeek_tsv.{setting}", value), self.assertRaises(ValueError):
                import_conn_log(StringIO(self.text))

    def test_empty_log_still_requires_a_valid_declared_schema(self):
        header = "\n".join(self.text.splitlines()[:7]) + "\n"
        self.assertEqual(import_conn_log(StringIO(header)), [])
        with self.assertRaises(ValueError):
            import_conn_log(StringIO(header.replace("port", "string", 1)))
        with self.assertRaises(ValueError):
            import_conn_log(StringIO(self.text.replace("fixture-1", "x" * 257)))

    def test_cli_and_malformed_tail_never_emit_partial_success(self):
        output = StringIO()
        with redirect_stdout(output):
            self.assertEqual(main([str(FIXTURE)]), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 4)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bad.log"
            path.write_text(self.text.replace("1789408830", "invalid-time"))
            output = StringIO()
            with redirect_stdout(output), redirect_stderr(StringIO()):
                self.assertEqual(main([str(path)]), 2)
            self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
