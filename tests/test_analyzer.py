from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from analyzer import InputError, analyze_events, format_text, parse_events


ROOT = Path(__file__).resolve().parents[1]
BASE = datetime(2026, 9, 14, tzinfo=timezone.utc)


def record(seconds=0, **changes):
    value = {"timestamp": (BASE + timedelta(seconds=seconds)).isoformat(), "event": "authentication",
             "host": "test-lab", "user": "sample-user", "source_ip": "192.0.2.10", "outcome": "failure"}
    value.update(changes)
    return value


def events(*records):
    return parse_events(io.StringIO("\n".join(json.dumps(row) for row in records)))


def report(*records, **options):
    return analyze_events(events(*records), **options)


class ParsingTests(unittest.TestCase):
    def test_unsorted_records_retain_physical_line_numbers(self):
        parsed = events(record(20), record(0), record(10))
        self.assertEqual([event.line for event in parsed], [2, 3, 1])

    def test_timezones_and_ipv6_are_normalized(self):
        parsed = events(record(timestamp="2026-09-14T01:00:00+01:00", source_ip="2001:0db8:0000::1"), record())
        self.assertEqual(parsed[0].timestamp, parsed[1].timestamp)
        self.assertEqual(parsed[0].source_ip, "2001:db8::1")

    def test_invalid_fields_include_line_without_echoing_record(self):
        for field, value in [("timestamp", "2026-09-14T00:00:00"), ("timestamp", "not-a-date"),
                             ("timestamp", "2026-09-14"), ("source_ip", "999.1.1.1"),
                             ("source_ip", "fe80::1%eth0"), ("host", ""), ("user", 4),
                             ("user", "\x1b[31mprivate-secret"), ("outcome", "maybe"),
                             ("event", "network"), ("host", "x" * 257)]:
            with self.subTest(field=field, value=value):
                with self.assertRaises(InputError) as error:
                    parse_events(["\n", json.dumps(record(**{field: value}))])
                self.assertIn("line 2", str(error.exception))
                self.assertNotIn("private-secret", str(error.exception))

    def test_malformed_json_objects_duplicates_and_nonfinite_numbers(self):
        for text in ["{", "[]", "null", '{"host":"one","host":"two"}',
                     json.dumps(record())[:-1] + ',"extra":NaN}',
                     json.dumps(record())[:-1] + ',"extra":1e999}',
                     json.dumps(record())[:-1] + ',"extra":-1e999}',
                     json.dumps({"event": "authentication"})]:
            with self.subTest(text=text), self.assertRaises(InputError):
                parse_events([text])

    def test_blank_lines_are_allowed_and_evidence_uses_original_line_numbers(self):
        parsed = parse_events(["\n", json.dumps(record()), "   ", json.dumps(record(1))])
        self.assertEqual([row.line for row in parsed], [2, 4])


class RuleTests(unittest.TestCase):
    def test_window_near_datetime_min_does_not_underflow(self):
        result = report(record(timestamp="0001-01-01T00:00:00Z"),
                        record(timestamp="0001-01-01T00:05:00Z"),
                        record(timestamp="0001-01-01T00:05:01Z"), threshold=2)
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["evidence_lines"], [1, 2, 3])
        self.assertEqual(result["findings"][0]["first_seen"], "0001-01-01T00:00:00Z")

    def test_failure_threshold_and_inclusive_window_boundary(self):
        self.assertEqual(report(*[record(i) for i in range(4)])["finding_count"], 0)
        result = report(record(0), record(100), record(200), record(250), record(300))
        self.assertEqual(result["finding_count"], 1)
        self.assertEqual(result["findings"][0]["rule"], "repeated_failures")
        self.assertEqual(result["findings"][0]["evidence_lines"], [1, 2, 3, 4, 5])
        self.assertEqual(report(record(0), record(100), record(200), record(250), record(301))["finding_count"], 0)

    def test_overlapping_windows_merge_and_separate_bursts_do_not(self):
        result = report(*[record(i) for i in range(7)], *[record(1000 + i) for i in range(5)])
        self.assertEqual(result["finding_count"], 2)
        self.assertEqual([row["event_count"] for row in result["findings"]], [7, 5])
        self.assertEqual(result["findings"][0]["evidence_lines"], list(range(1, 8)))

    def test_spraying_counts_distinct_users(self):
        result = report(*[record(i, user=f"sample-{i}") for i in range(5)])
        self.assertEqual(result["finding_count"], 1)
        finding = result["findings"][0]
        self.assertEqual(finding["rule"], "possible_password_spray")
        self.assertEqual(len(finding["users"]), 5)
        self.assertIsNone(finding["user"])
        repeated = report(*[record(i, user=f"sample-{i % 2}") for i in range(6)])
        self.assertEqual(repeated["finding_count"], 0)

    def test_success_requires_prior_failures_for_the_same_account(self):
        result = report(*[record(i) for i in range(5)], record(5, outcome="success"))
        self.assertEqual([row["rule"] for row in result["findings"]], ["repeated_failures", "success_after_failures"])
        self.assertEqual(result["findings"][1]["event_count"], 6)
        self.assertEqual(result["findings"][1]["severity"], "high")
        self.assertEqual(report(record(0, outcome="success"), *[record(i + 1) for i in range(5)])["finding_count"], 1)
        self.assertEqual(report(*[record(i) for i in range(5)], record(500, outcome="success"))["finding_count"], 1)

    def test_grouping_does_not_merge_hosts_ips_or_accounts(self):
        for field in ("host", "source_ip", "user"):
            values = [f"value-{i}" for i in range(5)] if field != "source_ip" else [f"192.0.2.{i + 1}" for i in range(5)]
            result = report(*[record(i, **{field: value}) for i, value in enumerate(values)], spray_users=6)
            self.assertEqual(result["finding_count"], 0, field)
        result = report(*[record(i) for i in range(5)], record(6, user="different", outcome="success"))
        self.assertEqual(result["finding_count"], 1)

    def test_out_of_order_input_and_equivalent_timezones_produce_findings(self):
        rows = [record(i) for i in range(5)] + [record(10, outcome="success")]
        result = report(*reversed(rows))
        self.assertEqual(result["finding_count"], 2)
        self.assertEqual(result["findings"][1]["evidence_lines"], [1, 2, 3, 4, 5, 6])

    def test_benign_and_empty_logs_have_no_findings(self):
        self.assertEqual(report()["finding_count"], 0)
        self.assertEqual(report(record(0, outcome="success"), record(500), record(1000))["finding_count"], 0)

    def test_invalid_thresholds_are_rejected(self):
        for options in [{"threshold": 0}, {"window_seconds": -1}, {"spray_users": 0}, {"threshold": True}]:
            with self.assertRaises(ValueError):
                analyze_events([], **options)

    def test_synthetic_sample_and_output_are_stable(self):
        with (ROOT / "samples/authentication.jsonl").open(encoding="utf-8") as stream:
            parsed = parse_events(stream)
        result = analyze_events(parsed)
        self.assertEqual(result["event_count"], 12)
        self.assertEqual(result["finding_count"], 3)
        self.assertEqual(result, analyze_events(parsed))
        text = format_text(result)
        self.assertIn("not confirmed compromise", text)
        self.assertIn("Input lines: 2, 3, 4, 5, 6, 7", text)
        self.assertEqual(json.loads(json.dumps(result, allow_nan=False)), result)


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        environment = os.environ.copy()
        environment["PYTHONIOENCODING"] = "utf-8"
        return subprocess.run([sys.executable, str(ROOT / "analyzer.py"), *map(str, args)],
                              cwd=ROOT, env=environment, capture_output=True, text=True, encoding="utf-8", timeout=10)

    def test_sample_text_and_json(self):
        text = self.run_cli("samples/authentication.jsonl")
        structured = self.run_cli("samples/authentication.jsonl", "--format", "json")
        self.assertEqual(text.returncode, 0)
        self.assertEqual(structured.returncode, 0)
        self.assertEqual(json.loads(structured.stdout)["finding_count"], 3)
        self.assertIn("12 authentication events; 3 finding(s)", text.stdout)
        self.assertEqual(structured.stderr, "")

    def test_missing_file_and_invalid_cli_threshold(self):
        for args in [("missing-file.jsonl",), ("samples/authentication.jsonl", "--threshold", "0")]:
            result = self.run_cli(*args)
            self.assertEqual(result.returncode, 2)
            self.assertEqual(result.stdout, "")
            self.assertIn("error:", result.stderr)

    def test_malformed_file_does_not_emit_partial_report(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text(json.dumps(record()) + "\n{bad", encoding="utf-8")
            result = self.run_cli(path, "--format", "json")
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("line 2", result.stderr)

    def test_utf8_bom_and_unicode_names(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "events.jsonl"
            path.write_text(json.dumps(record(user="sample-\u00e9"), ensure_ascii=False), encoding="utf-8-sig")
            result = self.run_cli(path, "--threshold", "1", "--format", "json")
        self.assertEqual(result.returncode, 0)
        self.assertEqual(json.loads(result.stdout)["findings"][0]["user"], "sample-\u00e9")


if __name__ == "__main__":
    unittest.main()
