from __future__ import annotations

import json
import sys
import unittest
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT))

import failed_login_detector as detector  # noqa: E402


class ParserTests(unittest.TestCase):
    def test_parses_linux_failed_password(self) -> None:
        text = (
            "Sep 11 10:15:01 lab sshd[1200]: Failed password for invalid user "
            "admin from 203.0.113.42 port 50100 ssh2"
        )
        failures = detector.parse_linux_auth_log(text, 2026)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].username, "admin")
        self.assertEqual(failures[0].source, "203.0.113.42")

    def test_parses_modern_linux_ssh_failure_types(self) -> None:
        text = "\n".join(
            [
                "2026-09-11T14:22:01.458921+00:00 lab sshd[1]: Failed publickey for invalid user admin from 192.0.2.1 port 1 ssh2",
                "2026-09-11T14:22:02Z lab sshd[2]: Invalid user oracle from 192.0.2.1 port 2",
                "2026-09-11T14:22:03+00:00 lab sshd[3]: maximum authentication attempts exceeded for root from 192.0.2.1 port 3 ssh2",
            ]
        )
        failures = detector.parse_linux_auth_log(text, 2026)
        self.assertEqual(len(failures), 3)
        self.assertEqual(failures[0].reason, "ssh failed publickey")
        self.assertEqual(failures[1].username, "oracle")

    def test_parses_journalctl_space_timestamp_and_compact_offset(self) -> None:
        text = (
            "2026-09-11 14:22:01.123456-0400 lab sshd[1]: "
            "Failed password for root from 192.0.2.1 port 22 ssh2"
        )
        failures = detector.parse_linux_auth_log(text, 2026)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].timestamp.hour, 18)

    def test_legacy_linux_log_handles_new_year_rollover(self) -> None:
        text = "\n".join(
            [
                "Dec 31 23:59:59 lab sshd[1]: Failed password for root from 192.0.2.1 port 1 ssh2",
                "Jan  1 00:00:01 lab sshd[2]: Failed password for root from 192.0.2.1 port 2 ssh2",
            ]
        )
        failures = detector.parse_linux_auth_log(text, 2026)
        self.assertEqual(failures[0].timestamp.year, 2025)
        self.assertEqual(failures[1].timestamp.year, 2026)

    def test_parses_jsonl(self) -> None:
        text = json.dumps(
            {
                "timestamp": "2026-09-11T10:00:00Z",
                "username": "root",
                "source_ip": "192.0.2.15",
            }
        )
        failures = detector.parse_jsonl(text)
        self.assertEqual(failures[0].platform, "generic")
        self.assertEqual(failures[0].source, "192.0.2.15")

    def test_jsonl_normalizes_null_fields(self) -> None:
        text = json.dumps(
            {
                "timestamp": "2026-09-11T10:00:00Z",
                "username": None,
                "source": None,
            }
        )
        failure = detector.parse_jsonl(text)[0]
        self.assertEqual(failure.username, "unknown")
        self.assertEqual(failure.source, "unknown")

    def test_decodes_utf16_windows_export(self) -> None:
        xml = '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event" />'
        self.assertEqual(detector.decode_log_bytes(xml.encode("utf-16")), xml)

    def test_rejects_invalid_jsonl_with_line_number(self) -> None:
        with self.assertRaisesRegex(ValueError, "line 2"):
            detector.parse_jsonl('{"timestamp":"2026-01-01T00:00:00Z","username":"a"}\n{')

    def test_parses_windows_4625_xml(self) -> None:
        xml = """<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4625</EventID><TimeCreated SystemTime="2026-09-11T12:00:00Z"/></System>
  <EventData><Data Name="TargetUserName">administrator</Data><Data Name="IpAddress">198.51.100.7</Data><Data Name="SubStatus">0xC000006A</Data></EventData>
</Event>"""
        failures = detector.parse_windows_xml(xml)
        self.assertEqual(len(failures), 1)
        self.assertEqual(failures[0].event_id, "4625")
        self.assertEqual(failures[0].username, "administrator")
        self.assertEqual(failures[0].reason, "bad password")

    def test_parses_wrapped_windows_event_export(self) -> None:
        text = (PROJECT_ROOT / "sample-data" / "windows-4625.xml").read_text(
            encoding="utf-8"
        )
        failures = detector.parse_windows_xml(text)
        self.assertEqual(len(failures), 5)

    def test_parses_namespace_free_windows_fragments(self) -> None:
        event = """<Event><System><EventID>4625</EventID><TimeCreated SystemTime="2026-09-11T12:00:00Z"/></System><EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">192.0.2.1</Data></EventData></Event>"""
        failures = detector.parse_windows_xml(event + event)
        self.assertEqual(len(failures), 2)


class DetectionTests(unittest.TestCase):
    def make_failures(self, count: int, spacing_minutes: int = 1):
        start = datetime(2026, 9, 11, tzinfo=timezone.utc)
        return [
            detector.LoginFailure(
                timestamp=start + timedelta(minutes=index * spacing_minutes),
                username="admin",
                source="203.0.113.42",
                platform="test",
                event_id="test",
            )
            for index in range(count)
        ]

    def test_alerts_when_threshold_is_reached(self) -> None:
        alerts = detector.detect_failures(
            self.make_failures(5), threshold=5, window_minutes=10
        )
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failure_count, 5)

    def test_sustained_attack_keeps_cumulative_count_and_first_seen(self) -> None:
        failures = self.make_failures(12)
        alerts = detector.detect_failures(failures, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].failure_count, 12)
        self.assertEqual(alerts[0].first_seen, failures[0].timestamp)
        self.assertEqual(alerts[0].severity, "high")

    def test_does_not_alert_outside_window(self) -> None:
        alerts = detector.detect_failures(
            self.make_failures(5, spacing_minutes=11), threshold=5, window_minutes=10
        )
        self.assertEqual(alerts, [])

    def test_source_grouping_detects_password_spray(self) -> None:
        failures = self.make_failures(5)
        failures = [
            detector.LoginFailure(
                timestamp=item.timestamp,
                username=f"user{index}",
                source=item.source,
                platform=item.platform,
                event_id=item.event_id,
            )
            for index, item in enumerate(failures)
        ]
        alerts = detector.detect_failures(failures, threshold=5, group_by="source")
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].classification, "password-spray")
        self.assertEqual(alerts[0].unique_usernames, 5)

    def test_source_user_grouping_separates_accounts(self) -> None:
        failures = self.make_failures(5)
        failures[0] = detector.LoginFailure(
            timestamp=failures[0].timestamp,
            username="different-user",
            source=failures[0].source,
            platform="test",
            event_id="test",
        )
        alerts = detector.detect_failures(
            failures, threshold=5, group_by="source-user"
        )
        self.assertEqual(alerts, [])

    def test_demo_produces_one_alert(self) -> None:
        alerts = detector.detect_failures(detector.demo_failures())
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].source, "203.0.113.42")

    def test_filters_cidr_and_username_exclusions(self) -> None:
        failures = self.make_failures(2)
        failures.append(
            detector.LoginFailure(
                timestamp=failures[-1].timestamp,
                username="service-account",
                source="198.51.100.8",
                platform="test",
                event_id="test",
            )
        )
        included, excluded_count = detector.filter_failures(
            failures,
            excluded_sources=["203.0.113.0/24"],
            excluded_users=["SERVICE-ACCOUNT"],
        )
        self.assertEqual(included, [])
        self.assertEqual(excluded_count, 3)

    def test_rejects_invalid_excluded_cidr(self) -> None:
        with self.assertRaisesRegex(ValueError, "invalid excluded IP"):
            detector.filter_failures(
                self.make_failures(1),
                excluded_sources=["192.0.2.0/99"],
                excluded_users=[],
            )


class CommandLineTests(unittest.TestCase):
    def test_demo_json_is_machine_readable(self) -> None:
        output = StringIO()
        with redirect_stdout(output):
            exit_code = detector.main(["--format", "demo", "--json"])
        report = json.loads(output.getvalue())
        self.assertEqual(exit_code, 0)
        self.assertEqual(report["events_analyzed"], 10)
        self.assertEqual(report["alerts_generated"], 1)

    def test_fail_on_alert_returns_one(self) -> None:
        with redirect_stdout(StringIO()):
            exit_code = detector.main(["--format", "demo", "--fail-on-alert"])
        self.assertEqual(exit_code, 1)


if __name__ == "__main__":
    unittest.main()
