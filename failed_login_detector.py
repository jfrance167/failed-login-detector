#!/usr/bin/env python3
"""Detect repeated authentication failures in Linux and Windows logs."""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
import subprocess
import sys
from defusedxml import ElementTree as ET
from collections import defaultdict, deque
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterable, Sequence


DEFAULT_THRESHOLD = 5
DEFAULT_WINDOW_MINUTES = 10
DEFAULT_MAX_WINDOWS_EVENTS = 1_000
WINDOWS_FAILED_LOGIN_EVENT_ID = "4625"
WINDOWS_SUBSTATUS_REASONS = {
    "0xc0000064": "unknown username",
    "0xc000006a": "bad password",
    "0xc000006f": "logon outside authorized hours",
    "0xc0000070": "unauthorized workstation",
    "0xc0000072": "disabled account",
    "0xc0000234": "locked account",
}

LINUX_LOG_LINE = re.compile(
    r"^(?P<timestamp>"
    r"(?:\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))"
    r"|(?:[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r")\s+\S+\s+\S+(?:\[\d+\])?:\s+(?P<message>.*)$"
)
LINUX_FAILURE_PATTERNS = (
    (
        re.compile(
            r"Failed (?P<method>password|publickey) for (?:invalid user )?"
            r"(?P<username>\S+) from (?P<source>\S+)"
        ),
        "ssh failed credential",
    ),
    (
        re.compile(r"Invalid user (?P<username>\S+) from (?P<source>\S+)"),
        "ssh invalid user",
    ),
    (
        re.compile(
            r"maximum authentication attempts exceeded for (?:invalid user )?"
            r"(?P<username>\S+) from (?P<source>\S+)"
        ),
        "ssh maximum attempts exceeded",
    ),
    (
        re.compile(
            r"authentication failure;.*rhost=(?P<source>\S*).*"
            r"user=(?P<username>\S+)"
        ),
        "pam authentication failure",
    ),
)


@dataclass(frozen=True)
class LoginFailure:
    timestamp: datetime
    username: str
    source: str
    platform: str
    event_id: str
    reason: str | None = None


@dataclass
class Alert:
    group: str
    username: str
    source: str
    failure_count: int
    first_seen: datetime
    last_seen: datetime
    window_minutes: int
    severity: str
    classification: str
    unique_usernames: int
    unique_sources: int
    reasons: list[str]

    def to_dict(self) -> dict[str, object]:
        document = asdict(self)
        document["first_seen"] = self.first_seen.isoformat()
        document["last_seen"] = self.last_seen.isoformat()
        return document


def positive_int(value: str) -> int:
    try:
        number = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("value must be a whole number") from exc
    if number < 1:
        raise argparse.ArgumentTypeError("value must be at least 1")
    return number


def parse_timestamp(value: str) -> datetime:
    normalized = value.strip()
    if normalized.endswith("Z"):
        normalized = normalized[:-1] + "+00:00"
    normalized = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", normalized)
    try:
        timestamp = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise ValueError(f"invalid ISO-8601 timestamp: {value!r}") from exc
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=timezone.utc)
    return timestamp.astimezone(timezone.utc)


def normalized_field(value: object, default: str) -> str:
    if value is None:
        return default
    text = str(value).strip()
    return text if text and text != "-" else default


def decode_log_bytes(data: bytes) -> str:
    """Decode UTF-8 logs and common UTF-16 Windows XML exports."""
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        return data.decode("utf-16")
    if data.startswith(b"\xef\xbb\xbf"):
        return data.decode("utf-8-sig")
    if data.startswith(b"<\x00"):
        return data.decode("utf-16-le")
    if data.startswith(b"\x00<"):
        return data.decode("utf-16-be")
    return data.decode("utf-8", errors="replace")


def parse_jsonl(text: str) -> list[LoginFailure]:
    failures: list[LoginFailure] = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        if not line.strip():
            continue
        try:
            item = json.loads(line)
            failures.append(
                LoginFailure(
                    timestamp=parse_timestamp(str(item["timestamp"])),
                    username=normalized_field(item["username"], "unknown"),
                    source=normalized_field(
                        item.get("source", item.get("source_ip")), "unknown"
                    ),
                    platform=normalized_field(item.get("platform"), "generic"),
                    event_id=normalized_field(item.get("event_id"), "failed-login"),
                    reason=(str(item["reason"]) if item.get("reason") else None),
                )
            )
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"invalid JSONL record on line {line_number}: {exc}") from exc
    return failures


def parse_linux_auth_log(text: str, year: int) -> list[LoginFailure]:
    records: list[tuple[str, re.Match[str], str]] = []
    for line in text.splitlines():
        line_match = LINUX_LOG_LINE.search(line)
        if not line_match:
            continue
        for pattern, base_reason in LINUX_FAILURE_PATTERNS:
            failure_match = pattern.search(line_match.group("message"))
            if failure_match:
                reason = base_reason
                if failure_match.groupdict().get("method"):
                    reason = f"ssh failed {failure_match.group('method')}"
                records.append((line_match.group("timestamp"), failure_match, reason))
                break

    legacy_months = [
        datetime.strptime(f"2000 {value}", "%Y %b %d %H:%M:%S").month
        for value, _, _ in records
        if not value[0].isdigit()
    ]
    crosses_year = any(
        previous >= 11 and current <= 2
        for previous, current in zip(legacy_months, legacy_months[1:])
    )
    current_year = year - 1 if crosses_year else year
    previous_legacy_month: int | None = None
    failures: list[LoginFailure] = []

    for timestamp_text, match, reason in records:
        if timestamp_text[0].isdigit():
            timestamp = parse_timestamp(timestamp_text)
        else:
            partial = datetime.strptime(
                f"2000 {timestamp_text}", "%Y %b %d %H:%M:%S"
            )
            if (
                previous_legacy_month is not None
                and previous_legacy_month >= 11
                and partial.month <= 2
            ):
                current_year += 1
            previous_legacy_month = partial.month
            timestamp = partial.replace(year=current_year, tzinfo=timezone.utc)

        failures.append(
            LoginFailure(
                timestamp=timestamp,
                username=match.group("username") or "unknown",
                source=match.group("source") or "local",
                platform="linux",
                event_id="sshd-auth-failure",
                reason=reason,
            )
        )
    return failures


def _windows_event_fragments(text: str) -> list[str]:
    return re.findall(r"<Event\b.*?</Event>", text, flags=re.DOTALL)


def parse_windows_xml(text: str) -> list[LoginFailure]:
    failures: list[LoginFailure] = []
    roots: list[ET.Element] = []
    if not text.strip():
        return failures

    try:
        document = ET.fromstring(text)
        if document.tag.rsplit("}", 1)[-1] == "Event":
            roots = [document]
        else:
            roots = [
                node
                for node in document.iter()
                if node.tag.rsplit("}", 1)[-1] == "Event"
            ]
    except ET.ParseError:
        for index, fragment in enumerate(_windows_event_fragments(text), start=1):
            try:
                roots.append(ET.fromstring(fragment))
            except ET.ParseError as exc:
                raise ValueError(
                    f"invalid Windows event XML near event {index}: {exc}"
                ) from exc

    if not roots:
        raise ValueError("input did not contain any Windows Event XML records")

    def child(parent: ET.Element | None, name: str) -> ET.Element | None:
        if parent is None:
            return None
        return next(
            (node for node in parent if node.tag.rsplit("}", 1)[-1] == name),
            None,
        )

    for root in roots:
        system = child(root, "System")
        event_id_node = child(system, "EventID")
        event_id = event_id_node.text if event_id_node is not None else None
        if event_id != WINDOWS_FAILED_LOGIN_EVENT_ID:
            continue

        created = child(system, "TimeCreated")
        if created is None or not created.get("SystemTime"):
            continue
        event_data = child(root, "EventData")
        fields = {
            node.get("Name", ""): node.text or ""
            for node in (event_data if event_data is not None else [])
            if node.tag.rsplit("}", 1)[-1] == "Data"
        }
        username = normalized_field(fields.get("TargetUserName"), "unknown")
        source = normalized_field(
            fields.get("IpAddress") or fields.get("WorkstationName"), "local"
        )
        substatus = fields.get("SubStatus", "").lower()
        reason = WINDOWS_SUBSTATUS_REASONS.get(substatus)
        if reason is None and substatus and substatus != "0x0":
            reason = f"Windows substatus {substatus}"
        failures.append(
            LoginFailure(
                timestamp=parse_timestamp(created.get("SystemTime", "")),
                username=username,
                source=source,
                platform="windows",
                event_id=WINDOWS_FAILED_LOGIN_EVENT_ID,
                reason=reason,
            )
        )
    return failures


def read_windows_security_log(max_events: int) -> str:
    if sys.platform != "win32":
        raise RuntimeError("live Windows event collection is available only on Windows")
    command = [
        "wevtutil",
        "qe",
        "Security",
        f"/q:*[System[(EventID={WINDOWS_FAILED_LOGIN_EVENT_ID})]]",
        "/f:xml",
        "/rd:true",
        f"/c:{max_events}",
    ]
    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        message = result.stderr.strip() or result.stdout.strip() or "unknown error"
        raise RuntimeError(f"could not read the Windows Security log: {message}")
    return result.stdout


def group_key(failure: LoginFailure, group_by: str) -> tuple[str, ...]:
    if group_by == "source":
        return (failure.source,)
    if group_by == "username":
        return (failure.username,)
    return (failure.source, failure.username)


def group_label(key: tuple[str, ...], group_by: str) -> str:
    if group_by == "source-user":
        return f"source={key[0]}, username={key[1]}"
    return f"{group_by}={key[0]}"


def classify_attack(unique_usernames: int, unique_sources: int) -> str:
    if unique_usernames > 1:
        return "password-spray"
    if unique_sources > 1:
        return "distributed-account-attack"
    return "brute-force"


def filter_failures(
    failures: Iterable[LoginFailure],
    excluded_sources: Sequence[str],
    excluded_users: Sequence[str],
) -> tuple[list[LoginFailure], int]:
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    source_names: set[str] = set()
    for value in excluded_sources:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            if "/" in value:
                raise ValueError(f"invalid excluded IP or CIDR: {value!r}") from exc
            source_names.add(value.casefold())

    user_names = {value.casefold() for value in excluded_users}
    included: list[LoginFailure] = []
    excluded_count = 0
    for failure in failures:
        source_excluded = failure.source.casefold() in source_names
        try:
            address = ipaddress.ip_address(failure.source)
        except ValueError:
            address = None
        if address is not None:
            source_excluded = source_excluded or any(
                address.version == network.version and address in network
                for network in networks
            )

        if source_excluded or failure.username.casefold() in user_names:
            excluded_count += 1
        else:
            included.append(failure)
    return included, excluded_count


def detect_failures(
    failures: Iterable[LoginFailure],
    threshold: int = DEFAULT_THRESHOLD,
    window_minutes: int = DEFAULT_WINDOW_MINUTES,
    group_by: str = "source",
) -> list[Alert]:
    """Detect threshold crossings using a per-group sliding time window."""
    if threshold < 1 or window_minutes < 1:
        raise ValueError("threshold and window_minutes must be at least 1")
    if group_by not in {"source", "username", "source-user"}:
        raise ValueError(f"unsupported grouping: {group_by}")

    window = timedelta(minutes=window_minutes)
    queues: dict[tuple[str, ...], deque[LoginFailure]] = defaultdict(deque)
    active_alerts: dict[tuple[str, ...], Alert] = {}
    active_users: dict[tuple[str, ...], set[str]] = {}
    active_sources: dict[tuple[str, ...], set[str]] = {}
    active_reasons: dict[tuple[str, ...], set[str]] = {}
    alerts: list[Alert] = []

    for failure in sorted(failures, key=lambda item: item.timestamp):
        key = group_key(failure, group_by)
        recent = queues[key]
        cutoff = failure.timestamp - window
        while recent and recent[0].timestamp < cutoff:
            recent.popleft()

        if key in active_alerts and len(recent) < threshold:
            active_alerts.pop(key, None)
            active_users.pop(key, None)
            active_sources.pop(key, None)
            active_reasons.pop(key, None)

        recent.append(failure)
        if len(recent) < threshold:
            continue

        if key not in active_alerts:
            usernames = {item.username for item in recent}
            sources = {item.source for item in recent}
            reasons = {item.reason for item in recent if item.reason}
            alert = Alert(
                group=group_label(key, group_by),
                username=(failure.username if group_by != "source" else "multiple/observed"),
                source=(failure.source if group_by != "username" else "multiple/observed"),
                failure_count=len(recent),
                first_seen=recent[0].timestamp,
                last_seen=failure.timestamp,
                window_minutes=window_minutes,
                severity="high" if len(recent) >= threshold * 2 else "medium",
                classification=classify_attack(len(usernames), len(sources)),
                unique_usernames=len(usernames),
                unique_sources=len(sources),
                reasons=sorted(reasons),
            )
            alerts.append(alert)
            active_alerts[key] = alert
            active_users[key] = usernames
            active_sources[key] = sources
            active_reasons[key] = reasons
        else:
            alert = active_alerts[key]
            active_users[key].add(failure.username)
            active_sources[key].add(failure.source)
            if failure.reason:
                active_reasons[key].add(failure.reason)
            alert.failure_count += 1
            alert.last_seen = failure.timestamp
            alert.severity = (
                "high" if alert.failure_count >= threshold * 2 else "medium"
            )
            alert.unique_usernames = len(active_users[key])
            alert.unique_sources = len(active_sources[key])
            alert.classification = classify_attack(
                alert.unique_usernames, alert.unique_sources
            )
            alert.reasons = sorted(active_reasons[key])

    return alerts


def demo_failures() -> list[LoginFailure]:
    start = datetime(2026, 9, 11, 14, 0, tzinfo=timezone.utc)
    failures = [
        LoginFailure(
            timestamp=start + timedelta(seconds=45 * offset),
            username="admin" if offset % 2 == 0 else "root",
            source="203.0.113.42",
            platform="demo",
            event_id="demo-failure",
        )
        for offset in range(7)
    ]
    failures.extend(
        [
            LoginFailure(
                timestamp=start + timedelta(minutes=offset * 20),
                username="student",
                source="192.0.2.25",
                platform="demo",
                event_id="demo-failure",
            )
            for offset in range(3)
        ]
    )
    return failures


def infer_format(path: Path) -> str:
    if path.suffix.lower() in {".jsonl", ".json"}:
        return "jsonl"
    if path.suffix.lower() in {".xml", ".evtx.xml"}:
        return "windows-xml"
    return "linux"


def load_failures(args: argparse.Namespace) -> list[LoginFailure]:
    if args.format == "demo":
        return demo_failures()
    if args.format == "windows-live":
        return parse_windows_xml(read_windows_security_log(args.max_events))
    if args.input is None:
        raise ValueError("an input file is required unless --format is demo or windows-live")

    path = Path(args.input)
    try:
        text = decode_log_bytes(path.read_bytes())
    except OSError as exc:
        raise ValueError(f"could not read {path}: {exc}") from exc

    selected_format = infer_format(path) if args.format == "auto" else args.format
    if selected_format == "jsonl":
        return parse_jsonl(text)
    if selected_format == "windows-xml":
        return parse_windows_xml(text)
    return parse_linux_auth_log(text, args.year)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detect repeated failed logins in authorized system logs."
    )
    parser.add_argument("input", nargs="?", help="authentication log or exported XML")
    parser.add_argument(
        "--format",
        choices=("auto", "linux", "jsonl", "windows-xml", "windows-live", "demo"),
        default="auto",
        help="input type (default: infer from the file name)",
    )
    parser.add_argument(
        "--threshold",
        type=positive_int,
        default=DEFAULT_THRESHOLD,
        help=f"failures needed for an alert (default: {DEFAULT_THRESHOLD})",
    )
    parser.add_argument(
        "--window",
        type=positive_int,
        default=DEFAULT_WINDOW_MINUTES,
        help=f"sliding window in minutes (default: {DEFAULT_WINDOW_MINUTES})",
    )
    parser.add_argument(
        "--group-by",
        choices=("source", "username", "source-user"),
        default="source",
        help="correlation key (default: source)",
    )
    parser.add_argument(
        "--year",
        type=positive_int,
        default=datetime.now().year,
        help="year for Linux syslog records that omit it",
    )
    parser.add_argument(
        "--max-events",
        type=positive_int,
        default=DEFAULT_MAX_WINDOWS_EVENTS,
        help="maximum live Windows 4625 events to read",
    )
    parser.add_argument(
        "--exclude-ip",
        action="append",
        default=[],
        metavar="IP_OR_CIDR",
        help="exclude a source address or CIDR (repeatable)",
    )
    parser.add_argument(
        "--exclude-user",
        action="append",
        default=[],
        metavar="USERNAME",
        help="exclude an exact username, case-insensitively (repeatable)",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON output")
    parser.add_argument(
        "--fail-on-alert",
        action="store_true",
        help="return exit code 1 when alerts are found",
    )
    return parser


def print_text_report(
    loaded_count: int,
    failures: list[LoginFailure],
    excluded_count: int,
    alerts: list[Alert],
) -> None:
    print("Failed Login Detector")
    print(f"Failed events loaded:   {loaded_count}")
    print(f"Failed events analyzed: {len(failures)}")
    print(f"Events excluded:        {excluded_count}")
    print(f"Alerts generated:       {len(alerts)}")
    print("-" * 72)
    for alert in alerts:
        print(
            f"[{alert.severity.upper()}] {alert.classification} | {alert.group}"
        )
        print(
            f"  {alert.failure_count} failures from {alert.first_seen.isoformat()} "
            f"to {alert.last_seen.isoformat()}"
        )
        print(
            f"  {alert.unique_usernames} unique user(s), "
            f"{alert.unique_sources} unique source(s)"
        )
        if alert.reasons:
            print(f"  Reasons: {', '.join(alert.reasons)}")
    if not alerts:
        print("No threshold crossings detected.")


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        loaded_failures = load_failures(args)
        failures, excluded_count = filter_failures(
            loaded_failures,
            excluded_sources=args.exclude_ip,
            excluded_users=args.exclude_user,
        )
        alerts = detect_failures(
            failures,
            threshold=args.threshold,
            window_minutes=args.window,
            group_by=args.group_by,
        )
    except (RuntimeError, ValueError) as exc:
        if args.json:
            print(json.dumps({"error": str(exc)}))
        else:
            print(f"Error: {exc}", file=sys.stderr)
        return 2

    if args.json:
        print(
            json.dumps(
                {
                    "events_loaded": len(loaded_failures),
                    "events_analyzed": len(failures),
                    "events_excluded": excluded_count,
                    "alerts_generated": len(alerts),
                    "alerts": [alert.to_dict() for alert in alerts],
                },
                indent=2,
            )
        )
    else:
        print_text_report(len(loaded_failures), failures, excluded_count, alerts)
    return 1 if alerts and args.fail_on_alert else 0


if __name__ == "__main__":
    raise SystemExit(main())