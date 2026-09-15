"""Read local JSONL authentication events and report explainable login patterns."""

import argparse
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import ipaddress
import json
import math
from pathlib import Path
import sys


class InputError(ValueError):
    """An invalid input record, identified without echoing its contents."""


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    host: str
    user: str
    source_ip: str
    outcome: str
    line: int


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-finite JSON number")


def _finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite JSON number")
    return number


def parse_events(lines):
    """Validate all records before analysis; retain physical input line numbers."""
    events = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line, object_pairs_hook=_unique_object, parse_constant=_reject_constant,
                                parse_float=_finite_float)
        except (ValueError, RecursionError) as error:
            raise InputError(f"line {number}: invalid JSON ({type(error).__name__})") from error
        if not isinstance(record, dict):
            raise InputError(f"line {number}: expected a JSON object")
        for field in ("timestamp", "event", "host", "user", "source_ip", "outcome"):
            value = record.get(field)
            if not isinstance(value, str) or not value.strip() or len(value) > 256 or any(not c.isprintable() for c in value):
                raise InputError(f"line {number}: {field} must be nonempty printable text, at most 256 characters")
        if record["event"] != "authentication":
            raise InputError(f"line {number}: event must be authentication")
        if record["outcome"] not in ("success", "failure"):
            raise InputError(f"line {number}: outcome must be success or failure")
        try:
            timestamp = datetime.fromisoformat(record["timestamp"].replace("Z", "+00:00"))
            if timestamp.utcoffset() is None or "T" not in record["timestamp"]:
                raise ValueError("timestamp needs a timezone and time")
            timestamp = timestamp.astimezone(timezone.utc)
        except (ValueError, OverflowError) as error:
            raise InputError(f"line {number}: timestamp must include a date, time and timezone") from error
        try:
            address = ipaddress.ip_address(record["source_ip"])
            if getattr(address, "scope_id", None):
                raise ValueError("scoped addresses are not supported")
        except ValueError as error:
            raise InputError(f"line {number}: source_ip must be an IPv4 or IPv6 address") from error
        events.append(Event(timestamp, record["host"], record["user"], str(address), record["outcome"], number))
    return sorted(events, key=lambda event: (event.timestamp, event.line))


def _iso(timestamp):
    return timestamp.isoformat().replace("+00:00", "Z")


def analyze_events(events, threshold=5, window_seconds=300, spray_users=5):
    """Find overlapping sliding-window incidents; a boundary exactly W seconds old counts."""
    if any(not isinstance(value, int) or isinstance(value, bool) or value < 1 for value in (threshold, window_seconds, spray_users)):
        raise ValueError("thresholds and window seconds must be positive integers")
    events = sorted(events, key=lambda event: (event.timestamp, event.line))
    failures, sources = defaultdict(deque), defaultdict(deque)
    findings, active = [], {}
    window = timedelta(seconds=window_seconds)

    def prune(queue, timestamp):
        while queue and timestamp - queue[0].timestamp > window:
            queue.popleft()

    def emit(rule, key, evidence, severity):
        first, last = evidence[0].timestamp, evidence[-1].timestamp
        incident = active.get((rule, key))
        if incident is None or first > incident["last"]:
            incident = {"rule": rule, "severity": severity, "host": key[0], "source_ip": key[1],
                        "user": key[2] if len(key) == 3 else None, "first": first, "last": last,
                        "lines": set(), "users": set()}
            active[(rule, key)] = incident
            findings.append(incident)
        incident["last"] = last
        incident["lines"].update(event.line for event in evidence)
        incident["users"].update(event.user for event in evidence)

    for event in events:
        key = (event.host, event.source_ip, event.user)
        source = key[:2]
        account_queue, source_queue = failures[key], sources[source]
        prune(account_queue, event.timestamp)
        prune(source_queue, event.timestamp)
        if event.outcome == "failure":
            account_queue.append(event)
            source_queue.append(event)
            if len(account_queue) >= threshold:
                emit("repeated_failures", key, list(account_queue), "medium")
            if len({item.user for item in source_queue}) >= spray_users:
                emit("possible_password_spray", source, list(source_queue), "medium")
        elif len(account_queue) >= threshold:
            emit("success_after_failures", key, [*account_queue, event], "high")

    findings.sort(key=lambda row: (row["first"], row["rule"], row["host"], row["source_ip"], row["user"] or ""))
    rows = [{"rule": row["rule"], "severity": row["severity"], "host": row["host"], "source_ip": row["source_ip"],
             "user": row["user"], "users": sorted(row["users"]), "first_seen": _iso(row["first"]), "last_seen": _iso(row["last"]),
             "event_count": len(row["lines"]), "evidence_lines": sorted(row["lines"])} for row in findings]
    return {"event_count": len(events), "finding_count": len(rows),
            "settings": {"threshold": threshold, "window_seconds": window_seconds, "spray_users": spray_users}, "findings": rows}


def format_text(report):
    lines = [f"Analyzed {report['event_count']} authentication events; {report['finding_count']} finding(s).",
             "Findings describe patterns, not confirmed compromise."]
    for finding in report["findings"]:
        user = finding["user"] if finding["user"] is not None else ", ".join(finding["users"])
        lines.extend(["", f"[{finding['severity'].upper()}] {finding['rule']}",
                      f"  Host: {finding['host']} | Source: {finding['source_ip']} | User(s): {user}",
                      f"  {finding['first_seen']} to {finding['last_seen']} | {finding['event_count']} evidence events",
                      "  Input lines: " + ", ".join(map(str, finding["evidence_lines"]))])
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="explicit local JSONL file to analyze")
    parser.add_argument("--format", choices=("text", "json"), default="text")
    parser.add_argument("--threshold", type=int, default=5, help="account failures required (default: 5)")
    parser.add_argument("--window-seconds", type=int, default=300, help="inclusive sliding window (default: 300)")
    parser.add_argument("--spray-users", type=int, default=5, help="distinct failed accounts required (default: 5)")
    args = parser.parse_args(argv)
    try:
        with args.input.open(encoding="utf-8-sig") as stream:
            events = parse_events(stream)
        report = analyze_events(events, args.threshold, args.window_seconds, args.spray_users)
    except (InputError, OSError, UnicodeError, ValueError, OverflowError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 2
    print(json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) if args.format == "json" else format_text(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
