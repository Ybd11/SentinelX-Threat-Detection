"""Simple, explainable authentication-log analyzer for defensive monitoring."""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
import json
import re
from typing import Iterable

# Expected format:
# 2026-11-24T09:15:00Z FAILED_LOGIN user=alice ip=203.0.113.10
LOG_PATTERN = re.compile(
    r"^(?P<timestamp>\S+)\s+(?P<event>FAILED_LOGIN|SUCCESS_LOGIN)\s+"
    r"user=(?P<user>\S+)\s+ip=(?P<ip>\S+)$"
)

@dataclass
class Finding:
    severity: str
    category: str
    source_ip: str
    description: str
    evidence_count: int

    def to_dict(self):
        return asdict(self)

def parse_log_lines(lines: Iterable[str]):
    """Parse supported log lines; malformed lines are skipped and counted."""
    events, malformed = [], 0
    for line_number, raw in enumerate(lines, start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = LOG_PATTERN.match(line)
        if not match:
            malformed += 1
            continue
        item = match.groupdict()
        try:
            # Accept ISO timestamps, including the trailing Z.
            datetime.fromisoformat(item["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            malformed += 1
            continue
        events.append(item)
    return events, malformed

def analyze_events(events, threshold=5):
    """Flag IPs with at least threshold failed logins.

    This is a deliberately transparent heuristic, not a production IDS.
    """
    failed_by_ip = defaultdict(list)
    users_by_ip = defaultdict(set)
    for event in events:
        users_by_ip[event["ip"]].add(event["user"])
        if event["event"] == "FAILED_LOGIN":
            failed_by_ip[event["ip"]].append(event)

    findings = []
    for ip, failures in sorted(failed_by_ip.items()):
        if len(failures) >= threshold:
            severity = "HIGH" if len(failures) >= threshold * 2 else "MEDIUM"
            findings.append(Finding(
                severity=severity,
                category="Possible brute-force activity",
                source_ip=ip,
                description=(
                    f"{len(failures)} failed login attempts observed across "
                    f"{len(users_by_ip[ip])} account(s). Review authentication "
                    "logs and apply your organisation's incident process."
                ),
                evidence_count=len(failures),
            ))
    return findings

def analyze_file(path: str | Path, threshold=5):
    path = Path(path)
    with path.open("r", encoding="utf-8") as handle:
        events, malformed = parse_log_lines(handle)
    findings = analyze_events(events, threshold=threshold)
    return {
        "summary": {
            "events_parsed": len(events),
            "malformed_lines": malformed,
            "findings": len(findings),
            "threshold": threshold,
        },
        "findings": [finding.to_dict() for finding in findings],
    }

def write_report(result, output_path):
    Path(output_path).write_text(json.dumps(result, indent=2), encoding="utf-8")
