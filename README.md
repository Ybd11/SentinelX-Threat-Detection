# SentinelX — Intelligent Threat Detection

SentinelX is a lightweight, explainable Python security-monitoring project. It parses a sample authentication log, counts failed login attempts by source IP, and creates a JSON report for review.

> **Scope and safety:** This is a defensive learning project. The included log data is synthetic and uses documentation-only IP ranges. It does not scan networks, contact hosts, or block traffic.

## Features
- Parses timestamped successful and failed login events.
- Detects repeated failed logins using a configurable threshold.
- Assigns a simple severity level based on observed evidence.
- Reports malformed log lines instead of silently treating them as valid.
- Exports structured JSON suitable for later dashboard integration.
- Includes automated unit tests.

## Project structure
```text
SentinelX-Threat-Detection/
├── sentinelx/
│   ├── __init__.py
│   ├── analyzer.py
│   └── cli.py
├── sample_data/
│   └── auth.log
├── tests/
│   └── test_analyzer.py
├── requirements.txt
└── README.md
```

## Requirements
- Python 3.10+
- No third-party packages are required.

## Run locally
```bash
python -m sentinelx.cli sample_data/auth.log
```

Set a different alert threshold and output file:
```bash
python -m sentinelx.cli sample_data/auth.log --threshold 3 --output report.json
```

## Run tests
```bash
python -m unittest discover -s tests -v
```

## Example output
The included sample data contains six failed logins from `203.0.113.10`. With the default threshold of five, SentinelX creates one medium-severity finding.

## Detection logic and limitations
The current rule flags an IP when its total failed-login count reaches a configurable threshold. It is intentionally simple and does not yet correlate events in time windows, distinguish shared NAT addresses, enrich IP reputation, or establish that an attack succeeded. A finding is an investigative lead—not proof of compromise.

## Future improvements
- Add rolling time-window analysis.
- Support common Linux authentication-log formats.
- Add allowlists and configurable detection rules.
- Build a Flask dashboard with charts and filtering.
- Add structured logging and CI tests.

## Portfolio note
This project demonstrates Python development, log parsing, defensive security monitoring, rule-based detection, JSON reporting, and unit testing.
