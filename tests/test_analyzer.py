import unittest
from sentinelx.analyzer import parse_log_lines, analyze_events

class AnalyzerTests(unittest.TestCase):
    def test_parse_valid_and_malformed_lines(self):
        lines = [
            "2026-11-24T09:15:00Z FAILED_LOGIN user=alice ip=203.0.113.10",
            "not a valid event",
        ]
        events, malformed = parse_log_lines(lines)
        self.assertEqual(len(events), 1)
        self.assertEqual(malformed, 1)

    def test_threshold_creates_finding(self):
        events = [
            {"event": "FAILED_LOGIN", "user": "alice", "ip": "203.0.113.10"}
            for _ in range(5)
        ]
        findings = analyze_events(events, threshold=5)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].severity, "MEDIUM")

    def test_below_threshold_no_finding(self):
        events = [
            {"event": "FAILED_LOGIN", "user": "alice", "ip": "203.0.113.10"}
            for _ in range(4)
        ]
        self.assertEqual(analyze_events(events, threshold=5), [])

if __name__ == "__main__":
    unittest.main()
