"""
Unit tests for Mini-SIEM detector.py module.

Covers:
1. Suspicious IP detection (brute-force threshold met within rolling window).
2. Normal IP behavior (successful logins, failures below threshold).
3. Failures spread outside rolling time window (no alert).
4. Severity level assignment (MEDIUM vs HIGH).
5. Graceful handling of missing files.
6. Graceful handling of malformed timestamps.
7. Graceful handling of missing columns and empty row values.
8. End-to-end validation with sample_logs.csv.
"""

from datetime import datetime
import os
from pathlib import Path
import tempfile
import unittest

from app.services.detector import Alert, LogEvent, detect_brute_force, load_logs, parse_log_row, parse_timestamp

class TestMiniSIEMDetector(unittest.TestCase):
    """Test suite for log parsing and brute-force detection logic."""

    def test_suspicious_ip_detection(self):
        """Verify that an IP with >= 3 failed logins within 5 minutes triggers an alert."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 0, 0),
                source_ip="203.0.113.42",
                username="admin",
                event_type="LOGIN_FAILED",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 1, 30),
                source_ip="203.0.113.42",
                username="root",
                event_type="LOGIN_FAILED",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 3, 0),
                source_ip="203.0.113.42",
                username="administrator",
                event_type="LOGIN_FAILED",
            ),
        ]

        alerts = detect_brute_force(events, threshold=3, window_minutes=5)

        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.source_ip, "203.0.113.42")
        self.assertEqual(alert.failure_count, 3)
        self.assertEqual(alert.severity, "MEDIUM")
        self.assertEqual(alert.window_start, datetime(2026, 10, 20, 9, 0, 0))
        self.assertEqual(alert.window_end, datetime(2026, 10, 20, 9, 3, 0))
        self.assertIn("admin", alert.targeted_usernames)
        self.assertIn("root", alert.targeted_usernames)
        self.assertIn("administrator", alert.targeted_usernames)

    def test_normal_ip_no_alert(self):
        """Verify that normal IP behavior (successful logins, single typo failure) triggers NO alert."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 5, 0),
                source_ip="192.168.1.50",
                username="alice",
                event_type="LOGIN_FAILED",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 5, 40),
                source_ip="192.168.1.50",
                username="alice",
                event_type="LOGIN_SUCCESS",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 30, 0),
                source_ip="192.168.1.50",
                username="alice",
                event_type="LOGIN_SUCCESS",
            ),
        ]

        alerts = detect_brute_force(events, threshold=3, window_minutes=5)
        self.assertEqual(len(alerts), 0)

    def test_failures_spread_outside_time_window(self):
        """Verify that 3 failures spread across > 5 minutes do NOT trigger an alert."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 0, 0),
                source_ip="198.51.100.18",
                username="bob",
                event_type="LOGIN_FAILED",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 12, 0),  # 12 minutes later
                source_ip="198.51.100.18",
                username="bob",
                event_type="LOGIN_FAILED",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 27, 0),  # 15 minutes later
                source_ip="198.51.100.18",
                username="bob",
                event_type="LOGIN_FAILED",
            ),
        ]

        alerts = detect_brute_force(events, threshold=3, window_minutes=5)
        self.assertEqual(len(alerts), 0)

    def test_severity_levels(self):
        """Verify that 3-4 failures produce MEDIUM severity and 5+ produce HIGH severity."""
        from datetime import timedelta
        base_time = datetime(2026, 10, 20, 10, 0, 0)

        # 4 failures: MEDIUM
        med_events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i * 20),
                source_ip="10.0.0.99",
                username="user",
                event_type="LOGIN_FAILED",
            )
            for i in range(4)
        ]
        med_alerts = detect_brute_force(med_events, threshold=3, window_minutes=5)
        self.assertEqual(len(med_alerts), 1)
        self.assertEqual(med_alerts[0].severity, "MEDIUM")

        # 5 failures: HIGH
        high_events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i * 15),
                source_ip="10.0.0.100",
                username="user",
                event_type="LOGIN_FAILED",
            )
            for i in range(5)
        ]
        high_alerts = detect_brute_force(high_events, threshold=3, window_minutes=5)
        self.assertEqual(len(high_alerts), 1)
        self.assertEqual(high_alerts[0].severity, "HIGH")

    def test_missing_file_handling(self):
        """Verify load_logs handles a missing file gracefully without crashing."""
        non_existent = Path("non_existent_logs_file_12345.csv")
        events, warnings = load_logs(non_existent)

        self.assertEqual(len(events), 0)
        self.assertEqual(len(warnings), 1)
        self.assertIn("not found", warnings[0].lower())

    def test_malformed_timestamp_handling(self):
        """Verify malformed timestamps are rejected with a warning and valid rows still parse."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv", encoding="utf-8") as tf:
            tf.write("timestamp,source_ip,username,event_type\n")
            tf.write("not-a-timestamp,10.0.0.1,admin,LOGIN_FAILED\n")
            tf.write("2026-10-20 09:00:00,10.0.0.2,admin,LOGIN_FAILED\n")
            temp_path = tf.name

        try:
            events, warnings = load_logs(temp_path)
            # Row 2 had bad timestamp; row 3 had good timestamp
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].source_ip, "10.0.0.2")
            self.assertEqual(len(warnings), 1)
            self.assertIn("Malformed timestamp", warnings[0])
        finally:
            os.remove(temp_path)

    def test_invalid_rows_handling(self):
        """Verify missing fields or empty values are flagged with warnings and valid rows still parse."""
        with tempfile.NamedTemporaryFile(mode="w", delete=False, suffix=".csv", encoding="utf-8") as tf:
            tf.write("timestamp,source_ip,username,event_type\n")
            tf.write("2026-10-20 09:00:00,,admin,LOGIN_FAILED\n")  # Empty source_ip
            tf.write("2026-10-20 09:01:00,10.0.0.1,,LOGIN_FAILED\n")  # Empty username
            tf.write("2026-10-20 09:02:00,10.0.0.1,admin,LOGIN_FAILED\n")  # Valid
            temp_path = tf.name

        try:
            events, warnings = load_logs(temp_path)
            self.assertEqual(len(events), 1)
            self.assertEqual(events[0].timestamp, datetime(2026, 10, 20, 9, 2, 0))
            self.assertEqual(len(warnings), 2)
            self.assertIn("empty value", warnings[0].lower())
            self.assertIn("empty value", warnings[1].lower())
        finally:
            os.remove(temp_path)

    def test_sample_logs_file_end_to_end(self):
        """Verify detection on the project's actual sample_logs.csv file."""
        sample_path = Path(__file__).parent.parent / "sample_logs" / "sample_logs.csv"
        self.assertTrue(sample_path.exists(), "sample_logs.csv must exist in project root")

        events, warnings = load_logs(sample_path)
        # All sample rows in sample_logs.csv are valid
        self.assertEqual(len(warnings), 0)
        self.assertEqual(len(events), 17)

        alerts = detect_brute_force(events, threshold=3, window_minutes=5)

        # Expected:
        # 1. 203.0.113.42: 4 failed attempts within ~3m15s (MEDIUM severity)
        # 2. 192.168.1.200: 5 failed attempts within ~1m45s (HIGH severity)
        # Normal IPs (10.0.0.15, 192.168.1.50) and spaced-out failures (198.51.100.18) must NOT trigger alerts.
        self.assertEqual(len(alerts), 2)

        alert_ips = {a.source_ip: a for a in alerts}
        self.assertIn("203.0.113.42", alert_ips)
        self.assertIn("192.168.1.200", alert_ips)

        alert_42 = alert_ips["203.0.113.42"]
        self.assertEqual(alert_42.failure_count, 4)
        self.assertEqual(alert_42.severity, "MEDIUM")

        alert_200 = alert_ips["192.168.1.200"]
        self.assertEqual(alert_200.failure_count, 5)
        self.assertEqual(alert_200.severity, "HIGH")


if __name__ == "__main__":
    unittest.main()
