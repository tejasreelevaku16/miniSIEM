"""
Unit tests for all Mini-SIEM Detection Rules (app/services/detection_engine.py).

Covers:
- AUTH-001: Brute-Force Login Detection
- AUTH-002: Failed Login Followed by Success
- AUTH-003: Repeated Suspicious Login Activity (Password Spraying)
- AUTH-004: Login Outside Working Hours
- FW-001: Port Scan Detection (with missing fields guard)
- WEB-001: High Request Volume (with missing fields guard)
"""

from datetime import datetime, timedelta
import unittest

from app.services.csv_parser import LogEvent
from app.services.detection_engine import (
    detect_brute_force,
    detect_failed_then_success,
    detect_high_web_request_volume,
    detect_outside_working_hours,
    detect_port_scan,
    detect_repeated_suspicious_logins,
    run_all_detection_rules,
)


class TestDetectionRules(unittest.TestCase):
    """Test suite verifying each detection rule logic."""

    def test_auth_001_brute_force_threshold_and_window(self):
        """AUTH-001: Verify >= 5 failures in 10 minutes triggers HIGH severity alert."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i * 30),
                source_ip="45.33.32.156",
                username="admin",
                event_type="LOGIN",
                outcome="failure",
            )
            for i in range(5)
        ]

        alerts = detect_brute_force(events, threshold=5, window_minutes=10)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "AUTH-001")
        self.assertEqual(alert.source_ip, "45.33.32.156")
        self.assertEqual(alert.failure_count, 5)
        self.assertEqual(alert.severity, "HIGH")
        self.assertEqual(alert.mitre_attack_id, "T1110")

    def test_auth_002_failed_then_success(self):
        """AUTH-002: Verify failed attempts followed by success for same user & IP triggers alert."""
        base_time = datetime(2026, 10, 20, 9, 10, 0)
        events = [
            LogEvent(
                timestamp=base_time,
                source_ip="192.168.1.50",
                username="developer",
                event_type="LOGIN",
                outcome="failure",
            ),
            LogEvent(
                timestamp=base_time + timedelta(seconds=45),
                source_ip="192.168.1.50",
                username="developer",
                event_type="LOGIN",
                outcome="failure",
            ),
            LogEvent(
                timestamp=base_time + timedelta(seconds=90),
                source_ip="192.168.1.50",
                username="developer",
                event_type="LOGIN",
                outcome="success",
            ),
        ]

        alerts = detect_failed_then_success(events, window_minutes=15)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "AUTH-002")
        self.assertEqual(alert.source_ip, "192.168.1.50")
        self.assertEqual(alert.targeted_usernames, ["developer"])
        self.assertEqual(alert.mitre_attack_id, "T1078")
        self.assertIn("SUCCESSFUL", alert.description)

    def test_auth_002_success_without_failures_no_alert(self):
        """AUTH-002: Normal successful login with no prior failures must NOT trigger alert."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 9, 0, 0),
                source_ip="10.0.0.1",
                username="alice",
                event_type="LOGIN",
                outcome="success",
            )
        ]
        alerts = detect_failed_then_success(events)
        self.assertEqual(len(alerts), 0)

    def test_auth_003_repeated_suspicious_logins_password_spray(self):
        """AUTH-003: Verify spray attempts against >= 3 distinct users from same IP triggers alert."""
        base_time = datetime(2026, 10, 20, 9, 20, 0)
        targets = ["root", "administrator", "backup", "guest"]
        events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i * 20),
                source_ip="185.220.101.5",
                username=target,
                event_type="LOGIN",
                outcome="failure",
            )
            for i, target in enumerate(targets)
        ]

        alerts = detect_repeated_suspicious_logins(events, user_spray_threshold=3, window_minutes=15)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "AUTH-003")
        self.assertEqual(alert.source_ip, "185.220.101.5")
        self.assertEqual(len(alert.targeted_usernames), 4)
        self.assertEqual(alert.mitre_attack_id, "T1110.003")

    def test_auth_004_outside_working_hours(self):
        """AUTH-004: Verify login at 02:00 AM (outside 08:00 - 18:00) triggers alert."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 2, 30, 0),  # Tuesday 02:30 AM
                source_ip="10.0.0.99",
                username="sysadmin",
                event_type="LOGIN",
                outcome="success",
            ),
            LogEvent(
                timestamp=datetime(2026, 10, 20, 10, 30, 0),  # Tuesday 10:30 AM (in hours)
                source_ip="10.0.0.15",
                username="normal_user",
                event_type="LOGIN",
                outcome="success",
            ),
        ]

        alerts = detect_outside_working_hours(events, start_hour=8, end_hour=18)
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].rule_id, "AUTH-004")
        self.assertEqual(alerts[0].source_ip, "10.0.0.99")
        self.assertEqual(alerts[0].targeted_usernames, ["sysadmin"])

    def test_fw_001_port_scan_detection(self):
        """FW-001: Verify connection attempts across >= 5 distinct ports triggers port scan alert."""
        base_time = datetime(2026, 10, 20, 10, 0, 0)
        ports = [21, 22, 23, 25, 80, 443, 3389]
        events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i * 5),
                source_ip="198.51.100.44",
                username="anonymous",
                event_type="PORT_PROBE",
                outcome="blocked",
                dest_port=port,
            )
            for i, port in enumerate(ports)
        ]

        alerts = detect_port_scan(events, port_threshold=5, window_minutes=5)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "FW-001")
        self.assertEqual(alert.source_ip, "198.51.100.44")
        self.assertEqual(alert.mitre_attack_id, "T1046")

    def test_fw_001_missing_fields_returns_empty(self):
        """FW-001: Must NOT fabricate alert if dest_port field is missing."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 10, 0, 0),
                source_ip="198.51.100.44",
                username="anonymous",
                event_type="PORT_PROBE",
                outcome="blocked",
                # dest_port is None
            )
        ]
        alerts = detect_port_scan(events)
        self.assertEqual(len(alerts), 0)

    def test_web_001_high_request_volume(self):
        """WEB-001: Verify >= 30 requests in 1 minute triggers rate anomaly alert."""
        base_time = datetime(2026, 10, 20, 11, 0, 0)
        events = [
            LogEvent(
                timestamp=base_time + timedelta(seconds=i),
                source_ip="203.0.113.88",
                username="anonymous",
                event_type="HTTP_REQUEST",
                outcome="success",
                request_path="/api/search",
                status_code=200,
            )
            for i in range(35)
        ]

        alerts = detect_high_web_request_volume(events, request_threshold=30, window_minutes=1)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.rule_id, "WEB-001")
        self.assertEqual(alert.source_ip, "203.0.113.88")
        self.assertEqual(alert.mitre_attack_id, "T1499")

    def test_web_001_missing_web_fields_returns_empty(self):
        """WEB-001: Must NOT fabricate alert if web fields are absent."""
        events = [
            LogEvent(
                timestamp=datetime(2026, 10, 20, 11, 0, 0),
                source_ip="203.0.113.88",
                username="anonymous",
                event_type="LOGIN",
                outcome="failure",
                # No web path or status code
            )
        ]
        alerts = detect_high_web_request_volume(events)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
