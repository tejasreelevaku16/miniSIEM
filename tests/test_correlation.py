"""
Unit tests for Mini-SIEM Incident Correlation Engine (app/services/incident_correlator.py).

Covers:
- Grouping alerts from same IP into a single unified incident.
- Multi-stage attack escalation (AUTH-001 + AUTH-002 escalating to CRITICAL).
- Incident persistence with deduplication into SQLite.
"""

from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import unittest

from app.database import count_incidents, get_incident_by_id, init_db
from app.services.detection_engine import Alert
from app.services.incident_correlator import (
    CorrelatedIncident,
    correlate_alerts,
    persist_correlated_incidents,
)


class TestIncidentCorrelator(unittest.TestCase):
    """Test suite for incident correlation logic."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_corr.db"
        init_db(self.test_db_path)

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_correlate_alerts_same_ip(self):
        """Verify multiple alerts from same IP within correlation window merge into 1 incident."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        alerts = [
            Alert(
                source_ip="192.168.1.100",
                failure_count=5,
                window_start=base_time,
                window_end=base_time + timedelta(minutes=5),
                severity="HIGH",
                description="Brute force alert",
                targeted_usernames=["admin"],
                rule_id="AUTH-001",
                rule_name="Brute-Force",
                mitre_attack_id="T1110",
            ),
            Alert(
                source_ip="192.168.1.100",
                failure_count=1,
                window_start=base_time + timedelta(minutes=6),
                window_end=base_time + timedelta(minutes=7),
                severity="LOW",
                description="Outside hours",
                targeted_usernames=["admin"],
                rule_id="AUTH-004",
                rule_name="Outside Hours",
                mitre_attack_id="T1078",
            ),
        ]

        incidents = correlate_alerts(alerts, correlation_window_minutes=30)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.source_ip, "192.168.1.100")
        self.assertEqual(inc.failure_count, 6)
        self.assertEqual(len(inc.alerts), 2)
        self.assertIn("AUTH-001", inc.rule_id)
        self.assertIn("AUTH-004", inc.rule_id)

    def test_multi_stage_attack_escalation_to_critical(self):
        """Verify presence of both AUTH-001 (Brute-Force) and AUTH-002 (Success) escalates to CRITICAL."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        alerts = [
            Alert(
                source_ip="45.33.32.156",
                failure_count=5,
                window_start=base_time,
                window_end=base_time + timedelta(minutes=5),
                severity="HIGH",
                description="Brute force",
                targeted_usernames=["admin"],
                rule_id="AUTH-001",
                mitre_attack_id="T1110",
            ),
            Alert(
                source_ip="45.33.32.156",
                failure_count=2,
                window_start=base_time + timedelta(minutes=6),
                window_end=base_time + timedelta(minutes=7),
                severity="MEDIUM",
                description="Success after failure",
                targeted_usernames=["admin"],
                rule_id="AUTH-002",
                mitre_attack_id="T1078",
            ),
        ]

        incidents = correlate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        self.assertEqual(inc.severity, "CRITICAL")
        self.assertIn("CRITICAL Multi-Stage Attack", inc.description)

    def test_persist_correlated_incidents_deduplication(self):
        """Verify persisting correlated incidents avoids double-inserting duplicates."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        inc = CorrelatedIncident(
            source_ip="10.0.0.99",
            failure_count=5,
            window_start=base_time,
            window_end=base_time + timedelta(minutes=5),
            severity="HIGH",
            status="Open",
            description="Persistent test incident",
            targeted_usernames=["admin"],
            rule_id="AUTH-001",
            mitre_technique="T1110",
            recommended_action="Block IP",
            alerts=[],
        )

        saved1, dup1 = persist_correlated_incidents([inc], db_path=self.test_db_path)
        self.assertEqual(saved1, 1)
        self.assertEqual(dup1, 0)
        self.assertEqual(count_incidents(self.test_db_path), 1)

        # Second persistence of same incident
        saved2, dup2 = persist_correlated_incidents([inc], db_path=self.test_db_path)
        self.assertEqual(saved2, 0)
        self.assertEqual(dup2, 1)
        self.assertEqual(count_incidents(self.test_db_path), 1)

    def test_multi_stage_attack_requires_matching_username(self):
        """Verify that AUTH-001 and AUTH-002 on DIFFERENT usernames from same IP does NOT falsely escalate to CRITICAL."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        alerts = [
            Alert(
                source_ip="192.168.1.10",
                failure_count=5,
                window_start=base_time,
                window_end=base_time + timedelta(minutes=5),
                severity="HIGH",
                description="Brute force on admin",
                targeted_usernames=["admin"],
                rule_id="AUTH-001",
                mitre_attack_id="T1110",
            ),
            Alert(
                source_ip="192.168.1.10",
                failure_count=2,
                window_start=base_time + timedelta(minutes=6),
                window_end=base_time + timedelta(minutes=7),
                severity="MEDIUM",
                description="Success after failure for legitimate user alice",
                targeted_usernames=["alice"],
                rule_id="AUTH-002",
                mitre_attack_id="T1078",
            ),
        ]

        incidents = correlate_alerts(alerts)
        self.assertEqual(len(incidents), 1)
        inc = incidents[0]
        # Should NOT escalate to CRITICAL because targeted users differ
        self.assertEqual(inc.severity, "HIGH")
        self.assertNotIn("CRITICAL Multi-Stage Attack", inc.description)

    def test_alerts_table_deduplication_on_repeated_persistence(self):
        """Verify alerts linked to correlated incidents are not duplicated in the alerts table."""
        base_time = datetime(2026, 10, 20, 9, 0, 0)
        alert_obj = Alert(
            source_ip="10.0.0.99",
            failure_count=5,
            window_start=base_time,
            window_end=base_time + timedelta(minutes=5),
            severity="HIGH",
            description="Persistent test alert",
            targeted_usernames=["admin"],
            rule_id="AUTH-001",
            mitre_attack_id="T1110",
        )
        inc = CorrelatedIncident(
            source_ip="10.0.0.99",
            failure_count=5,
            window_start=base_time,
            window_end=base_time + timedelta(minutes=5),
            severity="HIGH",
            status="Open",
            description="Persistent test incident",
            targeted_usernames=["admin"],
            rule_id="AUTH-001",
            mitre_technique="T1110",
            recommended_action="Block IP",
            alerts=[alert_obj],
        )

        persist_correlated_incidents([inc], db_path=self.test_db_path)

        import sqlite3
        conn = sqlite3.connect(self.test_db_path)
        alert_count_1 = conn.cursor().execute("SELECT count(*) FROM alerts").fetchone()[0]
        self.assertEqual(alert_count_1, 1)

        # Run persistence again with same incident & alert
        persist_correlated_incidents([inc], db_path=self.test_db_path)
        alert_count_2 = conn.cursor().execute("SELECT count(*) FROM alerts").fetchone()[0]
        self.assertEqual(alert_count_2, 1)
        conn.close()


if __name__ == "__main__":
    unittest.main()
