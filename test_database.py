"""
Unit tests for Mini-SIEM database.py module.

Covers:
1. Database initialization and table creation.
2. Saving alert incidents with auto-increment IDs.
3. Chronological retrieval of saved incidents.
4. Counting incidents.
5. Deduplication behavior (preventing duplicate saves on repeated runs).
6. Parameterized SQL query safety against injection payloads.
7. Handling empty alert lists.

All tests operate inside a temporary directory to avoid touching the production minisiem.db.
"""

from datetime import datetime
from pathlib import Path
import sqlite3
import tempfile
import unittest

from database import count_incidents, get_all_incidents, init_db, save_alerts
from detector import Alert


class TestMiniSIEMDatabase(unittest.TestCase):
    """Test suite for SQLite incident persistence."""

    def setUp(self):
        """Creates an isolated temporary directory and database path for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.db_path = Path(self.temp_dir.name) / "test_minisiem.db"

    def tearDown(self):
        """Cleans up the temporary directory."""
        self.temp_dir.cleanup()

    def test_init_db(self):
        """Verify init_db creates the incidents table with expected columns and constraint."""
        init_db(self.db_path)
        self.assertTrue(self.db_path.exists())

        conn = sqlite3.connect(self.db_path)
        try:
            cursor = conn.cursor()
            # Verify table existence
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='incidents';")
            self.assertIsNotNone(cursor.fetchone())

            # Verify table column information
            cursor.execute("PRAGMA table_info(incidents);")
            columns = {col[1]: col[2] for col in cursor.fetchall()}

            expected_columns = [
                "id",
                "source_ip",
                "failure_count",
                "window_start",
                "window_end",
                "severity",
                "description",
                "targeted_usernames",
                "created_at",
            ]
            for col_name in expected_columns:
                self.assertIn(col_name, columns)

            # Primary key check: 'id' should be INTEGER PRIMARY KEY
            self.assertEqual(columns["id"].upper(), "INTEGER")
        finally:
            conn.close()

    def test_save_and_retrieve_alerts(self):
        """Verify saving alerts populates database rows and assigns unique IDs."""
        alerts = [
            Alert(
                source_ip="203.0.113.42",
                failure_count=4,
                window_start=datetime(2026, 10, 20, 9, 0, 15),
                window_end=datetime(2026, 10, 20, 9, 3, 30),
                severity="MEDIUM",
                description="Brute force test alert 1",
                targeted_usernames=["admin", "root"],
            ),
            Alert(
                source_ip="192.168.1.200",
                failure_count=5,
                window_start=datetime(2026, 10, 20, 10, 0, 5),
                window_end=datetime(2026, 10, 20, 10, 1, 50),
                severity="HIGH",
                description="Brute force test alert 2",
                targeted_usernames=["service_acc"],
            ),
        ]

        saved, duplicates = save_alerts(alerts, self.db_path)
        self.assertEqual(saved, 2)
        self.assertEqual(duplicates, 0)

        # Verify count
        self.assertEqual(count_incidents(self.db_path), 2)

        # Verify stored data
        records = get_all_incidents(self.db_path)
        self.assertEqual(len(records), 2)

        first = records[0]
        self.assertIsInstance(first["id"], int)
        self.assertEqual(first["source_ip"], "203.0.113.42")
        self.assertEqual(first["failure_count"], 4)
        self.assertEqual(first["window_start"], "2026-10-20 09:00:15")
        self.assertEqual(first["window_end"], "2026-10-20 09:03:30")
        self.assertEqual(first["severity"], "MEDIUM")
        self.assertEqual(first["targeted_usernames"], "admin, root")
        self.assertTrue(first["created_at"])

        second = records[1]
        self.assertIsInstance(second["id"], int)
        self.assertNotEqual(first["id"], second["id"])
        self.assertEqual(second["source_ip"], "192.168.1.200")
        self.assertEqual(second["severity"], "HIGH")

    def test_chronological_ordering(self):
        """Verify get_all_incidents returns records sorted by window_start chronologically."""
        # Insert out of chronological order
        alerts = [
            Alert(
                source_ip="10.0.0.3",
                failure_count=3,
                window_start=datetime(2026, 10, 20, 14, 0, 0),  # Latest
                window_end=datetime(2026, 10, 20, 14, 3, 0),
                severity="MEDIUM",
                description="Incident 3",
                targeted_usernames=["user3"],
            ),
            Alert(
                source_ip="10.0.0.1",
                failure_count=3,
                window_start=datetime(2026, 10, 20, 8, 0, 0),  # Earliest
                window_end=datetime(2026, 10, 20, 8, 2, 0),
                severity="MEDIUM",
                description="Incident 1",
                targeted_usernames=["user1"],
            ),
            Alert(
                source_ip="10.0.0.2",
                failure_count=3,
                window_start=datetime(2026, 10, 20, 11, 0, 0),  # Middle
                window_end=datetime(2026, 10, 20, 11, 4, 0),
                severity="MEDIUM",
                description="Incident 2",
                targeted_usernames=["user2"],
            ),
        ]

        save_alerts(alerts, self.db_path)

        incidents = get_all_incidents(self.db_path, ascending=True)
        self.assertEqual(len(incidents), 3)
        self.assertEqual(incidents[0]["source_ip"], "10.0.0.1")
        self.assertEqual(incidents[1]["source_ip"], "10.0.0.2")
        self.assertEqual(incidents[2]["source_ip"], "10.0.0.3")

    def test_duplicate_handling(self):
        """Verify that identical incidents are detected and not duplicated upon multiple runs."""
        alert = Alert(
            source_ip="203.0.113.42",
            failure_count=3,
            window_start=datetime(2026, 10, 20, 9, 0, 0),
            window_end=datetime(2026, 10, 20, 9, 2, 0),
            severity="MEDIUM",
            description="Brute-force attack test",
            targeted_usernames=["admin"],
        )

        # First run: should save 1 incident, 0 duplicates
        saved1, dup1 = save_alerts([alert], self.db_path)
        self.assertEqual(saved1, 1)
        self.assertEqual(dup1, 0)
        self.assertEqual(count_incidents(self.db_path), 1)

        # Second run with exact same alert: should save 0, 1 duplicate skipped
        saved2, dup2 = save_alerts([alert], self.db_path)
        self.assertEqual(saved2, 0)
        self.assertEqual(dup2, 1)
        self.assertEqual(count_incidents(self.db_path), 1)

        # Third run: 1 existing duplicate + 1 genuinely new alert
        new_alert = Alert(
            source_ip="198.51.100.99",
            failure_count=5,
            window_start=datetime(2026, 10, 20, 12, 0, 0),
            window_end=datetime(2026, 10, 20, 12, 3, 0),
            severity="HIGH",
            description="Distinct attack test",
            targeted_usernames=["root"],
        )
        saved3, dup3 = save_alerts([alert, new_alert], self.db_path)
        self.assertEqual(saved3, 1)
        self.assertEqual(dup3, 1)
        self.assertEqual(count_incidents(self.db_path), 2)

    def test_parameterized_query_sql_injection_defense(self):
        """Verify SQL injection payloads in IP or username do not break the database or execute SQL."""
        malicious_alert = Alert(
            source_ip="192.168.1.1'; DROP TABLE incidents; --",
            failure_count=3,
            window_start=datetime(2026, 10, 20, 9, 0, 0),
            window_end=datetime(2026, 10, 20, 9, 2, 0),
            severity="HIGH",
            description="' OR '1'='1' --",
            targeted_usernames=["admin' UNION SELECT 1, 2, 3; --"],
        )

        saved, dup = save_alerts([malicious_alert], self.db_path)
        self.assertEqual(saved, 1)

        # Confirm the incidents table was NOT dropped and data was stored safely as literal strings
        incidents = get_all_incidents(self.db_path)
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source_ip"], "192.168.1.1'; DROP TABLE incidents; --")
        self.assertIn("UNION SELECT", incidents[0]["targeted_usernames"])

    def test_empty_alerts_handling(self):
        """Verify calling save_alerts with an empty list safely returns (0, 0)."""
        saved, duplicates = save_alerts([], self.db_path)
        self.assertEqual(saved, 0)
        self.assertEqual(duplicates, 0)
        self.assertEqual(count_incidents(self.db_path), 0)


if __name__ == "__main__":
    unittest.main()
