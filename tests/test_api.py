"""
Unit tests for Mini-SIEM FastAPI Ingestion Application (app.py).

Covers:
1. Health check endpoint (GET /api/health).
2. Valid CSV upload and database persistence (POST /api/logs/upload).
3. Duplicate event skipping on repeated uploads.
4. Validation and rejection of missing required CSV columns.
5. Graceful handling of malformed and empty rows within an upload.
6. Rejection of non-CSV files and empty files.
7. Retrieval of stored security events (GET /api/logs).
8. Pagination and chronological ordering of retrieved events.

Uses FastAPI's TestClient and temporary SQLite databases for complete isolation.
"""

from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from app.main import app, get_db_path
from app.database import init_db

class TestMiniSIEMApi(unittest.TestCase):
    """Test suite for Mini-SIEM FastAPI endpoints."""

    def setUp(self):
        """Creates an isolated temporary directory and database path for each test."""
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_api.db"
        init_db(self.test_db_path)

        # Override the FastAPI database dependency with our temporary DB
        app.dependency_overrides[get_db_path] = lambda: self.test_db_path
        self.client = TestClient(app)

    def tearDown(self):
        """Cleans up dependency overrides and temporary directory."""
        app.dependency_overrides.clear()
        self.temp_dir.cleanup()

    def test_health_check(self):
        """Verify GET /api/health returns 200 and healthy status information."""
        response = self.client.get("/api/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ok")
        self.assertEqual(data["service"], "Mini-SIEM Log Ingestion API")
        self.assertIn("timestamp", data)

    def test_upload_valid_csv(self):
        """Verify POST /api/logs/upload parses, stores, and returns summary counts for valid CSV."""
        csv_content = (
            "timestamp,source_ip,username,event_type\n"
            "2026-10-20 09:00:00,10.0.0.1,alice,LOGIN_SUCCESS\n"
            "2026-10-20 09:01:00,10.0.0.2,bob,LOGIN_FAILED\n"
        )
        files = {"file": ("auth_logs.csv", csv_content, "text/csv")}

        response = self.client.post("/api/logs/upload", files=files)
        self.assertEqual(response.status_code, 200)

        data = response.json()
        self.assertEqual(data["status"], "success")
        self.assertEqual(data["filename"], "auth_logs.csv")
        self.assertIsInstance(data["upload_id"], int)

        summary = data["summary"]
        self.assertEqual(summary["total_rows"], 2)
        self.assertEqual(summary["valid_events"], 2)
        self.assertEqual(summary["rejected_rows"], 0)
        self.assertEqual(summary["stored_events"], 2)
        self.assertEqual(summary["duplicate_events_skipped"], 0)

    def test_upload_duplicate_prevention(self):
        """Verify re-uploading the same events detects duplicates and avoids double-storing."""
        csv_content = (
            "timestamp,source_ip,username,event_type\n"
            "2026-10-20 09:00:00,10.0.0.1,alice,LOGIN_SUCCESS\n"
            "2026-10-20 09:01:00,10.0.0.2,bob,LOGIN_FAILED\n"
        )
        files1 = {"file": ("batch1.csv", csv_content, "text/csv")}
        res1 = self.client.post("/api/logs/upload", files=files1)
        self.assertEqual(res1.status_code, 200)
        self.assertEqual(res1.json()["summary"]["stored_events"], 2)

        # Upload the same data again
        files2 = {"file": ("batch2.csv", csv_content, "text/csv")}
        res2 = self.client.post("/api/logs/upload", files=files2)
        self.assertEqual(res2.status_code, 200)
        self.assertEqual(res2.json()["summary"]["stored_events"], 0)
        self.assertEqual(res2.json()["summary"]["duplicate_events_skipped"], 2)

        # Total in DB should still be 2
        logs_res = self.client.get("/api/logs")
        self.assertEqual(logs_res.json()["total"], 2)

    def test_upload_missing_required_columns(self):
        """Verify CSV missing required columns (e.g. username) is rejected with 400 Bad Request."""
        csv_content = (
            "timestamp,source_ip,event_type\n"
            "2026-10-20 09:00:00,10.0.0.1,LOGIN_FAILED\n"
        )
        files = {"file": ("missing_cols.csv", csv_content, "text/csv")}

        response = self.client.post("/api/logs/upload", files=files)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Missing required CSV column(s): username", response.json()["detail"])

    def test_upload_malformed_and_invalid_rows(self):
        """Verify malformed rows are counted as rejected while valid rows are stored."""
        csv_content = (
            "timestamp,source_ip,username,event_type\n"
            "2026-10-20 09:00:00,10.0.0.1,alice,LOGIN_SUCCESS\n"
            "not-a-timestamp,10.0.0.2,bob,LOGIN_FAILED\n"
            "2026-10-20 09:02:00,,charlie,LOGIN_FAILED\n"
        )
        files = {"file": ("mixed_logs.csv", csv_content, "text/csv")}

        response = self.client.post("/api/logs/upload", files=files)
        self.assertEqual(response.status_code, 200)

        summary = response.json()["summary"]
        self.assertEqual(summary["total_rows"], 3)
        self.assertEqual(summary["valid_events"], 1)
        self.assertEqual(summary["rejected_rows"], 2)
        self.assertEqual(summary["stored_events"], 1)

    def test_upload_non_csv_file(self):
        """Verify non-CSV files (wrong extension) are rejected with 400 Bad Request."""
        files = {"file": ("malware.exe", b"MZ\x90\x00", "application/octet-stream")}
        response = self.client.post("/api/logs/upload", files=files)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Please upload a CSV file", response.json()["detail"])

    def test_upload_empty_file(self):
        """Verify empty files are rejected with 400 Bad Request."""
        files = {"file": ("empty.csv", b"", "text/csv")}
        response = self.client.post("/api/logs/upload", files=files)
        self.assertEqual(response.status_code, 400)
        self.assertIn("Uploaded file is empty", response.json()["detail"])

    def test_get_logs_empty(self):
        """Verify GET /api/logs returns 0 total and empty list when database has no events."""
        response = self.client.get("/api/logs")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["total"], 0)
        self.assertEqual(len(data["events"]), 0)

    def test_get_logs_chronological_order(self):
        """Verify GET /api/logs returns events sorted chronologically by timestamp."""
        # Provide out-of-order logs
        csv_content = (
            "timestamp,source_ip,username,event_type\n"
            "2026-10-20 12:00:00,10.0.0.3,charlie,LOGIN_SUCCESS\n"
            "2026-10-20 08:00:00,10.0.0.1,alice,LOGIN_SUCCESS\n"
            "2026-10-20 10:00:00,10.0.0.2,bob,LOGIN_FAILED\n"
        )
        self.client.post("/api/logs/upload", files={"file": ("logs.csv", csv_content, "text/csv")})

        response = self.client.get("/api/logs")
        self.assertEqual(response.status_code, 200)
        events = response.json()["events"]
        self.assertEqual(len(events), 3)
        self.assertEqual(events[0]["timestamp"], "2026-10-20 08:00:00")
        self.assertEqual(events[1]["timestamp"], "2026-10-20 10:00:00")
        self.assertEqual(events[2]["timestamp"], "2026-10-20 12:00:00")

    def test_get_logs_pagination(self):
        """Verify limit and offset query parameters page correctly through security events."""
        rows = [
            f"2026-10-20 09:0{i}:00,10.0.0.{i},user{i},LOGIN_SUCCESS"
            for i in range(5)
        ]
        csv_content = "timestamp,source_ip,username,event_type\n" + "\n".join(rows)
        self.client.post("/api/logs/upload", files={"file": ("logs.csv", csv_content, "text/csv")})

        # Page 1: limit 2, offset 0
        p1 = self.client.get("/api/logs?limit=2&offset=0").json()
        self.assertEqual(p1["total"], 5)
        self.assertEqual(len(p1["events"]), 2)
        self.assertEqual(p1["events"][0]["username"], "user0")
        self.assertEqual(p1["events"][1]["username"], "user1")

        # Page 2: limit 2, offset 2
        p2 = self.client.get("/api/logs?limit=2&offset=2").json()
        self.assertEqual(len(p2["events"]), 2)
        self.assertEqual(p2["events"][0]["username"], "user2")
        self.assertEqual(p2["events"][1]["username"], "user3")

        # Page 3: limit 2, offset 4
        p3 = self.client.get("/api/logs?limit=2&offset=4").json()
        self.assertEqual(len(p3["events"]), 1)
        self.assertEqual(p3["events"][0]["username"], "user4")


if __name__ == "__main__":
    unittest.main()
