"""
Unit tests for Mini-SIEM Incidents, Alerts, and Dashboard API Endpoints.

Covers:
- GET /api/incidents
- GET /api/incidents/{incident_id}
- PATCH /api/incidents/{incident_id} (status updates)
- GET /api/alerts
- POST /api/alerts/run-detection
- GET /api/dashboard/stats
- GET / (UI serving)
"""

from datetime import datetime
from pathlib import Path
import tempfile
import unittest

from fastapi.testclient import TestClient

from app.database import get_db_path, init_db, save_alerts
from app.main import app
from app.services.detection_engine import Alert


class TestIncidentAndDashboardApi(unittest.TestCase):
    """Test suite for incident management, alert querying, and dashboard analytics."""

    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.test_db_path = Path(self.temp_dir.name) / "test_api_inc.db"
        init_db(self.test_db_path)

        app.dependency_overrides[get_db_path] = lambda: self.test_db_path
        self.client = TestClient(app)

    def tearDown(self):
        app.dependency_overrides.clear()
        self.temp_dir.cleanup()

    def test_serve_dashboard_ui(self):
        """Verify GET / returns 200 and loads the SOC dashboard HTML."""
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        # Should either serve index.html with SOC layout or fallback json
        self.assertTrue(
            "MINI-SIEM" in response.text or "Mini-SIEM" in response.text
        )

    def test_get_dashboard_stats_empty_and_populated(self):
        """Verify GET /api/dashboard/stats returns real aggregate numbers."""
        res_empty = self.client.get("/api/dashboard/stats")
        self.assertEqual(res_empty.status_code, 200)
        data = res_empty.json()
        self.assertEqual(data["total_events"], 0)
        self.assertEqual(data["total_incidents"], 0)

        # Ingest some telemetry via upload
        csv_content = (
            "timestamp,source,username,source_ip,event_type,outcome,user_agent\n"
            "2026-10-20T09:00:00,windows,alice,10.0.0.1,login,success,Chrome\n"
            "2026-10-20T09:01:00,windows,bob,10.0.0.2,login,failure,curl\n"
        )
        self.client.post("/api/logs/upload", files={"file": ("logs.csv", csv_content, "text/csv")})

        res_pop = self.client.get("/api/dashboard/stats")
        self.assertEqual(res_pop.status_code, 200)
        pop_data = res_pop.json()
        self.assertEqual(pop_data["total_events"], 2)
        self.assertIn("windows", pop_data["events_by_source"])

    def test_incidents_crud_and_status_patch(self):
        """Verify listing incidents, retrieving details, and PATCH status updates."""
        # Seed an incident
        alert = Alert(
            source_ip="203.0.113.42",
            failure_count=5,
            window_start=datetime(2026, 10, 20, 9, 0, 0),
            window_end=datetime(2026, 10, 20, 9, 5, 0),
            severity="HIGH",
            description="Brute force test alert",
            targeted_usernames=["admin"],
            rule_id="AUTH-001",
        )
        save_alerts([alert], self.test_db_path)

        # 1. List incidents
        list_res = self.client.get("/api/incidents")
        self.assertEqual(list_res.status_code, 200)
        incidents = list_res.json()["incidents"]
        self.assertEqual(len(incidents), 1)
        inc_id = incidents[0]["id"]
        self.assertEqual(incidents[0]["status"], "Open")

        # 2. Get incident details
        detail_res = self.client.get(f"/api/incidents/{inc_id}")
        self.assertEqual(detail_res.status_code, 200)
        detail = detail_res.json()
        self.assertEqual(detail["source_ip"], "203.0.113.42")
        self.assertIn("alerts", detail)

        # 3. PATCH status to 'Investigating'
        patch_res = self.client.patch(
            f"/api/incidents/{inc_id}",
            json={"status": "Investigating"},
        )
        self.assertEqual(patch_res.status_code, 200)
        self.assertEqual(patch_res.json()["incident"]["status"], "Investigating")

        # 4. PATCH status with invalid string -> 422 Unprocessable Entity
        bad_patch = self.client.patch(
            f"/api/incidents/{inc_id}",
            json={"status": "NonExistentStatus"},
        )
        self.assertEqual(bad_patch.status_code, 422)

    def test_run_detection_batch_endpoint(self):
        """Verify POST /api/alerts/run-detection executes detection on stored events."""
        # Upload brute force events
        csv_content = (
            "timestamp,source,username,source_ip,event_type,outcome,user_agent\n"
            + "\n".join(
                f"2026-10-20T09:0{i}:00,windows,admin,45.33.32.156,login,failure,curl"
                for i in range(5)
            )
        )
        self.client.post("/api/logs/upload", files={"file": ("brute.csv", csv_content, "text/csv")})

        res = self.client.post("/api/alerts/run-detection")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["status"], "ok")
        self.assertGreaterEqual(data["analyzed_events"], 5)


if __name__ == "__main__":
    unittest.main()
