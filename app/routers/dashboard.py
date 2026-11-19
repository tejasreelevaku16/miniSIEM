"""
Mini-SIEM Dashboard Analytics Router.

Provides real-time aggregated metrics for the SOC dashboard (GET /api/dashboard/stats).
"""

from pathlib import Path
from fastapi import APIRouter, Depends

from app.database import DEFAULT_DB_PATH, get_dashboard_stats, get_db_path

router = APIRouter(prefix="/api/dashboard", tags=["Dashboard"])


@router.get("/stats")
def get_stats(
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Computes real aggregate metrics across events, alerts, and incidents:
    - Overview KPIs (Total Events, Alerts, Incidents, Open Incidents, High/Critical)
    - Successful vs Failed login ratio
    - Events by telemetry source
    - Alerts by severity distribution
    - Incidents by lifecycle status
    - Top 5 suspicious source IP addresses
    - Timeline event frequency
    """
    return get_dashboard_stats(db_path=db_path)
