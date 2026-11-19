"""
Mini-SIEM Security Alerts Router.

Endpoints for:
- Querying stored detection alerts with filtering (GET /api/alerts)
- Triggering batch detection engine execution (POST /api/alerts/run-detection)
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, Query

from app.database import (
    DEFAULT_DB_PATH,
    get_all_alerts,
    get_db_connection,
    get_db_path,
    init_db,
)
from app.services.csv_parser import LogEvent, parse_timestamp
from app.services.detection_engine import run_all_detection_rules
from app.services.incident_correlator import correlate_alerts, persist_correlated_incidents

router = APIRouter(prefix="/api/alerts", tags=["Alerts"])


@router.get("")
def list_alerts(
    limit: int = Query(default=100, ge=1, le=1000, description="Max alerts to return"),
    offset: int = Query(default=0, ge=0, description="Alerts to skip for pagination"),
    rule_id: Optional[str] = Query(default=None, description="Filter by detection rule (e.g. AUTH-001)"),
    severity: Optional[str] = Query(default=None, description="Filter by severity (LOW, MEDIUM, HIGH, CRITICAL)"),
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Retrieves stored detection alerts ordered chronologically with optional filters.
    """
    total, alerts = get_all_alerts(
        db_path=db_path,
        limit=limit,
        offset=offset,
        rule_id=rule_id,
        severity=severity,
    )

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "alerts": alerts,
    }


@router.post("/run-detection")
def execute_batch_detection(
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Runs all detection rules across all stored security events in the database,
    correlates generated alerts into incidents, and persists new detections.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)

    events: list[LogEvent] = []
    try:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT
                timestamp,
                source_ip,
                username,
                event_type,
                source,
                outcome,
                user_agent,
                dest_ip,
                dest_port,
                protocol,
                request_path,
                status_code
            FROM security_events
            ORDER BY timestamp ASC;
        """)
        for row in cursor.fetchall():
            ts = parse_timestamp(row[0])
            if ts:
                events.append(LogEvent(
                    timestamp=ts,
                    source_ip=row[1],
                    username=row[2],
                    event_type=row[3],
                    source=row[4] or "",
                    outcome=row[5] or "",
                    user_agent=row[6],
                    dest_ip=row[7],
                    dest_port=row[8],
                    protocol=row[9],
                    request_path=row[10],
                    status_code=row[11],
                ))
    finally:
        conn.close()

    if not events:
        return {
            "status": "ok",
            "message": "No security events found in database to analyze.",
            "analyzed_events": 0,
            "generated_alerts": 0,
            "saved_incidents": 0,
        }

    alerts = run_all_detection_rules(events)
    correlated = correlate_alerts(alerts)
    saved_incidents, duplicate_incidents = persist_correlated_incidents(correlated, db_path=db_path)

    return {
        "status": "ok",
        "message": f"Detection complete. Analyzed {len(events)} event(s).",
        "analyzed_events": len(events),
        "generated_alerts": len(alerts),
        "saved_incidents": saved_incidents,
        "duplicate_incidents_skipped": duplicate_incidents,
    }
