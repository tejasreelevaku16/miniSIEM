"""
Mini-SIEM Incidents Router.

Endpoints for:
- Listing security incidents with status/severity filters (GET /api/incidents)
- Inspecting a single incident with timeline & alert breakdown (GET /api/incidents/{incident_id})
- Updating an incident's lifecycle status (PATCH /api/incidents/{incident_id})
"""

from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.database import (
    DEFAULT_DB_PATH,
    get_all_incidents,
    get_db_path,
    get_incident_by_id,
    update_incident_status,
)
from app.schemas import IncidentStatusUpdate

router = APIRouter(prefix="/api/incidents", tags=["Incidents"])


@router.get("")
def list_incidents(
    ascending: bool = Query(default=False, description="Sort order by start time"),
    status: Optional[str] = Query(default=None, description="Filter by status ('Open', 'Investigating', 'Resolved', 'False Positive')"),
    severity: Optional[str] = Query(default=None, description="Filter by severity ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')"),
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Retrieves all correlated security incidents matching optional filters.
    """
    incidents = get_all_incidents(
        db_path=db_path,
        ascending=ascending,
        status=status,
        severity=severity,
    )

    return {
        "total": len(incidents),
        "incidents": incidents,
    }


@router.get("/{incident_id}")
def get_incident_details(
    incident_id: int,
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Retrieves comprehensive incident details:
    - Root cause description and severity
    - Associated detection alerts
    - Raw security event timeline during the attack window
    - MITRE ATT&CK technique breakdown
    - Recommended SOC analyst investigation playbook
    """
    incident = get_incident_by_id(incident_id, db_path=db_path)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Security incident with ID {incident_id} not found.",
        )

    return incident


@router.patch("/{incident_id}")
def update_incident(
    incident_id: int,
    update_data: IncidentStatusUpdate,
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Updates the SOC investigation lifecycle status for an incident.
    Allowed statuses: 'Open', 'Investigating', 'Resolved', 'False Positive'.
    """
    updated = update_incident_status(
        incident_id=incident_id,
        status=update_data.status,
        db_path=db_path,
    )

    if not updated:
        raise HTTPException(
            status_code=404,
            detail=f"Security incident with ID {incident_id} not found.",
        )

    return {
        "status": "success",
        "message": f"Incident {incident_id} status updated to '{update_data.status}'.",
        "incident": updated,
    }
