"""
Mini-SIEM Incidents Router.

Endpoints for:
- Listing security incidents with status/severity filters (GET /api/incidents)
- Inspecting a single incident with timeline & alert breakdown (GET /api/incidents/{incident_id})
- Updating an incident's lifecycle status (PATCH /api/incidents/{incident_id})
"""

from datetime import datetime
import json
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Response

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


@router.get("/{incident_id}/export")
def export_incident_report(
    incident_id: int,
    format: str = Query(default="markdown", description="Report format: 'markdown' or 'json'"),
    db_path: Path = Depends(get_db_path),
) -> Response:
    """
    Exports a comprehensive SOC incident investigation briefing report
    as a downloadable Markdown or JSON file.
    """
    incident = get_incident_by_id(incident_id, db_path=db_path)
    if not incident:
        raise HTTPException(
            status_code=404,
            detail=f"Security incident with ID {incident_id} not found.",
        )

    if format.lower() == "json":
        content = json.dumps(incident, indent=2, default=str)
        filename = f"incident_{incident_id}_report.json"
        media_type = "application/json"
    else:
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        alerts_list = incident.get("alerts", [])
        events_list = incident.get("events", [])

        alerts_rows = "\n".join(
            f"| #{a.get('id', 'N/A')} | {a.get('rule_id', 'N/A')} | {a.get('rule_name', 'N/A')} | {a.get('severity', 'N/A')} | {a.get('first_observed', '')} -> {a.get('last_observed', '')} | {a.get('event_count', 0)} |"
            for a in alerts_list
        ) if alerts_list else "| None | None | None | None | None | 0 |"

        events_rows = "\n".join(
            f"| {e.get('timestamp', '')} | {e.get('source_ip', '')} | {e.get('username') or 'N/A'} | {e.get('event_type', '')} | {e.get('outcome', '')} | {e.get('user_agent') or 'N/A'} |"
            for e in events_list[:50]
        ) if events_list else "| None | None | None | None | None | None |"

        more_events_note = f"\n*(Showing first 50 of {len(events_list)} events)*\n" if len(events_list) > 50 else ""

        md_lines = [
            f"# Mini-SIEM Security Incident Investigation Report: Incident #{incident_id}",
            "",
            f"**Generated:** {now_str}",
            f"**Classification:** TLP:AMBER (Internal SOC Use Only)",
            "",
            "---",
            "",
            "## 1. Executive Summary",
            f"- **Incident ID:** #{incident_id}",
            f"- **Severity:** {incident.get('severity', 'UNKNOWN')}",
            f"- **Status:** {incident.get('status', 'Open')}",
            f"- **Source IP:** `{incident.get('source_ip', 'N/A')}`",
            f"- **Targeted Accounts:** {incident.get('targeted_usernames') or 'None'}",
            f"- **Rules Triggered:** {incident.get('rule_id', 'N/A')}",
            f"- **MITRE ATT&CK:** {incident.get('mitre_technique', 'N/A')}",
            f"- **Attack Window:** {incident.get('window_start', '')} -> {incident.get('window_end', '')}",
            f"- **Aggregated Event Count:** {incident.get('failure_count', 0)}",
            "",
            "## 2. Attack Description & Analysis",
            f"{incident.get('description', 'No description available.')}",
            "",
            "## 3. Recommended SOC Playbook & Remediation Actions",
            f"> {incident.get('recommended_action', 'Review logs and quarantine suspicious activity.')}",
            "",
            f"## 4. Associated Detection Alerts ({len(alerts_list)})",
            "| Alert ID | Rule ID | Rule Name | Severity | Time Window | Event Count |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
            alerts_rows,
            "",
            f"## 5. Raw Telemetry Timeline ({len(events_list)} Events)",
            "| Timestamp | Source IP | User | Event Type | Outcome | User-Agent |",
            "| :--- | :--- | :--- | :--- | :--- | :--- |",
            events_rows,
            more_events_note,
            "",
            "---",
            "*Report generated by Mini-SIEM Automated Incident Response Framework.*",
        ]
        content = "\n".join(md_lines)
        filename = f"incident_{incident_id}_report.md"
        media_type = "text/markdown"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
