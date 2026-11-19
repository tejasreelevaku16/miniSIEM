"""
Pydantic Request and Response Schemas for Mini-SIEM API.
"""

from datetime import datetime
from typing import Any, Optional
from pydantic import BaseModel, Field, field_validator


class IncidentStatusUpdate(BaseModel):
    """Schema for updating an incident's lifecycle status."""

    status: str = Field(
        ...,
        description="Updated status: 'Open', 'Investigating', 'Resolved', or 'False Positive'",
    )

    @field_validator("status")
    @classmethod
    def validate_status(cls, value: str) -> str:
        allowed = {"Open", "Investigating", "Resolved", "False Positive"}
        clean = value.strip()
        for valid in allowed:
            if clean.lower() == valid.lower():
                return valid
        raise ValueError(
            f"Invalid status '{value}'. Allowed: {', '.join(sorted(allowed))}"
        )


class AlertSchema(BaseModel):
    """Schema representing an individual detection alert."""

    id: Optional[int] = None
    rule_id: str
    rule_name: str
    source_ip: str
    username: Optional[str] = None
    event_count: int
    first_observed: str
    last_observed: str
    severity: str
    description: str
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None
    incident_id: Optional[int] = None
    created_at: str


class IncidentSummarySchema(BaseModel):
    """Schema representing a summarized incident in the incident feed."""

    id: int
    source_ip: str
    failure_count: int
    window_start: str
    window_end: str
    severity: str
    status: str
    description: str
    targeted_usernames: str
    rule_id: str
    mitre_technique: str
    recommended_action: str
    created_at: str
    updated_at: Optional[str] = None


class IncidentDetailSchema(IncidentSummarySchema):
    """Schema representing full incident details including related alerts and timeline events."""

    alerts: list[dict[str, Any]] = Field(default_factory=list)
    events: list[dict[str, Any]] = Field(default_factory=list)


class DashboardStatsSchema(BaseModel):
    """Schema for overall SOC overview metrics and chart telemetry."""

    total_events: int
    total_alerts: int
    total_incidents: int
    open_incidents: int
    high_critical_incidents: int
    outcomes: dict[str, int]
    events_by_source: dict[str, int]
    alerts_by_severity: dict[str, int]
    incidents_by_status: dict[str, int]
    top_suspicious_ips: list[dict[str, Any]]
    events_timeline: list[dict[str, Any]]
