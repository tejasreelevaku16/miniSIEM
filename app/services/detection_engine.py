
"""
Mini-SIEM detection engine.

Applies detection rules to parsed LogEvent objects
and produces security alerts.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta

from app.services.csv_parser import LogEvent


@dataclass
class Alert:
    """Represents a security alert produced by detection rules."""

    source_ip: str
    failure_count: int
    window_start: datetime
    window_end: datetime
    severity: str
    description: str
    targeted_usernames: list[str]


def determine_severity(failure_count: int) -> str:
    """
    Assign a severity rating based on failed login attempts.

    HIGH: 5 or more failures.
    MEDIUM: 3 or 4 failures.
    """

    if failure_count >= 5:
        return "HIGH"

    return "MEDIUM"


def detect_brute_force(
    events: list[LogEvent],
    threshold: int = 3,
    window_minutes: int = 5,
) -> list[Alert]:
    """
    Detect brute-force login attempts using a rolling time window.

    Detection rule:
    If a single source IP generates at least `threshold`
    failed login events within `window_minutes`, generate an alert.

    Supports both:
    1. Legacy format: event_type = LOGIN_FAILED
    2. New format: event_type = LOGIN, outcome = failure
    """

    window_delta = timedelta(minutes=window_minutes)

    # Step 1: Identify failed login events.
    failed_events = [
        event
        for event in events
        if (
            event.event_type.upper() == "LOGIN_FAILED"
            or (
                event.event_type.upper() == "LOGIN"
                and event.outcome.lower() == "failure"
            )
        )
    ]

    # Step 2: Group failed events by source IP.
    events_by_ip: dict[str, list[LogEvent]] = {}

    for event in failed_events:
        events_by_ip.setdefault(event.source_ip, []).append(event)

    alerts: list[Alert] = []

    # Step 3: Analyze each IP's events chronologically.
    for source_ip, ip_events in events_by_ip.items():

        ip_events.sort(key=lambda event: event.timestamp)

        i = 0
        n = len(ip_events)

        # Step 4: Apply the sliding time window.
        while i < n:

            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            window_cluster: list[LogEvent] = []

            for j in range(i, n):

                if ip_events[j].timestamp <= window_limit:
                    window_cluster.append(ip_events[j])
                else:
                    break

            # Step 5: Check whether the threshold is reached.
            if len(window_cluster) >= threshold:

                first_event = window_cluster[0]
                last_event = window_cluster[-1]

                failure_count = len(window_cluster)

                severity = determine_severity(failure_count)

                targeted_users = sorted(
                    set(event.username for event in window_cluster)
                )

                duration_seconds = (
                    last_event.timestamp - first_event.timestamp
                ).total_seconds()

                description = (
                    f"Possible Brute-Force attack: "
                    f"{failure_count} failed logins detected "
                    f"within {int(duration_seconds)}s "
                    f"(window: {window_minutes}m)."
                )

                alert = Alert(
                    source_ip=source_ip,
                    failure_count=failure_count,
                    window_start=first_event.timestamp,
                    window_end=last_event.timestamp,
                    severity=severity,
                    description=description,
                    targeted_usernames=targeted_users,
                )

                alerts.append(alert)

                # Move past this detected cluster to avoid
                # duplicate alerts for the same burst.
                i += len(window_cluster)

            else:
                i += 1

    # Step 6: Sort alerts chronologically.
    alerts.sort(key=lambda alert: alert.window_start)

    return alerts
