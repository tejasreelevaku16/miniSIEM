"""
Mini-SIEM detection engine.

Applies detection rules to parsed LogEvent objects and produces Alert objects.
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
    Assigns a severity rating based on the number of failed attempts.

    Args:
        failure_count: Total failed attempts in the detection window.

    Returns:
        'HIGH' for 5 or more failures, 'MEDIUM' for 3 or 4 failures.
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
    Detects brute-force login attempts using a rolling time window.

    Rule: If a single source IP generates at least `threshold` LOGIN_FAILED
    events within any `window_minutes` duration, an Alert is generated.

    Args:
        events: List of parsed LogEvent objects.
        threshold: Minimum number of failed attempts to trigger an alert (default: 3).
        window_minutes: Size of the rolling window in minutes (default: 5).

    Returns:
        List of Alert objects describing detected suspicious activity, sorted
        chronologically by alert start time.
    """
    window_delta = timedelta(minutes=window_minutes)

    # 1. Filter for failed login events
    failed_events = [e for e in events if e.event_type == "LOGIN_FAILED"]

    # 2. Group failed events by source IP
    events_by_ip: dict[str, list[LogEvent]] = {}
    for event in failed_events:
        events_by_ip.setdefault(event.source_ip, []).append(event)

    alerts: list[Alert] = []

    # 3. Analyze each IP's events chronologically
    for source_ip, ip_events in events_by_ip.items():
        # Ensure chronological ordering by timestamp
        ip_events.sort(key=lambda e: e.timestamp)

        i = 0
        n = len(ip_events)

        # Sliding window analysis over the chronological failures
        while i < n:
            start_event = ip_events[i]
            window_limit = start_event.timestamp + window_delta

            # Collect all failures starting at start_event and within window_delta
            window_cluster: list[LogEvent] = []
            for j in range(i, n):
                if ip_events[j].timestamp <= window_limit:
                    window_cluster.append(ip_events[j])
                else:
                    # Since ip_events is sorted, we can stop checking further
                    break

            # If the failures in this rolling window reach the threshold, generate an alert
            if len(window_cluster) >= threshold:
                first_event = window_cluster[0]
                last_event = window_cluster[-1]
                failure_count = len(window_cluster)
                severity = determine_severity(failure_count)
                targeted_users = sorted(list(set(e.username for e in window_cluster)))

                duration_seconds = (last_event.timestamp - first_event.timestamp).total_seconds()
                description = (
                    f"Possible Brute-Force attack: {failure_count} failed logins "
                    f"detected within {int(duration_seconds)}s (window: {window_minutes}m)."
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

                # Advance index past this cluster to avoid duplicate alerts for the same burst
                i += len(window_cluster)
            else:
                # Less than threshold; advance by 1 to check the next rolling start point
                i += 1

    # Sort alerts chronologically by window_start
    alerts.sort(key=lambda a: a.window_start)
    return alerts