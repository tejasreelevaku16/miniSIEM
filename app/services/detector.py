"""
Mini-SIEM Log Ingestion and Brute-Force Detection Engine.

This module provides data models and functions to load authentication logs
from a CSV file, validate individual log rows, and detect suspicious login activity
(such as brute-force attacks) using a rolling time window.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta
import csv
from pathlib import Path
from typing import Optional


@dataclass
class LogEvent:
    """Represents a single parsed and validated authentication log entry."""
    timestamp: datetime
    source_ip: str
    username: str
    event_type: str


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


def parse_timestamp(timestamp_str: str) -> Optional[datetime]:
    """
    Safely parses a timestamp string into a datetime object.

    Supports common formats such as:
    - '2026-10-20 09:00:15'
    - '2026-10-20T09:00:15'

    Returns:
        A datetime object if valid, or None if the format is unparseable.
    """
    cleaned = timestamp_str.strip()
    if not cleaned:
        return None

    # Try ISO-8601 parsing first (fast and standard in Python 3.10+)
    try:
        return datetime.fromisoformat(cleaned)
    except ValueError:
        pass

    # Fallback to explicit common formats
    formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(cleaned, fmt)
        except ValueError:
            continue

    return None


def parse_log_row(row: dict[str, str], row_number: int) -> tuple[Optional[LogEvent], Optional[str]]:
    """
    Validates a single CSV dictionary row and converts it to a LogEvent.

    Args:
        row: Dictionary of column name to string value from csv.DictReader.
        row_number: 1-indexed row number in the CSV file for error reporting.

    Returns:
        A tuple of (LogEvent, None) if parsing succeeded,
        or (None, warning_message) if the row is invalid.
    """
    required_fields = ["timestamp", "source_ip", "username", "event_type"]

    # 1. Verify all expected columns are present
    for field in required_fields:
        if field not in row or row[field] is None:
            return None, f"Row {row_number}: Missing required column '{field}'."

    timestamp_raw = row["timestamp"].strip()
    source_ip = row["source_ip"].strip()
    username = row["username"].strip()
    event_type = row["event_type"].strip().upper()

    # 2. Check for empty values
    if not timestamp_raw or not source_ip or not username or not event_type:
        return None, f"Row {row_number}: Contains empty value(s) in required fields."

    # 3. Parse timestamp
    parsed_time = parse_timestamp(timestamp_raw)
    if parsed_time is None:
        return None, f"Row {row_number}: Malformed timestamp '{timestamp_raw}'."

    # 4. Construct LogEvent
    event = LogEvent(
        timestamp=parsed_time,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
    )
    return event, None


def load_logs(file_path: str | Path) -> tuple[list[LogEvent], list[str]]:
    """
    Loads and parses authentication events from a CSV log file.

    Handles missing files, unreadable paths, and skips malformed rows gracefully
    without stopping execution.

    Args:
        file_path: Path to the CSV file.

    Returns:
        A tuple containing:
        - List of successfully parsed LogEvent objects.
        - List of warning/error messages encountered during loading and parsing.
    """
    path = Path(file_path)
    events: list[LogEvent] = []
    warnings: list[str] = []

    if not path.exists():
        warnings.append(f"Log file not found: '{file_path}'")
        return events, warnings

    if not path.is_file():
        warnings.append(f"Target path is not a file: '{file_path}'")
        return events, warnings

    try:
        with path.open(mode="r", encoding="utf-8", errors="replace") as csvfile:
            reader = csv.DictReader(csvfile)

            # Check if header contains required columns
            if reader.fieldnames is None:
                warnings.append(f"Log file '{file_path}' is empty.")
                return events, warnings

            # Normalize header names (lowercase, stripped)
            normalized_fieldnames = [f.strip().lower() for f in reader.fieldnames if f]
            expected = {"timestamp", "source_ip", "username", "event_type"}
            if not expected.issubset(set(normalized_fieldnames)):
                missing = expected - set(normalized_fieldnames)
                warnings.append(f"Header in '{file_path}' is missing expected columns: {missing}")
                return events, warnings

            # Iterate over rows
            # row_number starts at 2 (1 is the header)
            for row_num, row in enumerate(reader, start=2):
                # Normalize keys in row
                clean_row = {k.strip().lower(): v for k, v in row.items() if k is not None}
                event, warning = parse_log_row(clean_row, row_num)
                if warning:
                    warnings.append(warning)
                elif event:
                    events.append(event)

    except PermissionError:
        warnings.append(f"Permission denied accessing file: '{file_path}'")
    except Exception as exc:
        warnings.append(f"Unexpected error reading '{file_path}': {exc}")

    return events, warnings


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
