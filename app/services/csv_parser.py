"""
Mini-SIEM CSV parsing and validation.

Turns raw CSV rows into validated LogEvent objects. Malformed rows are
reported as warnings instead of crashing the application.
"""

from dataclasses import dataclass
from datetime import datetime
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