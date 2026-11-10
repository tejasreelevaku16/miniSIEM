
import csv
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class LogEvent:
    """Represents one parsed security log event."""

    timestamp: datetime
    source_ip: str
    username: str
    event_type: str
    source: str = ""
    outcome: str = ""
    user_agent: Optional[str] = None


# Required columns for the old CSV format.
LEGACY_REQUIRED_FIELDS = {
    "timestamp",
    "source_ip",
    "username",
    "event_type",
}

# Required columns for the new CSV format.
NEW_REQUIRED_FIELDS = {
    "timestamp",
    "source",
    "username",
    "source_ip",
    "event_type",
    "outcome",
}

ALLOWED_OUTCOMES = {
    "success",
    "failure",
    "blocked",
}


def parse_timestamp(timestamp_value: str) -> Optional[datetime]:
    """
    Convert a timestamp string into a datetime object.

    Supports ISO 8601 and common legacy timestamp formats.
    """

    if not timestamp_value:
        return None

    timestamp_value = timestamp_value.strip()

    # First try ISO 8601.
    try:
        return datetime.fromisoformat(
            timestamp_value.replace("Z", "+00:00")
        )
    except ValueError:
        pass

    # Try common timestamp formats.
    supported_formats = [
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y/%m/%d %H:%M:%S",
        "%d-%m-%Y %H:%M:%S",
    ]

    for timestamp_format in supported_formats:
        try:
            return datetime.strptime(
                timestamp_value,
                timestamp_format,
            )
        except ValueError:
            continue

    return None


def parse_log_row(
    row: dict,
    row_number: int = 1,
):
    """
    Parse one CSV row into a LogEvent.

    Supports:
    - Legacy CSV format with four required columns.
    - New CSV format with source and outcome information.

    Returns:
        (LogEvent, None) when successful.
        (None, warning_message) when invalid.
    """

    # Normalize column names and values.
    normalized_row = {
        str(key).strip().lower(): (
            value.strip() if isinstance(value, str) else value
        )
        for key, value in row.items()
        if key is not None
    }

    # Determine which CSV format is being used.
    is_new_format = (
        "source" in normalized_row
        or "outcome" in normalized_row
    )

    required_fields = (
        NEW_REQUIRED_FIELDS
        if is_new_format
        else LEGACY_REQUIRED_FIELDS
    )

    # Validate required columns.
    missing_fields = required_fields - set(normalized_row.keys())

    if missing_fields:
        return None, (
            f"Row {row_number}: Missing required column(s): "
            f"{', '.join(sorted(missing_fields))}."
        )

    # Validate required values.
    empty_fields = {
        field
        for field in required_fields
        if not normalized_row.get(field)
    }

    if empty_fields:
        return None, (
            f"Row {row_number}: Empty value for required field(s): "
            f"{', '.join(sorted(empty_fields))}."
        )

    # Validate timestamp.
    timestamp_raw = normalized_row["timestamp"]

    timestamp = parse_timestamp(timestamp_raw)

    if timestamp is None:
        return None, (
            f"Row {row_number}: Malformed timestamp "
            f"'{timestamp_raw}'."
        )

    # Extract common fields.
    source_ip = normalized_row["source_ip"]
    username = normalized_row["username"]
    event_type = normalized_row["event_type"].upper()

    # Extract new-format fields.
    if is_new_format:

        source = normalized_row["source"]
        outcome = normalized_row["outcome"].lower()

        if outcome not in ALLOWED_OUTCOMES:
            return None, (
                f"Row {row_number}: Invalid outcome "
                f"'{outcome}'. Allowed values: "
                f"{', '.join(sorted(ALLOWED_OUTCOMES))}."
            )

    else:
        # Maintain compatibility with the old CSV format.
        source = "legacy"

        if event_type == "LOGIN_FAILED":
            outcome = "failure"
        elif event_type == "LOGIN_SUCCESS":
            outcome = "success"
        else:
            outcome = ""

    # User agent is optional.
    user_agent = normalized_row.get("user_agent") or None

    # Create the LogEvent.
    event = LogEvent(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        event_type=event_type,
        source=source,
        outcome=outcome,
        user_agent=user_agent,
    )

    return event, None


def load_logs(file_path: str):
    """
    Load and parse security events from a CSV file.

    Returns:
        events: List of valid LogEvent objects.
        warnings: List of errors for rejected rows.
    """

    path = Path(file_path)

    events: list[LogEvent] = []
    warnings: list[str] = []

    # Check whether the file exists.
    if not path.exists():
        return [], [f"File not found: {file_path}"]

    # Check whether the file is empty.
    if path.stat().st_size == 0:
        return [], ["CSV file is empty."]

    try:
        with path.open(
            mode="r",
            encoding="utf-8-sig",
            newline="",
        ) as csv_file:

            reader = csv.DictReader(csv_file)

            # Check whether a header exists.
            if reader.fieldnames is None:
                return [], ["CSV file is missing a header row."]

            # Normalize header names.
            headers = {
                header.strip().lower()
                for header in reader.fieldnames
                if header is not None
            }

            # Detect CSV format.
            is_new_format = (
                "source" in headers
                or "outcome" in headers
            )

            required_fields = (
                NEW_REQUIRED_FIELDS
                if is_new_format
                else LEGACY_REQUIRED_FIELDS
            )

            # Validate header columns.
            missing_fields = required_fields - headers

            if missing_fields:
                return [], [
                    "Missing required column(s): "
                    + ", ".join(sorted(missing_fields))
                    + "."
                ]

            # Parse each CSV row.
            for row_number, row in enumerate(reader, start=2):

                event, warning = parse_log_row(
                    row,
                    row_number,
                )

                if warning:
                    warnings.append(warning)
                    continue

                if event is not None:
                    events.append(event)

    except UnicodeDecodeError:
        return [], ["CSV file is not valid UTF-8 text."]

    except csv.Error as error:
        return [], [f"CSV parsing error: {error}"]

    return events, warnings
