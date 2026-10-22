"""
Mini-SIEM SQLite Database Storage Module.

This module provides persistence for security incidents detected by the Mini-SIEM engine.
It uses Python's built-in `sqlite3` module to manage database connections, table schemas,
and incident records using parameterized SQL queries and database-enforced deduplication.
"""

from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Optional

from detector import Alert, LogEvent

DEFAULT_DB_PATH = Path(__file__).parent / "minisiem.db"


def get_db_connection(db_path: str | Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    """
    Creates and returns a connection to the SQLite database.

    Ensures the parent directory exists if a filesystem path is specified.

    Args:
        db_path: Filepath to the SQLite database or ':memory:'.

    Returns:
        sqlite3.Connection: Active database connection.
    """
    db_str = str(db_path)
    if db_str != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_str)
    # Enable foreign key support and column access by name
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """
    Initializes the database schema and creates the `incidents` table if it does not exist.

    Table Schema:
        - id: INTEGER PRIMARY KEY AUTOINCREMENT
        - source_ip: TEXT NOT NULL (Attacking IP address)
        - failure_count: INTEGER NOT NULL (Number of failed attempts in window)
        - window_start: TEXT NOT NULL (ISO timestamp of first attempt)
        - window_end: TEXT NOT NULL (ISO timestamp of last attempt)
        - severity: TEXT NOT NULL (MEDIUM or HIGH)
        - description: TEXT NOT NULL (Human-readable event summary)
        - targeted_usernames: TEXT NOT NULL (Comma-separated list of probed accounts)
        - created_at: TEXT NOT NULL (Timestamp when recorded in DB)

    Deduplication Constraint:
        UNIQUE(source_ip, window_start, window_end) prevents saving duplicate
        records if the detection engine reprocesses the same attack window.
    """
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_ip TEXT NOT NULL,
                    failure_count INTEGER NOT NULL,
                    window_start TEXT NOT NULL,
                    window_end TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    targeted_usernames TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    CONSTRAINT uq_incident UNIQUE (source_ip, window_start, window_end)
                );
                """
            )
            # Create indexes for fast chronological retrieval and IP search
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_incidents_window_start
                ON incidents(window_start);
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
                ON incidents(source_ip);
                """
            )

            # Week 1: Raw log upload metadata table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS uploaded_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    upload_timestamp TEXT NOT NULL,
                    total_rows INTEGER NOT NULL,
                    valid_events INTEGER NOT NULL,
                    rejected_rows INTEGER NOT NULL
                );
                """
            )

            # Week 1: Parsed security events table
            cursor.execute(
                """
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(upload_id) REFERENCES uploaded_logs(id) ON DELETE SET NULL,
                    CONSTRAINT uq_security_event UNIQUE (timestamp, source_ip, username, event_type)
                );
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
                ON security_events(timestamp);
                """
            )
            cursor.execute(
                """
                CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
                ON security_events(source_ip);
                """
            )
    finally:
        conn.close()


def format_dt(dt: datetime) -> str:
    """Standardizes datetime objects into ISO-8601 strings (YYYY-MM-DD HH:MM:SS)."""
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def save_alerts(
    alerts: list[Alert],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[int, int]:
    """
    Persists a list of Alert instances into the incidents table.

    Uses parameterized queries and INSERT OR IGNORE based on the UNIQUE constraint
    (source_ip, window_start, window_end) to prevent duplicate rows.

    Args:
        alerts: List of Alert objects from the detection engine.
        db_path: Filepath to the SQLite database.

    Returns:
        tuple[int, int]: (saved_count, duplicate_count)
    """
    if not alerts:
        return 0, 0

    init_db(db_path)
    saved_count = 0
    duplicate_count = 0

    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            record_time = format_dt(datetime.now())

            for alert in alerts:
                start_str = format_dt(alert.window_start)
                end_str = format_dt(alert.window_end)
                usernames_str = ", ".join(alert.targeted_usernames) if alert.targeted_usernames else ""

                # Parameterized query with ? placeholders protects against SQL injection
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO incidents (
                        source_ip,
                        failure_count,
                        window_start,
                        window_end,
                        severity,
                        description,
                        targeted_usernames,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        alert.source_ip,
                        alert.failure_count,
                        start_str,
                        end_str,
                        alert.severity,
                        alert.description,
                        usernames_str,
                        record_time,
                    ),
                )

                # cursor.rowcount is 1 if inserted, 0 if ignored as duplicate
                if cursor.rowcount > 0:
                    saved_count += 1
                else:
                    duplicate_count += 1
    finally:
        conn.close()

    return saved_count, duplicate_count


def get_all_incidents(
    db_path: str | Path = DEFAULT_DB_PATH,
    ascending: bool = True,
) -> list[dict]:
    """
    Retrieves all stored incidents from the database ordered chronologically.

    Args:
        db_path: Filepath to the SQLite database.
        ascending: True to order oldest to newest (ASC), False for newest to oldest (DESC).

    Returns:
        list[dict]: List of incident dictionaries with column names as keys.
    """
    init_db(db_path)
    order_direction = "ASC" if ascending else "DESC"

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row  # Enables column-access by dictionary keys
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            SELECT id, source_ip, failure_count, window_start, window_end,
                   severity, description, targeted_usernames, created_at
            FROM incidents
            ORDER BY window_start {order_direction}, id {order_direction};
            """
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def count_incidents(db_path: str | Path = DEFAULT_DB_PATH) -> int:
    """
    Counts the total number of incidents saved in the database.

    Args:
        db_path: Filepath to the SQLite database.

    Returns:
        int: Total number of records in the incidents table.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM incidents;")
        result = cursor.fetchone()
        return int(result[0]) if result else 0
    finally:
        conn.close()


def save_uploaded_log(
    filename: str,
    total_rows: int,
    valid_events: int,
    rejected_rows: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """
    Records an uploaded log file's metadata and ingestion metrics.

    Args:
        filename: Name of the uploaded file.
        total_rows: Number of data rows processed.
        valid_events: Number of successfully parsed security events.
        rejected_rows: Number of malformed/invalid rows skipped.
        db_path: Filepath to the SQLite database.

    Returns:
        int: The newly generated upload record ID (primary key).
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            upload_time = format_dt(datetime.now())
            cursor.execute(
                """
                INSERT INTO uploaded_logs (
                    filename,
                    upload_timestamp,
                    total_rows,
                    valid_events,
                    rejected_rows
                ) VALUES (?, ?, ?, ?, ?);
                """,
                (filename, upload_time, total_rows, valid_events, rejected_rows),
            )
            return int(cursor.lastrowid)
    finally:
        conn.close()


def save_security_events(
    events: list[LogEvent],
    upload_id: Optional[int] = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[int, int]:
    """
    Persists parsed LogEvent objects into the security_events table.

    Uses parameterized queries and INSERT OR IGNORE based on the UNIQUE constraint
    (timestamp, source_ip, username, event_type) to prevent storing duplicate events.

    Args:
        events: List of parsed LogEvent objects.
        upload_id: Optional ID referencing the uploaded_logs table.
        db_path: Filepath to the SQLite database.

    Returns:
        tuple[int, int]: (saved_count, duplicate_count)
    """
    if not events:
        return 0, 0

    init_db(db_path)
    saved_count = 0
    duplicate_count = 0

    conn = get_db_connection(db_path)
    try:
        with conn:
            cursor = conn.cursor()
            created_time = format_dt(datetime.now())

            for event in events:
                event_time_str = format_dt(event.timestamp)
                cursor.execute(
                    """
                    INSERT OR IGNORE INTO security_events (
                        upload_id,
                        timestamp,
                        source_ip,
                        username,
                        event_type,
                        created_at
                    ) VALUES (?, ?, ?, ?, ?, ?);
                    """,
                    (
                        upload_id,
                        event_time_str,
                        event.source_ip,
                        event.username,
                        event.event_type,
                        created_time,
                    ),
                )
                if cursor.rowcount > 0:
                    saved_count += 1
                else:
                    duplicate_count += 1
    finally:
        conn.close()

    return saved_count, duplicate_count


def get_security_events(
    limit: int = 100,
    offset: int = 0,
    db_path: str | Path = DEFAULT_DB_PATH,
    ascending: bool = True,
) -> list[dict]:
    """
    Retrieves parsed security events from the database ordered chronologically.

    Args:
        limit: Maximum number of records to return.
        offset: Number of records to skip (for pagination).
        db_path: Filepath to the SQLite database.
        ascending: True for oldest to newest, False for newest first.

    Returns:
        list[dict]: List of security event dictionaries.
    """
    init_db(db_path)
    order_direction = "ASC" if ascending else "DESC"

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row
    try:
        cursor = conn.cursor()
        cursor.execute(
            f"""
            SELECT id, upload_id, timestamp, source_ip, username, event_type, created_at
            FROM security_events
            ORDER BY timestamp {order_direction}, id {order_direction}
            LIMIT ? OFFSET ?;
            """,
            (limit, offset),
        )
        rows = cursor.fetchall()
        return [dict(row) for row in rows]
    finally:
        conn.close()


def count_security_events(db_path: str | Path = DEFAULT_DB_PATH) -> int:
    """
    Counts the total number of security events stored in the database.

    Args:
        db_path: Filepath to the SQLite database.

    Returns:
        int: Total number of records in the security_events table.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM security_events;")
        result = cursor.fetchone()
        return int(result[0]) if result else 0
    finally:
        conn.close()

