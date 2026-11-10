
"""
Mini-SIEM SQLite Database Storage Module.

This module provides persistence for:
- Security incidents
- Uploaded log file metadata
- Parsed security events

It supports:
- Automatic database initialization
- Non-destructive schema migrations
- SHA-256 file-level duplicate detection
- Event-level duplicate prevention
- Parameterized SQL queries
"""

from datetime import datetime
from pathlib import Path
import sqlite3
from typing import Optional

from app.services.csv_parser import LogEvent
from app.services.detection_engine import Alert


DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "minisiem.db"


def get_db_connection(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> sqlite3.Connection:
    """
    Create and return a SQLite database connection.
    """

    db_str = str(db_path)

    if db_str != ":memory:":
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(db_str)
    conn.execute("PRAGMA foreign_keys = ON;")

    return conn


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    """
    Initialize database tables and perform safe schema migrations.

    Existing tables and records are preserved.
    """

    conn = get_db_connection(db_path)

    try:
        with conn:

            cursor = conn.cursor()

            # --------------------------------------------------
            # 1. INCIDENTS TABLE
            # --------------------------------------------------

            cursor.execute("""
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

                    CONSTRAINT uq_incident
                    UNIQUE (source_ip, window_start, window_end)
                );
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_window_start
                ON incidents(window_start);
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_incidents_source_ip
                ON incidents(source_ip);
            """)

            # --------------------------------------------------
            # 2. UPLOADED LOGS TABLE
            # --------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS uploaded_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    filename TEXT NOT NULL,
                    upload_timestamp TEXT NOT NULL,
                    total_rows INTEGER NOT NULL,
                    valid_events INTEGER NOT NULL,
                    rejected_rows INTEGER NOT NULL
                );
            """)

            # --------------------------------------------------
            # 3. SECURITY EVENTS TABLE
            # --------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS security_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    upload_id INTEGER,
                    timestamp TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    username TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    created_at TEXT NOT NULL,

                    FOREIGN KEY(upload_id)
                    REFERENCES uploaded_logs(id)
                    ON DELETE SET NULL,

                    CONSTRAINT uq_security_event
                    UNIQUE (timestamp, source_ip, username, event_type)
                );
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_events_timestamp
                ON security_events(timestamp);
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_security_events_source_ip
                ON security_events(source_ip);
            """)

            # --------------------------------------------------
            # 4. DATABASE MIGRATIONS
            # --------------------------------------------------
            # Add missing columns without deleting existing data.

            uploaded_columns = {
                row[1]
                for row in cursor.execute(
                    "PRAGMA table_info(uploaded_logs)"
                ).fetchall()
            }

            if "file_hash" not in uploaded_columns:
                cursor.execute("""
                    ALTER TABLE uploaded_logs
                    ADD COLUMN file_hash TEXT;
                """)

            event_columns = {
                row[1]
                for row in cursor.execute(
                    "PRAGMA table_info(security_events)"
                ).fetchall()
            }

            if "source" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN source TEXT;
                """)

            if "outcome" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN outcome TEXT;
                """)

            if "user_agent" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN user_agent TEXT;
                """)

            # --------------------------------------------------
            # 5. FILE HASH UNIQUE INDEX
            # --------------------------------------------------

            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS
                idx_uploaded_logs_file_hash
                ON uploaded_logs(file_hash);
            """)

            # Transaction is committed by the connection context manager.

    finally:
        conn.close()


def format_dt(dt: datetime) -> str:
    """
    Convert datetime objects into a consistent timestamp format.
    """

    return dt.strftime("%Y-%m-%d %H:%M:%S")


# ============================================================
# INCIDENT FUNCTIONS
# ============================================================

def save_alerts(
    alerts: list[Alert],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[int, int]:
    """
    Save detected security alerts as incidents.

    Returns:
        (saved_count, duplicate_count)
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

                usernames_str = (
                    ", ".join(alert.targeted_usernames)
                    if alert.targeted_usernames
                    else ""
                )

                cursor.execute("""
                    INSERT OR IGNORE INTO incidents (
                        source_ip,
                        failure_count,
                        window_start,
                        window_end,
                        severity,
                        description,
                        targeted_usernames,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    alert.source_ip,
                    alert.failure_count,
                    start_str,
                    end_str,
                    alert.severity,
                    alert.description,
                    usernames_str,
                    record_time,
                ))

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
    Retrieve all incidents in chronological order.
    """

    init_db(db_path)

    order_direction = "ASC" if ascending else "DESC"

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT
                id,
                source_ip,
                failure_count,
                window_start,
                window_end,
                severity,
                description,
                targeted_usernames,
                created_at
            FROM incidents
            ORDER BY
                window_start {order_direction},
                id {order_direction};
        """)

        return [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()


def count_incidents(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """
    Count stored incidents.
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


# ============================================================
# UPLOADED LOG FILE FUNCTIONS
# ============================================================

def get_uploaded_log_by_hash(
    file_hash: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> Optional[dict]:
    """
    Find an uploaded file using its SHA-256 hash.

    Returns:
        Existing upload information if found, otherwise None.
    """

    if not file_hash:
        return None

    init_db(db_path)

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                filename,
                upload_timestamp,
                total_rows,
                valid_events,
                rejected_rows,
                file_hash
            FROM uploaded_logs
            WHERE file_hash = ?;
        """, (file_hash,))

        row = cursor.fetchone()

        return dict(row) if row else None

    finally:
        conn.close()


def save_uploaded_log(
    filename: str,
    total_rows: int,
    valid_events: int,
    rejected_rows: int,
    db_path: str | Path = DEFAULT_DB_PATH,
    file_hash: Optional[str] = None,
) -> int:
    """
    Save uploaded log file metadata.

    file_hash:
        Optional SHA-256 hash of the uploaded file.

    Returns:
        Newly created upload record ID.

    Raises:
        sqlite3.IntegrityError if a duplicate non-null file hash
        violates the unique index.
    """

    init_db(db_path)

    conn = get_db_connection(db_path)

    try:
        with conn:
            cursor = conn.cursor()

            upload_time = format_dt(datetime.now())

            cursor.execute("""
                INSERT INTO uploaded_logs (
                    filename,
                    upload_timestamp,
                    total_rows,
                    valid_events,
                    rejected_rows,
                    file_hash
                )
                VALUES (?, ?, ?, ?, ?, ?);
            """, (
                filename,
                upload_time,
                total_rows,
                valid_events,
                rejected_rows,
                file_hash,
            ))

            return int(cursor.lastrowid)

    finally:
        conn.close()


# ============================================================
# SECURITY EVENT FUNCTIONS
# ============================================================

def save_security_events(
    events: list[LogEvent],
    upload_id: Optional[int] = None,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[int, int]:
    """
    Save parsed security events.

    Uses event-level duplicate prevention.

    Returns:
        (saved_count, duplicate_count)
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

                # getattr keeps compatibility with the current
                # LogEvent class until its new fields are added.

                source = getattr(event, "source", None)
                outcome = getattr(event, "outcome", None)
                user_agent = getattr(event, "user_agent", None)

                cursor.execute("""
                    INSERT OR IGNORE INTO security_events (
                        upload_id,
                        timestamp,
                        source_ip,
                        username,
                        event_type,
                        created_at,
                        source,
                        outcome,
                        user_agent
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    upload_id,
                    event_time_str,
                    event.source_ip,
                    event.username,
                    event.event_type,
                    created_time,
                    source,
                    outcome,
                    user_agent,
                ))

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
    Retrieve security events with pagination.
    """

    init_db(db_path)

    order_direction = "ASC" if ascending else "DESC"

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute(f"""
            SELECT
                id,
                upload_id,
                timestamp,
                source_ip,
                username,
                event_type,
                created_at,
                source,
                outcome,
                user_agent
            FROM security_events
            ORDER BY
                timestamp {order_direction},
                id {order_direction}
            LIMIT ? OFFSET ?;
        """, (limit, offset))

        return [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()


def count_security_events(
    db_path: str | Path = DEFAULT_DB_PATH,
) -> int:
    """
    Count stored security events.
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
