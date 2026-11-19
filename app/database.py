
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


def get_db_path() -> Path:
    """Dependency injection provider for database path (allows test overrides)."""
    return DEFAULT_DB_PATH


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
            # 4. ALERTS TABLE
            # --------------------------------------------------

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id TEXT NOT NULL,
                    rule_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    username TEXT,
                    event_count INTEGER NOT NULL,
                    first_observed TEXT NOT NULL,
                    last_observed TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT NOT NULL,
                    mitre_technique_id TEXT,
                    mitre_technique_name TEXT,
                    incident_id INTEGER,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(incident_id) REFERENCES incidents(id) ON DELETE SET NULL
                );
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_rule_id
                ON alerts(rule_id);
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_source_ip
                ON alerts(source_ip);
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_incident_id
                ON alerts(incident_id);
            """)

            cursor.execute("""
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at
                ON alerts(created_at);
            """)

            # --------------------------------------------------
            # 5. DATABASE MIGRATIONS (Non-destructive)
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

            if "dest_ip" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN dest_ip TEXT;
                """)

            if "dest_port" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN dest_port INTEGER;
                """)

            if "protocol" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN protocol TEXT;
                """)

            if "request_path" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN request_path TEXT;
                """)

            if "status_code" not in event_columns:
                cursor.execute("""
                    ALTER TABLE security_events
                    ADD COLUMN status_code INTEGER;
                """)

            incident_columns = {
                row[1]
                for row in cursor.execute(
                    "PRAGMA table_info(incidents)"
                ).fetchall()
            }

            if "status" not in incident_columns:
                cursor.execute("""
                    ALTER TABLE incidents
                    ADD COLUMN status TEXT DEFAULT 'Open';
                """)

            if "rule_id" not in incident_columns:
                cursor.execute("""
                    ALTER TABLE incidents
                    ADD COLUMN rule_id TEXT DEFAULT 'AUTH-001';
                """)

            if "mitre_technique" not in incident_columns:
                cursor.execute("""
                    ALTER TABLE incidents
                    ADD COLUMN mitre_technique TEXT DEFAULT 'T1110';
                """)

            if "recommended_action" not in incident_columns:
                cursor.execute("""
                    ALTER TABLE incidents
                    ADD COLUMN recommended_action TEXT DEFAULT 'Investigate source IP and review authentication logs';
                """)

            if "updated_at" not in incident_columns:
                cursor.execute("""
                    ALTER TABLE incidents
                    ADD COLUMN updated_at TEXT;
                """)

            # --------------------------------------------------
            # 6. FILE HASH UNIQUE INDEX
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
# INCIDENT & ALERT PERSISTENCE
# ============================================================

VALID_INCIDENT_STATUSES = {"Open", "Investigating", "Resolved", "False Positive"}


def save_alerts(
    alerts: list[Alert],
    db_path: str | Path = DEFAULT_DB_PATH,
) -> tuple[int, int]:
    """
    Save detected security alerts as incidents and records in alerts table.

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

                status = getattr(alert, "status", "Open")
                rule_id = getattr(alert, "rule_id", "AUTH-001")
                rule_name = getattr(alert, "rule_name", "Brute-Force Login Detection")
                mitre_tech = getattr(
                    alert,
                    "mitre_attack_id",
                    getattr(alert, "mitre_technique", "T1110"),
                )
                mitre_name = getattr(alert, "mitre_attack_name", "Brute Force")
                rec_action = getattr(
                    alert,
                    "recommended_action",
                    "Investigate source IP and review authentication logs",
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
                        created_at,
                        status,
                        rule_id,
                        mitre_technique,
                        recommended_action,
                        updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    alert.source_ip,
                    alert.failure_count,
                    start_str,
                    end_str,
                    alert.severity,
                    alert.description,
                    usernames_str,
                    record_time,
                    status,
                    rule_id,
                    mitre_tech,
                    rec_action,
                    record_time,
                ))

                if cursor.rowcount > 0:
                    saved_count += 1
                    incident_id = cursor.lastrowid
                else:
                    duplicate_count += 1
                    cursor.execute("""
                        SELECT id FROM incidents
                        WHERE source_ip = ? AND window_start = ? AND window_end = ?;
                    """, (alert.source_ip, start_str, end_str))
                    match_row = cursor.fetchone()
                    incident_id = match_row[0] if match_row else None

                # Also insert into alerts table
                primary_user = (
                    alert.targeted_usernames[0]
                    if alert.targeted_usernames
                    else None
                )

                cursor.execute("""
                    INSERT INTO alerts (
                        rule_id,
                        rule_name,
                        source_ip,
                        username,
                        event_count,
                        first_observed,
                        last_observed,
                        severity,
                        description,
                        mitre_technique_id,
                        mitre_technique_name,
                        incident_id,
                        created_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
                """, (
                    rule_id,
                    rule_name,
                    alert.source_ip,
                    primary_user,
                    alert.failure_count,
                    start_str,
                    end_str,
                    alert.severity,
                    alert.description,
                    mitre_tech,
                    mitre_name,
                    incident_id,
                    record_time,
                ))

    finally:
        conn.close()

    return saved_count, duplicate_count


def get_all_incidents(
    db_path: str | Path = DEFAULT_DB_PATH,
    ascending: bool = True,
    status: Optional[str] = None,
    severity: Optional[str] = None,
) -> list[dict]:
    """
    Retrieve all incidents in chronological order with optional filters.
    """

    init_db(db_path)

    order_direction = "ASC" if ascending else "DESC"

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        conditions = []
        params = []

        if status:
            conditions.append("COALESCE(status, 'Open') = ?")
            params.append(status)

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

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
                created_at,
                COALESCE(status, 'Open') as status,
                COALESCE(rule_id, 'AUTH-001') as rule_id,
                COALESCE(mitre_technique, 'T1110') as mitre_technique,
                COALESCE(recommended_action, 'Investigate source IP and review authentication logs') as recommended_action,
                updated_at
            FROM incidents
            {where_clause}
            ORDER BY
                window_start {order_direction},
                id {order_direction};
        """, params)

        return [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()


def get_incident_by_id(
    incident_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> Optional[dict]:
    """
    Retrieve full incident details including related alerts and timeline events.
    """
    init_db(db_path)

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute("""
            SELECT
                id,
                source_ip,
                failure_count,
                window_start,
                window_end,
                severity,
                description,
                targeted_usernames,
                created_at,
                COALESCE(status, 'Open') as status,
                COALESCE(rule_id, 'AUTH-001') as rule_id,
                COALESCE(mitre_technique, 'T1110') as mitre_technique,
                COALESCE(recommended_action, 'Investigate source IP and review authentication logs') as recommended_action,
                updated_at
            FROM incidents
            WHERE id = ?;
        """, (incident_id,))

        row = cursor.fetchone()
        if not row:
            return None

        incident = dict(row)

        # Related alerts
        cursor.execute("""
            SELECT
                id,
                rule_id,
                rule_name,
                source_ip,
                username,
                event_count,
                first_observed,
                last_observed,
                severity,
                description,
                mitre_technique_id,
                mitre_technique_name,
                created_at
            FROM alerts
            WHERE incident_id = ?
            ORDER BY first_observed ASC;
        """, (incident_id,))
        incident["alerts"] = [dict(r) for r in cursor.fetchall()]

        # Related events within window
        cursor.execute("""
            SELECT
                id,
                timestamp,
                source_ip,
                username,
                event_type,
                outcome,
                source,
                user_agent
            FROM security_events
            WHERE source_ip = ?
              AND timestamp >= ?
              AND timestamp <= ?
            ORDER BY timestamp ASC;
        """, (incident["source_ip"], incident["window_start"], incident["window_end"]))
        incident["events"] = [dict(r) for r in cursor.fetchall()]

        return incident

    finally:
        conn.close()


def update_incident_status(
    incident_id: int,
    status: str,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> Optional[dict]:
    """
    Update the investigation status of an incident.
    """
    if status not in VALID_INCIDENT_STATUSES:
        raise ValueError(
            f"Invalid status '{status}'. Must be one of: {', '.join(sorted(VALID_INCIDENT_STATUSES))}"
        )

    init_db(db_path)

    conn = get_db_connection(db_path)

    try:
        with conn:
            cursor = conn.cursor()
            updated_at = format_dt(datetime.now())

            cursor.execute("""
                UPDATE incidents
                SET status = ?, updated_at = ?
                WHERE id = ?;
            """, (status, updated_at, incident_id))

            if cursor.rowcount == 0:
                return None

        return get_incident_by_id(incident_id, db_path=db_path)

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


def get_all_alerts(
    db_path: str | Path = DEFAULT_DB_PATH,
    limit: int = 100,
    offset: int = 0,
    rule_id: Optional[str] = None,
    severity: Optional[str] = None,
) -> tuple[int, list[dict]]:
    """
    Retrieve stored alerts with optional filtering and pagination.
    """
    init_db(db_path)

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()
        conditions = []
        params = []

        if rule_id:
            conditions.append("rule_id = ?")
            params.append(rule_id)

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""

        cursor.execute(f"SELECT COUNT(*) FROM alerts {where_clause};", params)
        total = int(cursor.fetchone()[0])

        query = f"""
            SELECT
                id,
                rule_id,
                rule_name,
                source_ip,
                username,
                event_count,
                first_observed,
                last_observed,
                severity,
                description,
                mitre_technique_id,
                mitre_technique_name,
                incident_id,
                created_at
            FROM alerts
            {where_clause}
            ORDER BY first_observed DESC, id DESC
            LIMIT ? OFFSET ?;
        """
        cursor.execute(query, params + [limit, offset])
        alerts = [dict(row) for row in cursor.fetchall()]

        return total, alerts

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
                dest_ip = getattr(event, "dest_ip", None)
                dest_port = getattr(event, "dest_port", None)
                protocol = getattr(event, "protocol", None)
                request_path = getattr(event, "request_path", None)
                status_code = getattr(event, "status_code", None)

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
                        user_agent,
                        dest_ip,
                        dest_port,
                        protocol,
                        request_path,
                        status_code
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
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
                    dest_ip,
                    dest_port,
                    protocol,
                    request_path,
                    status_code,
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
                user_agent,
                dest_ip,
                dest_port,
                protocol,
                request_path,
                status_code
            FROM security_events
            ORDER BY
                timestamp {order_direction},
                id {order_direction}
            LIMIT ? OFFSET ?;
        """, (limit, offset))

        return [dict(row) for row in cursor.fetchall()]

    finally:
        conn.close()


def get_security_event_by_id(
    event_id: int,
    db_path: str | Path = DEFAULT_DB_PATH,
) -> Optional[dict]:
    """
    Retrieve a single security event by its primary key ID.
    """
    init_db(db_path)

    conn = get_db_connection(db_path)
    conn.row_factory = sqlite3.Row

    try:
        cursor = conn.cursor()

        cursor.execute("""
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
                user_agent,
                dest_ip,
                dest_port,
                protocol,
                request_path,
                status_code
            FROM security_events
            WHERE id = ?;
        """, (event_id,))

        row = cursor.fetchone()
        return dict(row) if row else None

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


# ============================================================
# DASHBOARD AGGREGATIONS
# ============================================================

def get_dashboard_stats(db_path: str | Path = DEFAULT_DB_PATH) -> dict:
    """
    Computes real aggregate statistics across all tables for the SOC dashboard.
    """
    init_db(db_path)
    conn = get_db_connection(db_path)

    try:
        cursor = conn.cursor()

        # 1. Total counts
        cursor.execute("SELECT COUNT(*) FROM security_events;")
        total_events = int(cursor.fetchone()[0])

        cursor.execute("SELECT COUNT(*) FROM alerts;")
        total_alerts = int(cursor.fetchone()[0])

        cursor.execute("SELECT COUNT(*) FROM incidents;")
        total_incidents = int(cursor.fetchone()[0])

        cursor.execute("""
            SELECT COUNT(*) FROM incidents
            WHERE COALESCE(status, 'Open') IN ('Open', 'Investigating');
        """)
        open_incidents = int(cursor.fetchone()[0])

        cursor.execute("""
            SELECT COUNT(*) FROM incidents
            WHERE severity IN ('HIGH', 'CRITICAL');
        """)
        high_critical_incidents = int(cursor.fetchone()[0])

        # 2. Events by outcome
        cursor.execute("""
            SELECT LOWER(COALESCE(outcome, 'unknown')) as oc, COUNT(*)
            FROM security_events
            GROUP BY oc;
        """)
        outcomes = {row[0]: row[1] for row in cursor.fetchall()}

        # 3. Events by source
        cursor.execute("""
            SELECT COALESCE(source, 'unknown') as src, COUNT(*)
            FROM security_events
            GROUP BY src
            ORDER BY COUNT(*) DESC
            LIMIT 5;
        """)
        events_by_source = {row[0]: row[1] for row in cursor.fetchall()}

        # 4. Alerts by severity
        cursor.execute("""
            SELECT severity, COUNT(*)
            FROM alerts
            GROUP BY severity;
        """)
        alerts_by_severity = {row[0]: row[1] for row in cursor.fetchall()}

        # 5. Incidents by status
        cursor.execute("""
            SELECT COALESCE(status, 'Open') as st, COUNT(*)
            FROM incidents
            GROUP BY st;
        """)
        incidents_by_status = {row[0]: row[1] for row in cursor.fetchall()}

        # 6. Top 5 suspicious IPs (failed logins / blocked traffic)
        cursor.execute("""
            SELECT source_ip, COUNT(*) as cnt
            FROM security_events
            WHERE outcome IN ('failure', 'blocked')
               OR event_type = 'LOGIN_FAILED'
            GROUP BY source_ip
            ORDER BY cnt DESC
            LIMIT 5;
        """)
        top_suspicious_ips = [
            {"ip": row[0], "failures": row[1]}
            for row in cursor.fetchall()
        ]

        # 7. Events timeline (chronological activity buckets)
        cursor.execute("""
            SELECT SUBSTR(timestamp, 1, 13) as hour_bucket, COUNT(*)
            FROM security_events
            GROUP BY hour_bucket
            ORDER BY hour_bucket ASC
            LIMIT 24;
        """)
        events_timeline = [
            {"time": row[0], "count": row[1]}
            for row in cursor.fetchall()
        ]

        return {
            "total_events": total_events,
            "total_alerts": total_alerts,
            "total_incidents": total_incidents,
            "open_incidents": open_incidents,
            "high_critical_incidents": high_critical_incidents,
            "outcomes": outcomes,
            "events_by_source": events_by_source,
            "alerts_by_severity": alerts_by_severity,
            "incidents_by_status": incidents_by_status,
            "top_suspicious_ips": top_suspicious_ips,
            "events_timeline": events_timeline,
        }

    finally:
        conn.close()
