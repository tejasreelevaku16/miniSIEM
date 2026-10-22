# Mini-SIEM (Security Information and Event Management)

Mini-SIEM is a lightweight, educational Security Information and Event Management prototype built with Python and FastAPI. It simulates how modern Security Operations Center (SOC) platforms ingest authentication telemetry via REST APIs or files, normalize event logs, correlate suspicious activities (such as brute-force attacks) using rolling time windows, and persist both raw telemetry and correlated security incidents into a local relational database for SOC auditing.

This project is tailored as a cybersecurity portfolio demonstration illustrating security log parsing, rule-based detection engineering, REST API log ingestion, parameterized SQL defense, and defensive scripting.

---

## Project Structure

```
MiniSIEM/
│
├── sample_logs.csv        # Simulated authentication dataset with realistic events
├── detector.py            # Log ingestion, normalization, and detection engine
├── database.py            # SQLite storage module with deduplication and parameterized queries
├── app.py                 # FastAPI REST API for log uploading, health, and event retrieval
├── main.py                # Command-line entry point, alert presentation, and storage orchestrator
├── test_detector.py       # Unit tests for log parsing and brute-force detection
├── test_database.py       # Unit tests for database schemas, persistence, and deduplication
├── test_api.py            # Unit tests for FastAPI endpoints, uploads, and pagination
├── minisiem.db            # Local SQLite database storing events, upload metadata, and incidents
├── PROJECT_JOURNAL.md     # Engineering log tracking implemented & verified milestones
└── README.md              # Project documentation and setup guide
```

### Module Breakdown

| File | Purpose |
| :--- | :--- |
| `sample_logs.csv` | Contains simulated audit logs (timestamps, IPs, usernames, status). |
| `detector.py` | Contains `LogEvent` and `Alert` models, safe CSV loading, validation, and rolling 5-minute window correlation. |
| `database.py` | Manages SQLite connection lifecycle, schema migrations, parameterized queries, and incident/event deduplication. |
| `app.py` | FastAPI application exposing `/api/health`, `/api/logs/upload`, and `/api/logs`. |
| `main.py` | CLI tool coordinating log ingestion, triggering detection, and printing terminal alert cards. |
| `test_detector.py` | Automated tests verifying brute-force detection, normal traffic filtering, time-window logic, and malformed data handling. |
| `test_database.py` | Automated tests verifying table creation, auto-increment IDs, chronological queries, duplicate skipping, and SQL injection defense. |
| `test_api.py` | Automated tests verifying REST API health checks, file validation, duplicate event skipping, and log pagination. |

---

## Prerequisites & Setup

### Requirements
- **Python 3.10+** (tested on Python 3.14)
- **Dependencies**: `fastapi`, `uvicorn[standard]`, `python-multipart`, and `httpx`.
- **PyCharm** (Community or Professional Edition)

### Setup Instructions in PyCharm

1. Open the project directory (`MiniSIEM`) in PyCharm.
2. Ensure your Python Interpreter is configured to the project's virtual environment (`.venv`).
3. Open PyCharm's built-in **Terminal** (`Alt+F12` or View &rarr; Tool Windows &rarr; Terminal).
4. Install required packages (if not already installed):
   ```powershell
   pip install "fastapi>=0.100.0" "uvicorn[standard]>=0.20.0" "python-multipart>=0.0.6" "httpx>=0.24.0"
   ```

---

## How to Run the REST API Backend

Start the FastAPI application with Uvicorn:

```powershell
uvicorn app:app --reload
```

The server starts locally at `http://127.0.0.1:8000`.

### Interactive Swagger UI (`/docs`)
FastAPI provides an automatic, interactive API documentation interface. Open your browser and navigate to:
```
http://127.0.0.1:8000/docs
```
From `/docs`, you can:
1. **Health Check (`GET /api/health`)**: Click "Try it out" &rarr; "Execute" to inspect service uptime.
2. **Upload CSV Logs (`POST /api/logs/upload`)**: Click "Try it out", browse and select `sample_logs.csv`, and click "Execute" to upload and ingest logs into SQLite.
3. **Query Events (`GET /api/logs`)**: Retrieve stored events with custom `limit` and `offset` pagination.

---

## REST API Endpoints

### 1. `GET /api/health`
Checks API status.
- **Response `200 OK`**:
  ```json
  {
    "status": "ok",
    "service": "Mini-SIEM Log Ingestion API",
    "timestamp": "2026-10-20 20:50:00"
  }
  ```

### 2. `POST /api/logs/upload`
Uploads a CSV file containing authentication telemetry.
- **Payload**: `multipart/form-data` with key `file`.
- **Validation**:
  - Must have `.csv` file extension.
  - Header must contain: `timestamp`, `source_ip`, `username`, `event_type`.
  - Malformed or incomplete rows are skipped while valid events are saved.
- **Response `200 OK`**:
  ```json
  {
    "status": "success",
    "filename": "sample_logs.csv",
    "upload_id": 1,
    "summary": {
      "total_rows": 17,
      "valid_events": 17,
      "rejected_rows": 0,
      "stored_events": 17,
      "duplicate_events_skipped": 0
    }
  }
  ```
- **Error Response `400 Bad Request`**: Returned on non-CSV uploads, empty files, or missing headers.

### 3. `GET /api/logs`
Retrieves stored security events in chronological order.
- **Query Parameters**:
  - `limit` (default: 100, min: 1, max: 1000)
  - `offset` (default: 0, min: 0)
- **Response `200 OK`**:
  ```json
  {
    "total": 17,
    "limit": 100,
    "offset": 0,
    "events": [
      {
        "id": 1,
        "upload_id": 1,
        "timestamp": "2026-10-20 08:30:00",
        "source_ip": "10.0.0.15",
        "username": "charlie",
        "event_type": "LOGIN_SUCCESS",
        "created_at": "2026-10-20 20:50:00"
      }
    ]
  }
  ```

---

## SQLite Database Schemas

Mini-SIEM maintains three relational tables in `minisiem.db`:

### 1. `uploaded_logs` Table (Metadata)
Stores batch upload records and parsing metrics.
```sql
CREATE TABLE IF NOT EXISTS uploaded_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    filename TEXT NOT NULL,
    upload_timestamp TEXT NOT NULL,
    total_rows INTEGER NOT NULL,
    valid_events INTEGER NOT NULL,
    rejected_rows INTEGER NOT NULL
);
```

### 2. `security_events` Table (Parsed Telemetry)
Stores individual normalized authentication events.
```sql
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
```

### 3. `incidents` Table (Correlated Alerts)
Stores security incidents detected by correlation rules.
```sql
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
```

---

## How to Run the Automated Tests

Run test discovery across all 24 automated unit tests:

```powershell
python -m unittest discover -v
```

Or run individual test modules:

```powershell
python -m unittest -v test_api.py
python -m unittest -v test_database.py
python -m unittest -v test_detector.py
```

### What the Test Suite Covers (24 Tests Total)

- **API Tests (`test_api.py` - 10 tests)**:
  - Health check endpoint verification.
  - Successful CSV upload and parsing.
  - Duplicate event skipping on repeated uploads.
  - Rejection of missing required headers (e.g. missing `username`).
  - Handling of mixed files (valid rows stored, malformed rows rejected).
  - Rejection of non-CSV extensions and empty payloads.
  - Retrieval of events from empty and populated databases.
  - Chronological ordering and pagination (`limit`, `offset`).
- **Database Tests (`test_database.py` - 6 tests)**:
  - Table initialization and schema constraints.
  - Alert saving and unique ID assignment.
  - Chronological queries and count metrics.
  - Incident deduplication.
  - Parameterized query SQL injection defense.
  - Empty list handling.
- **Detector Tests (`test_detector.py` - 8 tests)**:
  - Brute-force threshold detection within rolling windows.
  - Normal traffic filtering.
  - Spread-out failures outside the 5-minute window.
  - Severity level calculation (`MEDIUM` vs `HIGH`).
  - Missing file and malformed row error handling.
  - End-to-end sample log verification.

---

## Future Roadmap

- [x] **Milestone 1**: CSV log ingestion, validation, rolling 5-minute brute-force detection.
- [x] **Milestone 2**: SQLite incident persistence, parameterized queries, and deduplication.
- [x] **Milestone 3 (Week 1)**: FastAPI REST backend for log ingestion, upload validation, and event retrieval.
- [ ] **Milestone 4 (Week 2)**: Interactive Web Dashboard for SOC analysts (incident timeline charts, threat maps, status tagging).
- [ ] **Milestone 5**: Advanced detection rules (password spraying detection, impossible travel, anomalous off-hours logins).
- [ ] **Milestone 6**: Real-time live log ingestion daemon (listening on UDP/TCP syslog socket).
