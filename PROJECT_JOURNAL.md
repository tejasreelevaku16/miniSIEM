# Mini-SIEM Project Journal

This journal tracks engineering milestones, implemented features, bugs fixed, architectural decisions, and verified test results for the Mini-SIEM cybersecurity portfolio project. Items are marked completed `[x]` only after passing automated tests and end-to-end execution verification.

---

## Milestone 1: Log Ingestion & Brute-Force Detection Engine
- **Status**: Completed & Verified
- **Verification Date**: 2026-10-20
- **Test Results**: 8/8 tests passed (`test_detector.py`)

### Implemented Features
- [x] Simulated log dataset (`sample_logs.csv`) with realistic authentication telemetry (failed logins, successful logins, normal traffic, spaced-out attempts, brute-force waves).
- [x] Resilient CSV parser using Python's standard `csv` module with malformed timestamp handling and row-level validation.
- [x] Rolling 5-minute sliding window correlation engine detecting source IPs with $\ge 3$ failed attempts.
- [x] Alert generation with metadata: `source_ip`, `failure_count`, `window_start`, `window_end`, `severity` (`MEDIUM` / `HIGH`), and `targeted_usernames`.
- [x] Command-line runner (`main.py`) displaying human-readable analyst alert cards in the terminal.
- [x] Defensive validation: graceful handling of missing log files, corrupted columns, and invalid timestamps without crashing.

---

## Milestone 2: SQLite Incident Persistence & Deduplication
- **Status**: Completed & Verified
- **Verification Date**: 2026-10-20
- **Test Results**: 6/6 tests passed (`test_database.py`), 14/14 tests passed across total project suite

### Implemented Features
- [x] Storage module (`database.py`) using Python's standard library `sqlite3` without external dependencies.
- [x] Schema definition creating `incidents` table with auto-incrementing integer `id` primary keys and indexes.
- [x] Parameterized SQL queries using `?` placeholders preventing SQL injection attacks even on hostile log strings.
- [x] Reliable connection lifecycle management ensuring commits on success, rollbacks on error, and guaranteed connection closure (`finally: conn.close()`).
- [x] Database-enforced incident deduplication using composite constraint `UNIQUE(source_ip, window_start, window_end)` and `INSERT OR IGNORE`.
- [x] Reporting of newly saved incidents vs duplicate incidents in `main.py` CLI output.
- [x] Query utilities: `init_db()`, `save_alerts()`, `get_all_incidents()` (ordered chronologically), and `count_incidents()`.
- [x] Unit test isolation: temporary database creation ensuring `minisiem.db` is never corrupted during test runs.

---

## Milestone 3: FastAPI Log Ingestion Backend
- **Status**: Completed & Verified
- **Verification Date**: 2026-10-20
- **Test Results**: 10/10 tests passed (`test_api.py`), 24/24 tests passed across all suites

### Implemented Features
- [x] FastAPI REST application entry point (`app/main.py`).
- [x] Health check endpoint (`GET /api/health`).
- [x] CSV log file upload endpoint (`POST /api/logs/upload`) with multipart file validation.
- [x] Strict header validation rejecting non-CSV formats and missing required columns.
- [x] Row-level defensive parsing skipping malformed timestamps and empty values while saving valid records.
- [x] SQLite schema extension: `uploaded_logs` metadata table and `security_events` table with foreign key linkage and indexes.
- [x] Event-level deduplication constraint `UNIQUE(timestamp, source_ip, username, event_type)` preventing double-insertion on re-uploads.
- [x] Security event retrieval endpoint (`GET /api/logs`) with limit and offset pagination.

---

## Milestone 4: Cryptographic Hashing & Ingestion Resiliency
- **Status**: Completed & Verified
- **Verification Date**: 2026-11-18
- **Test Results**: 6 new tests passed, 30/30 total tests passing

### Implemented Features
- [x] SHA-256 cryptographic file hashing of incoming CSV log files.
- [x] File-level duplicate detection: identical files return `{ "status": "duplicate", "message": "This file has already been uploaded.", "existing_raw_log_id": id }`.
- [x] Concurrency safety: graceful `sqlite3.IntegrityError` handling preventing race conditions on simultaneous duplicate uploads.
- [x] Physical row numbering starting at row 2 (row 1 is header).
- [x] Collection and reporting of `rejected_row_numbers: list[int]` in upload API response.
- [x] Non-destructive database migrations adding `dest_ip`, `dest_port`, `protocol`, `request_path`, `status_code` to `security_events` while preserving all existing historical records.
- [x] Single event retrieval endpoint (`GET /api/logs/{event_id}`).
- [x] Migration from deprecated `@app.on_event("startup")` to FastAPI `lifespan` context manager.

---

## Milestone 5: Multi-Rule Detection Engine & MITRE ATT&CK Mapping
- **Status**: Completed & Verified
- **Verification Date**: 2026-11-18
- **Test Results**: 13 new tests passed (`test_rules.py`, `test_mitre.py`)

### Implemented Features
- [x] Separate MITRE ATT&CK mapping module (`app/services/mitre_mapper.py`):
  - `T1110` (Brute Force)
  - `T1110.001` (Password Guessing)
  - `T1110.003` (Password Spraying)
  - `T1078` (Valid Accounts)
  - `T1046` (Network Service Discovery)
  - `T1499` (Endpoint Denial of Service)
- [x] Detection rules in `app/services/detection_engine.py`:
  - [x] **AUTH-001**: Brute-force detection ($\ge 5$ failures in 10 minutes from same IP).
  - [x] **AUTH-002**: Suspicious login sequence (failed logins followed by successful login for same user/IP).
  - [x] **AUTH-003**: Repeated suspicious login activity (password spraying targeting $\ge 3$ distinct users).
  - [x] **AUTH-004**: Out-of-working-hours login (configurable schedule, e.g. outside 08:00&ndash;18:00).
  - [x] **FW-001**: Port scan reconnaissance ($\ge 5$ distinct destination ports from same IP, with missing field guard).
  - [x] **WEB-001**: High request volume ($\ge 30$ HTTP requests/minute, with missing field guard).
- [x] Enriched `Alert` dataclass containing `rule_id`, `rule_name`, `mitre_attack_id`, `severity`, and `recommended_action`.

---

## Milestone 6: Incident Correlation, Management & Interactive SOC Dashboard
- **Status**: Completed & Verified
- **Verification Date**: 2026-11-18
- **Test Results**: 7 new tests passed (`test_correlation.py`, `test_incident_api.py`), **50/50 total tests passed**

### Implemented Features
- [x] Incident correlation engine (`app/services/incident_correlator.py`):
  - Groups related alerts by `source_ip` and time window.
  - Multi-stage attack progression detection: escalates `AUTH-001 + AUTH-002` to **CRITICAL** severity.
  - Incident deduplication and relational alert linkage.
- [x] Incident lifecycle state machine (`Open`, `Investigating`, `Resolved`, `False Positive`).
- [x] Dedicated API routers:
  - `/api/logs`: upload, pagination, single log retrieval.
  - `/api/alerts`: alert listing, batch detection runner (`POST /api/alerts/run-detection`).
  - `/api/incidents`: incident listing, detail view with event timeline, and `PATCH /api/incidents/{id}` status updates.
  - `/api/dashboard/stats`: real aggregated KPI metrics and Chart.js telemetry.
- [x] Interactive Single-Page SOC Dashboard (`app/static/`):
  - Dark-mode responsive cybersecurity interface.
  - Overview KPI cards (Total Events, Alerts, Incidents, Open Incidents, Critical Risks).
  - Chart.js charts: Activity timeline, Outcome doughnut, Severity distribution, Incident status, Source breakdown.
  - Top suspicious source IP rankings table.
  - Interactive incident table with inline status dropdowns.
  - Modal investigation drawer with MITRE ATT&CK badges, attack descriptions, playbooks, and raw event timelines.
  - Drag-and-drop CSV log file uploader with live summary, duplicate detection banners, and rejected row pills.
- [x] Four realistic sample datasets in `sample_logs/`:
  - `sample_logs.csv` (baseline authentication telemetry).
  - `auth_sample.csv` (brute-force, password spray, off-hours, success-after-fail).
  - `firewall_sample.csv` (network port scan).
  - `web_sample.csv` (HTTP request flood).

---

## Engineering Concepts Learned & Applied

1. **Defensive Log Parsing**:
   Never trust user-supplied input files. We strip BOM headers, normalize casing and whitespaces, validate ISO 8601 timestamps, verify categorical values against allowed sets, and gracefully skip corrupt rows while recording exact row numbers so analysts can audit corrupt data.

2. **Cryptographic Deduplication**:
   By computing a SHA-256 hash of the entire file buffer, we provide $O(1)$ duplicate file detection before even parsing lines. Backed by a SQLite `UNIQUE` index, race conditions are safely resolved at the database constraint level.

3. **Rule-Based Detection Engineering**:
   Moving beyond simple counts to stateful sliding time windows (`timedelta`). Correlating not just individual event types, but ordered sequences (such as multiple failed logins immediately followed by a successful login, signaling compromised valid accounts).

4. **Multi-Stage Attack Correlation**:
   Single alerts create alert fatigue for SOC analysts. Correlating alerts by source IP, targeted entities, and time windows groups disparate events into unified incidents. Combining brute-force reconnaissance with subsequent successful authentication automatically escalates risk to CRITICAL.

5. **REST API Architecture & Separation of Concerns**:
   Decoupling API routers, database persistence, parser engines, detection rules, and frontend static assets prevents monolithic code and ensures individual modules can be tested independently.

---

## Bug Fixes & Technical Debt Resolved

- **Fixed FastAPI Startup Deprecation**: Replaced deprecated `@app.on_event("startup")` with modern `@asynccontextmanager lifespan` handler.
- **Fixed Database Overwrite Risk**: Ensured `init_db()` uses non-destructive `ALTER TABLE ADD COLUMN` queries, protecting existing historical incident records.
- **Fixed Physical Row Count Tracking**: Corrected CSV line offset to count data rows starting at line 2 (respecting row 1 as header).
- **Added Concurrency Protection**: Wrapped upload record insertion in a try/except block catching `sqlite3.IntegrityError` to gracefully handle concurrent duplicate uploads.

---

## Verification Test Results (Final Run)

Command: `pytest -v`
```
============================== test session starts ==============================
collected 50 items

tests/test_api.py::TestMiniSIEMApi .............                          [ 26%]
tests/test_correlation.py::TestIncidentCorrelator ...                     [ 32%]
tests/test_database.py::TestMiniSIEMDatabase .........                    [ 50%]
tests/test_detector.py::TestMiniSIEMDetector ........                     [ 66%]
tests/test_incident_api.py::TestIncidentAndDashboardApi ....              [ 74%]
tests/test_mitre.py::TestMitreMapper ....                                 [ 82%]
tests/test_rules.py::TestDetectionRules .........                         [100%]

======================== 50 passed, 1 warning in 8.55s ========================
```
100% test pass rate across all 50 automated tests.
