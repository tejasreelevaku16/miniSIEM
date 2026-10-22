# Mini-SIEM Project Journal

This journal tracks implemented engineering milestones and verified capabilities for the Mini-SIEM project. Items are marked completed `[x]` only after passing automated tests and end-to-end execution verification.

---

## Milestone 1: Log Ingestion & Brute-Force Detection Engine
- **Status**: Completed & Verified
- **Verification Date**: 2026-10-20
- **Test Results**: 8/8 tests passed (`test_detector.py`)

### Implemented Features
- [x] Simulated log dataset (`sample_logs.csv`) with realistic authentication telemetry (failed logins, successful logins, normal traffic, spaced-out attempts, brute-force waves).
- [x] Resilient CSV parser using Python's standard `csv` module with malformed timestamp handling and row-level validation (`detector.py`).
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

## Milestone 3 (Week 1 Extension): FastAPI Log Ingestion Backend
- **Status**: Completed & Verified
- **Verification Date**: 2026-10-20
- **Test Results**: 10/10 tests passed (`test_api.py`), 24/24 tests passed across all suites

### Implemented Features
- [x] FastAPI REST application entry point (`app.py`).
- [x] Health check endpoint (`GET /api/health`).
- [x] CSV log file upload endpoint (`POST /api/logs/upload`) with multipart file validation.
- [x] Strict header validation rejecting non-CSV formats and missing required columns (`timestamp`, `source_ip`, `username`, `event_type`).
- [x] Row-level defensive parsing skipping malformed timestamps and empty values while saving valid events.
- [x] SQLite schema extension: `uploaded_logs` metadata table and `security_events` table with foreign key linkage and indexes.
- [x] Event-level deduplication constraint `UNIQUE(timestamp, source_ip, username, event_type)` preventing double-insertion on re-uploads.
- [x] Security event retrieval endpoint (`GET /api/logs`) with limit and offset pagination.
- [x] Automated API test suite (`test_api.py`) verifying health checks, valid uploads, duplicate handling, malformed rows, and pagination using temporary test databases.

---

## Future Roadmap (Untested / Planned)

The following items are planned for future phases and remain unchecked until implemented and verified:
- [ ] **Milestone 4**: Interactive Web Dashboard for SOC analysts (incident timeline charts, threat maps, status tagging).
- [ ] **Milestone 5**: Advanced Detection Rules:
  - [ ] Password spraying detection ($\ge N$ different accounts targeted by a single IP with low failure rates per account).
  - [ ] Impossible travel detection (same account logging in from geographically disparate IPs within short time spans).
  - [ ] Off-hours authentication anomalies.
- [ ] **Milestone 6**: Real-time live log ingestion daemon (listening on UDP/TCP syslog socket).
