"""
Mini-SIEM FastAPI Ingestion Application.

Provides REST API endpoints for:
1. System health status (GET /api/health).
2. Authentication log CSV file upload and validation (POST /api/logs/upload).
3. Retrieval of parsed and stored security events (GET /api/logs).
"""

import csv
from datetime import datetime
import io
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile

from app.database import (
    DEFAULT_DB_PATH,
    count_security_events,
    get_security_events,
    init_db,
    save_security_events,
    save_uploaded_log,
)
from app.services.detector import LogEvent, parse_log_row

app = FastAPI(
    title="Mini-SIEM Log Ingestion API",
    description="Educational SIEM REST API for ingesting, validating, and retrieving authentication events.",
    version="1.0.0",
)


def get_db_path() -> Path:
    """Dependency injection provider for database path (allows test overrides)."""
    return DEFAULT_DB_PATH


@app.on_event("startup")
def on_startup() -> None:
    """Initializes database tables on application startup."""
    init_db(DEFAULT_DB_PATH)


@app.get("/api/health", tags=["System"])
def health_check() -> dict:
    """
    Returns service health status and current server timestamp.
    """
    return {
        "status": "ok",
        "service": "Mini-SIEM Log Ingestion API",
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


@app.post("/api/logs/upload", tags=["Logs"])
async def upload_log_file(
    file: UploadFile = File(...),
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Accepts an uploaded CSV authentication log file, validates its structure,
    stores log metadata, and persists parsed security events into SQLite.

    Validation rules:
    - Must be a `.csv` file.
    - Must contain required header columns: `timestamp`, `source_ip`, `username`, `event_type`.
    - Skips malformed rows while saving valid records.
    - Prevents duplicate event insertion via database-enforced unique constraints.
    """
    filename = file.filename or "uploaded_logs.csv"

    # 1. Validate file extension
    if not filename.lower().endswith(".csv"):
        raise HTTPException(
            status_code=400,
            detail="Invalid file format. Please upload a CSV file (.csv).",
        )

    # 2. Read and decode content safely
    try:
        content_bytes = await file.read()
    except Exception:
        raise HTTPException(status_code=400, detail="Failed to read uploaded file.")

    if not content_bytes or len(content_bytes.strip()) == 0:
        raise HTTPException(status_code=400, detail="Uploaded file is empty.")

    # Decode using utf-8 with replacement for corrupted byte sequences
    text_content = content_bytes.decode("utf-8", errors="replace")

    # 3. Parse CSV structure
    stream = io.StringIO(text_content)
    reader = csv.DictReader(stream)

    if reader.fieldnames is None:
        raise HTTPException(status_code=400, detail="Uploaded CSV file is missing a header row.")

    # Normalize header column names
    normalized_fieldnames = [col.strip().lower() for col in reader.fieldnames if col]
    required_columns = {"timestamp", "source_ip", "username", "event_type"}
    if not required_columns.issubset(set(normalized_fieldnames)):
        missing = sorted(list(required_columns - set(normalized_fieldnames)))
        raise HTTPException(
            status_code=400,
            detail=f"Missing required CSV column(s): {', '.join(missing)}",
        )

    # 4. Parse rows defensively
    total_rows = 0
    valid_events: list[LogEvent] = []
    rejected_rows = 0

    for row_num, raw_row in enumerate(reader, start=2):
        total_rows += 1
        clean_row = {k.strip().lower(): v for k, v in raw_row.items() if k is not None}
        event, warning = parse_log_row(clean_row, row_num)
        if warning or event is None:
            rejected_rows += 1
        else:
            valid_events.append(event)

    if total_rows == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV contains a header but no data rows.",
        )

    # 5. Persist upload metadata and parsed events into SQLite
    upload_id = save_uploaded_log(
        filename=filename,
        total_rows=total_rows,
        valid_events=len(valid_events),
        rejected_rows=rejected_rows,
        db_path=db_path,
    )

    stored_count, duplicate_count = save_security_events(
        events=valid_events,
        upload_id=upload_id,
        db_path=db_path,
    )

    return {
        "status": "success",
        "filename": filename,
        "upload_id": upload_id,
        "summary": {
            "total_rows": total_rows,
            "valid_events": len(valid_events),
            "rejected_rows": rejected_rows,
            "stored_events": stored_count,
            "duplicate_events_skipped": duplicate_count,
        },
    }


@app.get("/api/logs", tags=["Logs"])
def get_logs(
    limit: int = Query(default=100, ge=1, le=1000, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Records to skip for pagination"),
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Retrieves stored security events ordered chronologically with pagination.
    """
    total = count_security_events(db_path=db_path)
    events = get_security_events(limit=limit, offset=offset, db_path=db_path, ascending=True)

    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "events": events,
    }
