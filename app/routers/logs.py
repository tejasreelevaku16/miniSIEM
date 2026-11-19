"""
Mini-SIEM Log Telemetry Router.

Endpoints for:
- Uploading and validating CSV log telemetry (POST /api/logs/upload)
- Querying stored security events with pagination (GET /api/logs)
- Inspecting a single security event (GET /api/logs/{event_id})
"""

from datetime import datetime
import hashlib
from pathlib import Path
import sqlite3
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile

from app.database import (
    DEFAULT_DB_PATH,
    count_security_events,
    get_db_path,
    get_security_event_by_id,
    get_security_events,
    get_uploaded_log_by_hash,
    save_security_events,
    save_uploaded_log,
)
from app.services.csv_parser import LogEvent, parse_csv_content
from app.services.detection_engine import run_all_detection_rules
from app.services.incident_correlator import correlate_alerts, persist_correlated_incidents

router = APIRouter(prefix="/api/logs", tags=["Logs"])


@router.post("/upload")
async def upload_log_file(
    file: UploadFile = File(...),
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Accepts an uploaded CSV authentication log file, validates its structure,
    stores log metadata, persists parsed security events into SQLite, and
    automatically triggers security detection rules.
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
        raise HTTPException(
            status_code=400,
            detail="Failed to read uploaded file.",
        )

    if not content_bytes or len(content_bytes.strip()) == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded file is empty.",
        )

    # 3. Check for file-level duplicates using SHA-256 hash
    file_hash = hashlib.sha256(content_bytes).hexdigest()
    existing_file = get_uploaded_log_by_hash(file_hash, db_path=db_path)

    if existing_file is not None:
        return {
            "status": "duplicate",
            "message": "This file has already been uploaded.",
            "existing_raw_log_id": existing_file["id"],
            "raw_log_id": existing_file["id"],
            "upload_id": existing_file["id"],
            "filename": filename,
            "summary": {
                "total_rows": existing_file["total_rows"],
                "valid_events": 0,
                "rejected_rows": 0,
                "stored_events": 0,
                "duplicate_events_skipped": existing_file["valid_events"],
                "rejected_row_numbers": [],
            },
        }

    # Decode using utf-8 with replacement for corrupted byte sequences
    text_content = content_bytes.decode("utf-8", errors="replace")

    # 4. Parse CSV structure and defensively validate rows
    (
        valid_events,
        warnings,
        rejected_row_numbers,
        total_rows,
    ) = parse_csv_content(text_content)

    if total_rows == 0 and warnings:
        raise HTTPException(status_code=400, detail=warnings[0])

    if total_rows == 0:
        raise HTTPException(
            status_code=400,
            detail="Uploaded CSV contains a header but no data rows.",
        )

    rejected_rows_count = len(rejected_row_numbers)

    # 5. Persist upload metadata into SQLite
    try:
        upload_id = save_uploaded_log(
            filename=filename,
            total_rows=total_rows,
            valid_events=len(valid_events),
            rejected_rows=rejected_rows_count,
            db_path=db_path,
            file_hash=file_hash,
        )
    except sqlite3.IntegrityError:
        existing_file = get_uploaded_log_by_hash(file_hash, db_path=db_path)
        if existing_file:
            return {
                "status": "duplicate",
                "message": "This file has already been uploaded.",
                "existing_raw_log_id": existing_file["id"],
                "raw_log_id": existing_file["id"],
                "upload_id": existing_file["id"],
                "filename": filename,
                "summary": {
                    "total_rows": existing_file["total_rows"],
                    "valid_events": 0,
                    "rejected_rows": 0,
                    "stored_events": 0,
                    "duplicate_events_skipped": existing_file["valid_events"],
                    "rejected_row_numbers": [],
                },
            }
        raise

    # 6. Persist parsed events into SQLite
    stored_count, duplicate_count = save_security_events(
        events=valid_events,
        upload_id=upload_id,
        db_path=db_path,
    )

    # 7. Automatically execute detection engine and correlate incidents
    if valid_events:
        detected_alerts = run_all_detection_rules(valid_events)
        if detected_alerts:
            correlated = correlate_alerts(detected_alerts)
            persist_correlated_incidents(correlated, db_path=db_path)

    return {
        "status": "success",
        "message": "Log file processed",
        "filename": filename,
        "upload_id": upload_id,
        "raw_log_id": upload_id,
        "total_rows": total_rows,
        "processed_events": len(valid_events),
        "rejected_rows": rejected_rows_count,
        "rejected_row_numbers": rejected_row_numbers,
        "summary": {
            "total_rows": total_rows,
            "valid_events": len(valid_events),
            "rejected_rows": rejected_rows_count,
            "stored_events": stored_count,
            "duplicate_events_skipped": duplicate_count,
            "rejected_row_numbers": rejected_row_numbers,
        },
    }


@router.get("")
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


@router.get("/{event_id}")
def get_log_by_id(
    event_id: int,
    db_path: Path = Depends(get_db_path),
) -> dict:
    """
    Retrieves a single security event by its primary key ID.
    """
    event = get_security_event_by_id(event_id, db_path=db_path)
    if not event:
        raise HTTPException(
            status_code=404,
            detail=f"Security event with ID {event_id} not found.",
        )
    return event
