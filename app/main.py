"""
Mini-SIEM FastAPI Application.

Integrates REST API endpoints for:
1. System Health (/api/health)
2. Log Ingestion & Querying (/api/logs)
3. Detection Alerts (/api/alerts)
4. Correlated Incidents (/api/incidents)
5. Dashboard Metrics & Analytics (/api/dashboard)
6. Interactive SOC Web Interface (/)
"""

from contextlib import asynccontextmanager
from datetime import datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.database import DEFAULT_DB_PATH, get_db_path, init_db
from app.routers import alerts, dashboard, incidents, logs


@asynccontextmanager
async def lifespan(app_instance: FastAPI):
    """Initializes database tables and safe schema migrations on startup."""
    init_db(DEFAULT_DB_PATH)
    yield


app = FastAPI(
    title="Mini-SIEM Security Operations Center API",
    description=(
        "Educational SIEM platform for security log ingestion, multi-rule detection, "
        "MITRE ATT&CK correlation, and incident investigation."
    ),
    version="2.0.0",
    lifespan=lifespan,
)

# Enable CORS for local development and analyst dashboards
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include modular API routers
app.include_router(logs.router)
app.include_router(alerts.router)
app.include_router(incidents.router)
app.include_router(dashboard.router)

# Mount static web assets
STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)
app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/", tags=["UI"], include_in_schema=False)
def serve_dashboard():
    """Serves the interactive single-page SOC monitoring dashboard."""
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return FileResponse(index_file)
    return {
        "service": "Mini-SIEM SOC Platform",
        "status": "online",
        "documentation": "/docs",
    }


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
