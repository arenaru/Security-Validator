"""
FastAPI application entry point.
Replaces Streamlit app.py for MVC migration.

Run with: uvicorn backend.app_fastapi:app --host 0.0.0.0 --port 8000 --reload
"""
from __future__ import annotations

import logging
from datetime import datetime

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.controllers.scan_controller import get_scan_service as controller_get_scan_service
from backend.controllers.scan_controller import router as scan_router
from backend.services.scan_service import InMemoryScanStore, ScanService

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

# Initialize services (singleton)
_scan_store = InMemoryScanStore()
_scan_service = ScanService(store=_scan_store)


def get_scan_service() -> ScanService:
    """Dependency injection: provide ScanService to routes."""
    return _scan_service


# Create FastAPI app
app = FastAPI(
    title="SecVal Scan API",
    version="0.1.0",
    description="Vulnerability scanner with MVC + service layer architecture",
    openapi_url="/api/docs/openapi.json",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# Add CORS middleware (allow all origins for dev; restrict in prod)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Register routers with dependency injection
app.dependency_overrides[controller_get_scan_service] = get_scan_service
app.include_router(scan_router)

# Health check root endpoint
@app.get("/", tags=["root"])
async def root():
    """Root endpoint - redirects to docs."""
    return {
        "message": "SecVal API - Vulnerability Scanner",
        "version": "0.1.0",
        "docs_url": "/api/docs",
        "redoc_url": "/api/redoc",
        "openapi_url": "/api/docs/openapi.json",
    }


@app.on_event("startup")
async def startup_event():
    """Log startup event."""
    logger.info(f"FastAPI app started at {datetime.utcnow().isoformat()}")


@app.on_event("shutdown")
async def shutdown_event():
    """Log shutdown event."""
    logger.info(f"FastAPI app shutdown at {datetime.utcnow().isoformat()}")


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "backend.app_fastapi:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
