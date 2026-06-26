"""FastAPI routes for scan orchestration."""
from __future__ import annotations

import logging
import uuid
from dataclasses import asdict
from datetime import datetime

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Response, status

from backend.schemas.scan_schemas import (
    ErrorPayload,
    ErrorResponse,
    HealthResponse,
    ScanAcceptedResponse,
    ScanCreateRequest,
    ScanStatusResponse,
    ScanSummaryResponse,
)
from backend.services.scan_service import ScanService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api", tags=["scans"])


def get_scan_service() -> ScanService:
    """Dependency placeholder overridden in app bootstrap."""
    raise RuntimeError("ScanService dependency is not configured")


def generate_trace_id() -> str:
    return str(uuid.uuid4())[:8]


def error_response(code: str, message: str) -> dict:
    error_resp = ErrorResponse(
        error=ErrorPayload(code=code, message=message, trace_id=generate_trace_id())
    )
    return asdict(error_resp)


@router.get("/health", response_model=HealthResponse, tags=["health"])
async def get_health() -> HealthResponse:
    return HealthResponse(
        status="ok",
        service="secval-api",
        version="0.1.0",
        time=datetime.utcnow(),
        dependencies={"scanner_engine": "up", "nmap": "up"},
    )


@router.post("/scans", response_model=ScanAcceptedResponse, status_code=status.HTTP_202_ACCEPTED)
async def create_scan(
    request: ScanCreateRequest,
    background_tasks: BackgroundTasks,
    service: ScanService = Depends(get_scan_service),
) -> ScanAcceptedResponse:
    try:
        job = service.create_job(request)
        background_tasks.add_task(service.run_scan, job.scan_id)
        return ScanAcceptedResponse(
            scan_id=job.scan_id,
            status=job.status,
            created_at=job.created_at,
            message="Scan accepted",
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=error_response("BAD_REQUEST", str(exc)),
        ) from exc


@router.get("/scans/{scan_id}", response_model=ScanStatusResponse)
async def get_scan_status(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanStatusResponse:
    try:
        return service.get_status(scan_id, include_results=True)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error_response("SCAN_NOT_FOUND", f"scanId '{scan_id}' not found"),
        ) from exc


@router.get("/scans/{scan_id}/summary", response_model=ScanSummaryResponse)
async def get_scan_summary(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> ScanSummaryResponse:
    try:
        return service.get_summary(scan_id)
    except KeyError as exc:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error_response("SCAN_NOT_FOUND", f"scanId '{scan_id}' not found"),
        ) from exc


@router.get("/scans/{scan_id}/report.xlsx", tags=["reports"])
async def download_scan_report(
    scan_id: str,
    service: ScanService = Depends(get_scan_service),
) -> Response:
    job = service.store.get(scan_id)
    if not job:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=error_response("SCAN_NOT_FOUND", f"scanId '{scan_id}' not found"),
        )

    if job.status.value not in {"done", "partial"}:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=error_response("SCAN_NOT_READY", "Report is available only when status is done or partial"),
        )

    report_bytes = service.build_xlsx_report(scan_id)
    filename = f"VA_Scan_Report_{scan_id[:8]}.xlsx"
    return Response(
        content=report_bytes,
        media_type="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
