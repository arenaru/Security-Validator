import threading
import time

from backend.models.scan_models import ScanOptions
from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.utils import scanner_engine


def build_service():
    store = InMemoryScanStore()
    return ScanService(store=store)


def test_run_scan_enforces_job_deadline(monkeypatch):
    release = threading.Event()

    def hanging_module(targets):
        release.wait(30)
        return []

    monkeypatch.setattr(scanner_engine, "check_security_headers", hanging_module)

    service = build_service()
    request = ScanCreateRequest(
        targets=["example.com"],
        modules=["Security Headers Check"],
        options=ScanOptions(timeout_seconds=1),
    )
    job = service.create_job(request)

    start = time.monotonic()
    try:
        finished = service.run_scan(job.scan_id)
    finally:
        release.set()
    elapsed = time.monotonic() - start

    assert elapsed < 5
    assert finished.status.value in {"partial", "failed"}
    assert finished.results.get("Security Headers Check") == []
    assert any("timeout" in error.message.lower() for error in finished.errors)


def test_run_scan_completes_when_module_is_fast(monkeypatch):
    def fast_module(targets):
        return [{"URL": "https://example.com", "Status": "SECURE", "Detail": "ok"}]

    monkeypatch.setattr(scanner_engine, "check_security_headers", fast_module)

    service = build_service()
    request = ScanCreateRequest(
        targets=["example.com"],
        modules=["Security Headers Check"],
        options=ScanOptions(timeout_seconds=60),
    )
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    assert finished.status.value == "done"
    assert finished.errors == []
    module_results = finished.results["Security Headers Check"]
    assert len(module_results) == 1
    assert module_results[0].status.value == "secure"
