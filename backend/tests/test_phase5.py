import time
from datetime import timedelta

import pytest

from backend.models.scan_models import ScanJob, ScanOptions
from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import headerCheck, scan_service as scan_service_module, tlsScanner
from backend.services.scan_service import InMemoryScanStore, ScanService, _STORE_TTL_SECONDS
from backend.utils import scanner_engine


# ---------------------------------------------------------------------------
# Step 1 — headerCheck threading
# ---------------------------------------------------------------------------

def test_check_security_headers_is_parallel_and_ordered(monkeypatch):
    delay = 0.25
    targets = [f"https://t{i}.example.com" for i in range(8)]

    def fake_check(url):
        time.sleep(delay)
        return {"URL": url, "Status": "SECURE", "Score": "6/6"}

    monkeypatch.setattr(headerCheck, "_check_single_target", fake_check)

    start = time.monotonic()
    results = headerCheck.check_security_headers(targets)
    elapsed = time.monotonic() - start

    assert [r["URL"] for r in results] == targets
    assert elapsed < delay * len(targets) / 2


# ---------------------------------------------------------------------------
# Step 2 — TLS consolidation: one nmap call, three results
# ---------------------------------------------------------------------------

def test_check_tls_protocols_runs_nmap_once(monkeypatch):
    calls = []

    class FakeProc:
        stdout = "443/tcp open  https\n|   TLSv1.0:\n|   TLSv1.1:\n|   TLSv1.2:\n"
        returncode = 0

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return FakeProc()

    monkeypatch.setattr(tlsScanner.subprocess, "run", fake_run)

    result = tlsScanner.check_tls_protocols("https://example.com")

    assert len(calls) == 1
    assert set(result.keys()) == {"SSLv3 Detection", "TLS 1.0 Detection", "TLS 1.1 Detection"}
    assert result["TLS 1.0 Detection"]["status"] == "INSECURE"
    assert result["TLS 1.1 Detection"]["status"] == "INSECURE"
    assert result["SSLv3 Detection"]["status"] == "SECURE"


def test_run_tls_scan_calls_check_once_per_target(monkeypatch):
    calls = []

    def fake_check(target):
        calls.append(target)
        return {
            "SSLv3 Detection": {"target": target, "status": "SECURE", "details": "ok"},
            "TLS 1.0 Detection": {"target": target, "status": "SECURE", "details": "ok"},
            "TLS 1.1 Detection": {"target": target, "status": "SECURE", "details": "ok"},
        }

    monkeypatch.setattr(tlsScanner, "check_tls_protocols", fake_check)

    targets = ["t1.example.com", "t2.example.com", "t3.example.com"]
    result = tlsScanner.run_tls_scan(targets)

    assert len(calls) == 3          # once per target, not 9 (3 × 3 protocols)
    assert len(result["SSLv3 Detection"]) == 3
    assert len(result["TLS 1.0 Detection"]) == 3
    assert len(result["TLS 1.1 Detection"]) == 3


# ---------------------------------------------------------------------------
# Step 3 — filter true-positives + job.counts
# ---------------------------------------------------------------------------

def _build_service():
    return ScanService(store=InMemoryScanStore())


def _patch_pipeline(monkeypatch):
    monkeypatch.setattr(scan_service_module, "validate_target_safety", lambda *a, **k: None)
    monkeypatch.setattr(scan_service_module, "resolve_targets", lambda t, **k: list(t))
    # Treat every target as reachable: the TCP pre-flight would otherwise make
    # real connect attempts to the fake *.example.com hosts and skip them all.
    monkeypatch.setattr(scan_service_module, "probe_targets", lambda t, **k: {})


def test_results_filtered_to_true_positives_only(monkeypatch):
    _patch_pipeline(monkeypatch)

    def mixed_module(targets, max_threads=20):
        return [
            {"URL": "https://a.example.com", "Status": "SECURE",   "Detail": "all good"},
            {"URL": "https://b.example.com", "Status": "INSECURE",  "Detail": "vuln found"},
            {"URL": "https://c.example.com", "Status": "WARNING",   "Detail": "check this"},
            {"URL": "https://d.example.com", "Status": "ERROR",     "Detail": "timeout"},
            {"URL": "https://e.example.com", "Status": "INFO",      "Detail": "just info"},
        ]

    monkeypatch.setattr(scanner_engine, "check_security_headers", mixed_module)

    service = _build_service()
    request = ScanCreateRequest(
        targets=["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"],
        modules=["Security Headers Check"],
    )
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    module_results = finished.results["Security Headers Check"]
    statuses = {r.status.value for r in module_results}

    assert statuses <= {"warning", "insecure"}
    assert len(module_results) == 2


def test_counts_accurate_after_filter(monkeypatch):
    _patch_pipeline(monkeypatch)

    def mixed_module(targets, max_threads=20):
        return [
            {"URL": "https://a.example.com", "Status": "SECURE",   "Detail": "ok"},
            {"URL": "https://b.example.com", "Status": "INSECURE",  "Detail": "vuln"},
            {"URL": "https://c.example.com", "Status": "WARNING",   "Detail": "warn"},
            {"URL": "https://d.example.com", "Status": "ERROR",     "Detail": "err"},
            {"URL": "https://e.example.com", "Status": "INFO",      "Detail": "info"},
        ]

    monkeypatch.setattr(scanner_engine, "check_security_headers", mixed_module)

    service = _build_service()
    request = ScanCreateRequest(
        targets=["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"],
        modules=["Security Headers Check"],
    )
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    counts = finished.counts["Security Headers Check"]
    assert counts["secure"] == 1
    assert counts["insecure"] == 1
    assert counts["warning"] == 1
    assert counts["error"] == 1
    assert counts["info"] == 1


# ---------------------------------------------------------------------------
# Step 4 — parallelism wired end-to-end
# ---------------------------------------------------------------------------

def test_parallelism_option_reaches_module(monkeypatch):
    _patch_pipeline(monkeypatch)

    captured = {}

    def capture_module(targets, max_threads=20):
        captured["max_threads"] = max_threads
        return []

    monkeypatch.setattr(scanner_engine, "check_security_headers", capture_module)

    service = _build_service()
    request = ScanCreateRequest(
        targets=["example.com"],
        modules=["Security Headers Check"],
        options=ScanOptions(parallelism=5),
    )
    job = service.create_job(request)
    service.run_scan(job.scan_id)

    assert captured.get("max_threads") == 5


# ---------------------------------------------------------------------------
# Step 5 — InMemoryScanStore lazy eviction
# ---------------------------------------------------------------------------

def test_store_evicts_expired_job():
    store = InMemoryScanStore()
    job = ScanJob(targets=["example.com"], modules=["SSL Certificate Check"])

    job.updated_at = job.updated_at - timedelta(seconds=_STORE_TTL_SECONDS + 60)
    store._jobs[job.scan_id] = job  # insert without triggering eviction

    assert store.get(job.scan_id) is None
    assert job.scan_id not in store._jobs


def test_store_keeps_fresh_job():
    store = InMemoryScanStore()
    job = ScanJob(targets=["example.com"], modules=["SSL Certificate Check"])
    store.save(job)

    assert store.get(job.scan_id) is not None
