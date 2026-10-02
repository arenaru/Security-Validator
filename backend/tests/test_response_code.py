import requests

from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import responseCode
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.utils import scanner_engine


class _FakeResponse:
    def __init__(self, status_code, reason="OK"):
        self.status_code = status_code
        self.reason = reason


def test_https_timeout_falls_back_to_http_and_flags_fallback(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.startswith("https://"):
            raise requests.exceptions.Timeout("Connection Timeout")
        return _FakeResponse(200, "OK")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("accounts.dayaauto.co.id")

    assert calls == [
        "https://accounts.dayaauto.co.id",
        "http://accounts.dayaauto.co.id",
    ]
    assert result["URL"] == "http://accounts.dayaauto.co.id"
    assert result["Status Code"] == 200
    assert result["Category"] == "SUCCESS"
    assert result["Fallback Used"] is True
    assert "https://accounts.dayaauto.co.id" in result["Fallback Note"]
    assert "Connection Timeout" in result["Fallback Note"]
    assert "fallback" in result["Message"].lower()
    assert result["Status"] == "WARNING"


def test_https_success_has_no_fallback(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeResponse(200, "OK")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("example.com")

    assert calls == ["https://example.com"]
    assert result["URL"] == "https://example.com"
    assert result["Category"] == "SUCCESS"
    assert result["Fallback Used"] is False
    assert "Fallback Note" not in result
    assert result["Message"] == "HTTP 200 OK"
    assert result["Status"] == "WARNING"


def test_both_candidates_fail_returns_error_without_fallback_fields(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("unreachable.example.com")

    assert result["Status Code"] == "N/A"
    assert result["Category"] == "ERROR"
    assert result["Reason"] == "CONNECTION_ERROR"
    assert result["Fallback Used"] is False
    assert "Fallback Note" not in result
    assert result["Status"] == "WARNING"


def test_explicit_scheme_single_candidate_no_fallback(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeResponse(200, "OK")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("https://example.com/path")

    assert calls == ["https://example.com/path"]
    assert result["Fallback Used"] is False
    assert "Fallback Note" not in result


def _patch_pipeline(monkeypatch):
    monkeypatch.setattr("backend.services.scan_service.validate_target_safety", lambda *a, **k: None)
    monkeypatch.setattr("backend.services.scan_service.resolve_targets", lambda t, **k: list(t))


def test_all_targets_survive_true_positive_filter_including_clean_200(monkeypatch):
    """
    Regression test for the bug where Response Code Check never showed up in
    reports: _normalize_module_output filters results down to WARNING/INSECURE
    only, and every Category this module produced (SUCCESS/ERROR/etc.) used to
    normalize to INFO/ERROR, so 100% of results were silently dropped.
    """
    _patch_pipeline(monkeypatch)

    def mixed_targets(targets, max_threads=20):
        return [
            {"URL": "https://clean.example.com", "Status Code": 200, "Category": "SUCCESS",
             "Message": "HTTP 200 OK", "Fallback Used": False, "Status": "WARNING"},
            {"URL": "http://fallback.example.com", "Status Code": 200, "Category": "SUCCESS",
             "Message": "HTTP 200 OK (fallback)", "Fallback Used": True,
             "Fallback Note": "https timed out", "Status": "WARNING"},
            {"URL": "https://notfound.example.com", "Status Code": 404, "Category": "CLIENT_ERROR",
             "Message": "HTTP 404 Not Found", "Fallback Used": False, "Status": "WARNING"},
            {"URL": "https://down.example.com", "Status Code": "N/A", "Category": "ERROR",
             "Message": "Connection Timeout", "Fallback Used": False, "Status": "WARNING"},
        ]

    monkeypatch.setattr(scanner_engine, "run_response_code_scan", mixed_targets)
    monkeypatch.setattr(responseCode, "run_response_code_scan", mixed_targets)

    service = ScanService(store=InMemoryScanStore())
    request = ScanCreateRequest(
        targets=[
            "clean.example.com",
            "fallback.example.com",
            "notfound.example.com",
            "down.example.com",
        ],
        modules=["Response Code Check"],
    )
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    module_results = finished.results["Response Code Check"]
    urls = {r.target for r in module_results}

    assert urls == {
        "https://clean.example.com",
        "http://fallback.example.com",
        "https://notfound.example.com",
        "https://down.example.com",
    }
    assert len(module_results) == 4
