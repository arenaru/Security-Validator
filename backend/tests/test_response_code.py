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
    monkeypatch.setattr(responseCode.time, "sleep", lambda _: None)

    result = responseCode.check_response_code("accounts.dayaauto.co.id")

    # HTTPS is retried once on timeout before the HTTP downgrade.
    assert calls == [
        "https://accounts.dayaauto.co.id",
        "https://accounts.dayaauto.co.id",
        "http://accounts.dayaauto.co.id",
    ]
    assert result["URL"] == "http://accounts.dayaauto.co.id"
    assert result["Status Code"] == 200
    assert result["Category"] == "SUCCESS"
    assert result["Fallback Used"] is True
    assert "https://accounts.dayaauto.co.id" in result["Fallback Note"]
    assert "timed out" in result["Fallback Note"]
    assert "fallback" in result["Message"].lower()
    assert result["Status"] == "INFO"


def test_tls_error_does_not_downgrade_to_http(monkeypatch):
    """
    A broken TLS layer means port 443 answered, so HTTPS exists and is
    misconfigured. Falling back to HTTP would report a healthy 200 and bury a
    real finding. SSLError subclasses ConnectionError, so this also guards the
    except-clause ordering in check_response_code.
    """
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("certificate verify failed: certificate has expired")
        return _FakeResponse(200, "OK")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("expired.example.com")

    assert calls == ["https://expired.example.com"]
    assert result["URL"] == "https://expired.example.com"
    assert result["Category"] == "TLS_ERROR"
    assert result["Status"] == "WARNING"
    assert result["Fallback Used"] is False
    assert "certificate has expired" in result["Message"]


def test_timeout_is_retried_before_giving_up(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            raise requests.exceptions.Timeout("transient")
        return _FakeResponse(200, "OK")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)
    monkeypatch.setattr(responseCode.time, "sleep", lambda _: None)

    result = responseCode.check_response_code("flaky.example.com")

    assert calls == ["https://flaky.example.com", "https://flaky.example.com"]
    assert result["Status Code"] == 200
    assert result["Fallback Used"] is False


def test_connection_error_is_not_retried(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    responseCode.check_response_code("down.example.com")

    assert calls == ["https://down.example.com", "http://down.example.com"]


def test_client_and_server_errors_are_warnings(monkeypatch):
    def make(status, reason):
        def fake_get(url, **kwargs):
            return _FakeResponse(status, reason)
        return fake_get

    for status, reason, category in (
        (404, "Not Found", "CLIENT_ERROR"),
        (500, "Internal Server Error", "SERVER_ERROR"),
    ):
        monkeypatch.setattr(responseCode.requests, "get", make(status, reason))
        result = responseCode.check_response_code("example.com")
        assert result["Category"] == category
        assert result["Status"] == "WARNING"


def test_redirect_is_informational(monkeypatch):
    monkeypatch.setattr(
        responseCode.requests, "get",
        lambda url, **kwargs: _FakeResponse(301, "Moved Permanently"),
    )

    result = responseCode.check_response_code("example.com")

    assert result["Category"] == "REDIRECT"
    assert result["Status"] == "INFO"


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
    assert result["Status"] == "INFO"


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
    assert result["Status"] == "ERROR"


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


def _mixed_targets(targets, max_threads=20):
    """Realistic module output: honest per-category statuses, no forced WARNING."""
    return [
        {"URL": "https://clean.example.com", "Status Code": 200, "Category": "SUCCESS",
         "Message": "HTTP 200 OK", "Fallback Used": False, "Status": "INFO"},
        {"URL": "http://fallback.example.com", "Status Code": 200, "Category": "SUCCESS",
         "Message": "HTTP 200 OK (fallback)", "Fallback Used": True,
         "Fallback Note": "https timed out", "Status": "INFO"},
        {"URL": "https://notfound.example.com", "Status Code": 404, "Category": "CLIENT_ERROR",
         "Message": "HTTP 404 Not Found", "Fallback Used": False, "Status": "WARNING"},
        {"URL": "https://down.example.com", "Status Code": "N/A", "Category": "ERROR",
         "Message": "Connection Timeout", "Fallback Used": False, "Status": "ERROR"},
    ]


def test_all_targets_survive_true_positive_filter_including_clean_200(monkeypatch):
    """
    Regression test for the bug where Response Code Check never showed up in
    reports: _normalize_module_output filters results down to WARNING/INSECURE,
    which dropped every row this module produced. The module used to force
    every Status to WARNING to work around it; now it reports honest statuses
    and survives via the INFORMATIONAL_MODULES bypass instead.
    """
    _patch_pipeline(monkeypatch)

    monkeypatch.setattr(scanner_engine, "run_response_code_scan", _mixed_targets)
    monkeypatch.setattr(responseCode, "run_response_code_scan", _mixed_targets)

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


def test_informational_module_does_not_degrade_domain_worst(monkeypatch):
    """
    A healthy HTTP 200 must not push a domain's overall verdict to warning.
    Before the fix every row was forced to WARNING and fed into
    merge_domain_status, so a clean target was reported as degraded.
    """
    _patch_pipeline(monkeypatch)

    monkeypatch.setattr(scanner_engine, "run_response_code_scan", _mixed_targets)
    monkeypatch.setattr(responseCode, "run_response_code_scan", _mixed_targets)

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

    assert finished.domain_worst == {}
