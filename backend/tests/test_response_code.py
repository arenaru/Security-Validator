import requests

from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import responseCode
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.utils import scanner_engine


class _FakeResponse:
    """Minimal stand-in for requests.Response.

    ``history`` is non-empty when the request was redirected, mirroring what
    requests populates when allow_redirects=True.
    """

    def __init__(self, status_code, reason="OK", url=None, history=()):
        self.status_code = status_code
        self.reason = reason
        self.url = url or ""
        self.history = list(history)


def test_redirect_reports_both_first_and_final_code(monkeypatch):
    """
    The module must follow redirects and report where the request landed, so it
    agrees with a browser, curl -L, and other response-code tools. Reporting
    only the first hop said "308" for a host that actually answers 200.

    Both codes are kept: the final one is the answer, the first is the context.
    """
    hop = _FakeResponse(308, "Permanent Redirect", url="https://unit.example.com")

    def fake_get(url, **kwargs):
        assert kwargs["allow_redirects"] is True
        return _FakeResponse(200, "OK", url="https://unit.example.com/product", history=[hop])

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("unit.example.com")

    assert result["Status Code"] == 308
    assert result["Final Code"] == 200
    assert result["Final URL"] == "https://unit.example.com/product"
    assert result["Redirects"] == 1
    assert result["Message"] == "HTTP 308 -> 200 OK"


def test_no_redirect_reports_identical_first_and_final_code(monkeypatch):
    monkeypatch.setattr(
        responseCode.requests, "get",
        lambda url, **kwargs: _FakeResponse(200, "OK", url="https://example.com"),
    )

    result = responseCode.check_response_code("example.com")

    assert result["Status Code"] == 200
    assert result["Final Code"] == 200
    assert result["Redirects"] == 0
    assert result["Message"] == "HTTP 200 OK"


def test_module_reports_codes_verbatim_without_severity(monkeypatch):
    """
    Pure recon: the module reports the code and nothing else. A 401 on an
    auth-gated API and a 404 on an unused path are facts about the host, not
    findings, so no Status/Category/severity field may be emitted. Labelling
    them WARNING is what produced the false positives this module used to have.
    """
    for code, reason in ((200, "OK"), (301, "Moved"), (401, "Unauthorized"),
                         (403, "Forbidden"), (404, "Not Found"), (503, "Unavailable")):
        monkeypatch.setattr(
            responseCode.requests, "get",
            lambda url, _c=code, _r=reason, **kwargs: _FakeResponse(_c, _r, url=url),
        )

        result = responseCode.check_response_code("example.com")

        assert result["Status Code"] == code, f"{code} must be reported verbatim"
        assert result["Final Code"] == code
        assert "Status" not in result
        assert "Category" not in result


def test_forbidden_document_is_reported_as_forbidden(monkeypatch):
    """A 403 on the document is reported as 403 — never masked as 200."""
    monkeypatch.setattr(
        responseCode.requests, "get",
        lambda url, **kwargs: _FakeResponse(403, "Forbidden", url="https://example.com"),
    )

    result = responseCode.check_response_code("example.com")

    assert result["Status Code"] == 403
    assert result["Final Code"] == 403
    assert result["Message"] == "HTTP 403 Forbidden"


def test_sends_browser_like_headers(monkeypatch):
    """
    A bare User-Agent is enough of an outlier that some WAFs answer 403, which
    would then be reported as the target's real response code.
    """
    seen = {}

    def fake_get(url, **kwargs):
        seen.update(kwargs["headers"])
        return _FakeResponse(200, "OK", url=url)

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    responseCode.check_response_code("example.com")

    assert "User-Agent" in seen
    assert "Accept" in seen
    assert "Accept-Language" in seen


def test_tls_error_does_not_downgrade_to_http(monkeypatch):
    """
    A broken TLS layer means port 443 answered, so HTTPS exists and is
    misconfigured. Falling back to HTTP would report a different service's code
    as this target's. SSLError subclasses ConnectionError, so this also guards
    the except-clause ordering in check_response_code.
    """
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("certificate verify failed: certificate has expired")
        return _FakeResponse(200, "OK", url=url)

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("expired.example.com")

    assert calls == ["https://expired.example.com"]
    assert result["Status Code"] == "N/A"
    assert result["Reason"] == "TLS_ERROR"
    assert "certificate has expired" in result["Message"]


def test_redirect_loop_is_reported_not_raised(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.TooManyRedirects("exceeded 30 redirects")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("loop.example.com")

    assert result["Status Code"] == "N/A"
    assert result["Reason"] == "REDIRECT_LOOP"


def test_timeout_is_retried_before_giving_up(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if len(calls) == 1:
            raise requests.exceptions.Timeout("transient")
        return _FakeResponse(200, "OK", url=url)

    monkeypatch.setattr(responseCode.requests, "get", fake_get)
    monkeypatch.setattr(responseCode.time, "sleep", lambda _: None)

    result = responseCode.check_response_code("flaky.example.com")

    assert calls == ["https://flaky.example.com", "https://flaky.example.com"]
    assert result["Final Code"] == 200


def test_connection_error_is_not_retried(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    responseCode.check_response_code("down.example.com")

    assert calls == ["https://down.example.com", "http://down.example.com"]


def test_unreachable_target_reports_na_with_reason(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.ConnectionError("refused")

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    result = responseCode.check_response_code("unreachable.example.com")

    assert result["Status Code"] == "N/A"
    assert result["Final Code"] == "N/A"
    assert result["Reason"] == "CONNECTION_ERROR"
    assert "Status" not in result


def test_explicit_scheme_yields_single_candidate(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return _FakeResponse(200, "OK", url=url)

    monkeypatch.setattr(responseCode.requests, "get", fake_get)

    responseCode.check_response_code("https://example.com/path")

    assert calls == ["https://example.com/path"]


def _patch_pipeline(monkeypatch):
    monkeypatch.setattr("backend.services.scan_service.validate_target_safety", lambda *a, **k: None)
    monkeypatch.setattr("backend.services.scan_service.resolve_targets", lambda t, **k: list(t))
    # Treat every target as reachable: the TCP pre-flight would otherwise make
    # real connect attempts to the fake *.example.com hosts and skip them all.
    monkeypatch.setattr("backend.services.scan_service.probe_targets", lambda t, **k: {})


def _mixed_targets(targets, max_threads=20):
    """Realistic module output: codes only, no status field."""
    return [
        {"URL": "https://clean.example.com", "Status Code": 200, "Final Code": 200,
         "Final URL": "https://clean.example.com", "Reason": "OK", "Redirects": 0,
         "Message": "HTTP 200 OK"},
        {"URL": "https://redirect.example.com", "Status Code": 308, "Final Code": 200,
         "Final URL": "https://redirect.example.com/product", "Reason": "OK", "Redirects": 1,
         "Message": "HTTP 308 -> 200 OK"},
        {"URL": "https://notfound.example.com", "Status Code": 404, "Final Code": 404,
         "Final URL": "https://notfound.example.com", "Reason": "Not Found", "Redirects": 0,
         "Message": "HTTP 404 Not Found"},
        {"URL": "https://down.example.com", "Status Code": "N/A", "Final Code": "N/A",
         "Final URL": "https://down.example.com", "Reason": "CONNECTION_ERROR", "Redirects": 0,
         "Message": "Connection refused or host unreachable"},
    ]


def _run_response_code_job(monkeypatch):
    _patch_pipeline(monkeypatch)
    monkeypatch.setattr(scanner_engine, "run_response_code_scan", _mixed_targets)
    monkeypatch.setattr(responseCode, "run_response_code_scan", _mixed_targets)

    service = ScanService(store=InMemoryScanStore())
    request = ScanCreateRequest(
        targets=[
            "clean.example.com",
            "redirect.example.com",
            "notfound.example.com",
            "down.example.com",
        ],
        modules=["Response Code Check"],
    )
    job = service.create_job(request)
    return service.run_scan(job.scan_id)


def test_every_scanned_target_survives_the_true_positive_filter(monkeypatch):
    """
    _normalize_module_output filters results down to WARNING/INSECURE, which
    would drop every row this module produces. Rows survive via the
    INFORMATIONAL_MODULES bypass, so each scanned target stays visible.
    """
    finished = _run_response_code_job(monkeypatch)

    module_results = finished.results["Response Code Check"]

    assert {r.target for r in module_results} == {
        "https://clean.example.com",
        "https://redirect.example.com",
        "https://notfound.example.com",
        "https://down.example.com",
    }
    assert len(module_results) == 4


def test_recon_rows_are_info_and_never_findings(monkeypatch):
    """
    With no Status field, normalize_result_status falls through to INFO. A 404
    must not land in WARNING/INSECURE, or it becomes a remediation action item.
    """
    finished = _run_response_code_job(monkeypatch)

    statuses = {r.status.value for r in finished.results["Response Code Check"]}

    assert statuses == {"info"}
    assert finished.counts["Response Code Check"]["info"] == 4
    assert finished.counts["Response Code Check"]["warning"] == 0
    assert finished.counts["Response Code Check"]["insecure"] == 0


def test_informational_module_does_not_degrade_domain_worst(monkeypatch):
    """
    A healthy HTTP 200 — or an auth-gated 404 — must not push a domain's overall
    verdict to warning. The module is excluded from domain_worst aggregation.
    """
    finished = _run_response_code_job(monkeypatch)

    assert finished.domain_worst == {}
