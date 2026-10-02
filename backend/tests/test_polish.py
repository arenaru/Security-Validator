from backend.models.scan_models import ModuleResult
from backend.models.scan_models import ScanOptions
from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import scan_service as scan_service_module
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.services import laravelCheck, nodeDebug
from backend.utils import scanner_engine


class FakeResponse:
    def __init__(self, status_code, text):
        self.status_code = status_code
        self.text = text


def make_fake_session():
    class FakeSession:
        instances = []

        def __init__(self):
            self.calls = []
            self.closed = False
            FakeSession.instances.append(self)

        def get(self, url, **kwargs):
            self.calls.append(("GET", url))
            return FakeResponse(404, "")

        def request(self, method, url, **kwargs):
            self.calls.append((method, url))
            return FakeResponse(200, "")

        def close(self):
            self.closed = True

    return FakeSession


def test_laravel_scan_reuses_one_session_per_target(monkeypatch):
    fake_session = make_fake_session()
    monkeypatch.setattr(laravelCheck.requests, "Session", fake_session)

    result = laravelCheck.scan_single_target("https://example.com")

    assert result["status"] == "SECURE"
    assert len(fake_session.instances) == 1
    session = fake_session.instances[0]
    assert len(session.calls) == 14
    assert session.closed is True


def test_node_scan_reuses_one_session_per_target(monkeypatch):
    fake_session = make_fake_session()
    monkeypatch.setattr(nodeDebug.requests, "Session", fake_session)

    result = nodeDebug.scan_single_target("https://example.com")

    assert result["status"] == "SECURE"
    assert len(fake_session.instances) == 1
    session = fake_session.instances[0]
    assert len(session.calls) == 9
    assert session.closed is True


def test_from_legacy_truncates_long_details():
    payload = {"URL": "https://example.com", "Status": "SECURE", "Detail": "x" * 500}

    result = ModuleResult.from_legacy("SSL Certificate Check", payload)

    assert len(result.details) == 200
    assert result.raw["Detail"] == "x" * 500


def test_run_scan_truncates_long_module_errors(monkeypatch):
    monkeypatch.setattr(scan_service_module, "validate_target_safety", lambda *args, **kwargs: None)
    monkeypatch.setattr(scan_service_module, "resolve_targets", lambda targets, **kwargs: list(targets))
    # Treat every target as reachable: the TCP pre-flight would otherwise make
    # real connect attempts to the fake example.com host.
    monkeypatch.setattr(scan_service_module, "probe_targets", lambda targets, **kwargs: {})

    def exploding_module(targets, max_threads=20):
        raise RuntimeError("boom" * 300)

    monkeypatch.setattr(scanner_engine, "check_security_headers", exploding_module)

    service = ScanService(store=InMemoryScanStore())
    request = ScanCreateRequest(
        targets=["example.com"],
        modules=["Security Headers Check"],
        options=ScanOptions(timeout_seconds=30),
    )
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    assert finished.status.value in {"partial", "failed"}
    assert finished.errors
    assert all(len(error.message) <= 200 for error in finished.errors)
    assert finished.errors[0].message == ("boom" * 300)[:200]
