import pytest

from backend.models.scan_models import ScanOptions
from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import scan_service as scan_service_module
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.utils import target_resolver
from backend.utils import scanner_engine


def build_service():
    store = InMemoryScanStore()
    return ScanService(store=store)


def fake_getaddrinfo(ips):
    def _getaddrinfo(host, port):
        return [(target_resolver.socket.AF_INET, target_resolver.socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]

    return _getaddrinfo


def test_create_job_rejects_private_target(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["127.0.0.1"]))

    service = build_service()
    request = ScanCreateRequest(targets=["internal.example.com"], modules=["SSL Certificate Check"])

    with pytest.raises(ValueError, match="blocked network range"):
        service.create_job(request)


def test_create_job_rejects_unresolvable_target(monkeypatch):
    def _getaddrinfo(host, port):
        raise target_resolver.socket.gaierror("name resolution failed")

    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", _getaddrinfo)

    service = build_service()
    request = ScanCreateRequest(targets=["gone.example.com"], modules=["SSL Certificate Check"])

    with pytest.raises(ValueError, match="cannot resolve"):
        service.create_job(request)


def test_create_job_allows_private_when_opted_in(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["10.1.2.3"]))
    monkeypatch.setattr(scan_service_module, "resolve_targets", lambda targets, **kwargs: list(targets))

    service = build_service()
    request = ScanCreateRequest(
        targets=["internal.example.com"],
        modules=["SSL Certificate Check"],
        options=ScanOptions(allow_private_targets=True),
    )

    job = service.create_job(request)
    assert job.targets == ["internal.example.com"]
    assert job.options.allow_private_targets is True


def test_create_job_lists_every_unsafe_target(monkeypatch):
    def _getaddrinfo(host, port):
        if host == "bad.example.com":
            return [(target_resolver.socket.AF_INET, 2, 6, "", ("169.254.169.254", 0))]
        return [(target_resolver.socket.AF_INET, 2, 6, "", ("93.184.216.34", 0))]

    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", _getaddrinfo)

    service = build_service()
    request = ScanCreateRequest(
        targets=["good.example.com", "bad.example.com"],
        modules=["SSL Certificate Check"],
    )

    with pytest.raises(ValueError, match="169.254.169.254"):
        service.create_job(request)


def test_run_scan_passes_resolved_targets_to_modules(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["93.184.216.34"]))
    monkeypatch.setattr(
        scan_service_module,
        "resolve_targets",
        lambda targets, **kwargs: [f"https://{target}" for target in targets],
    )

    captured = {}

    def capture_module(targets):
        captured["targets"] = targets
        return [{"URL": "https://example.com", "Status": "SECURE", "Detail": "ok"}]

    monkeypatch.setattr(scanner_engine, "check_security_headers", capture_module)

    service = build_service()
    request = ScanCreateRequest(targets=["example.com"], modules=["Security Headers Check"])
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    assert captured["targets"] == ["https://example.com"]
    assert finished.targets == ["example.com"]
    assert finished.results["Security Headers Check"][0].target == "https://example.com"


def test_run_scan_keeps_original_target_when_unreachable(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["93.184.216.34"]))
    monkeypatch.setattr(scan_service_module, "resolve_targets", lambda targets, **kwargs: list(targets))

    def fast_module(targets):
        return [{"URL": targets[0], "Status": "SECURE", "Detail": "ok"}]

    monkeypatch.setattr(scanner_engine, "check_security_headers", fast_module)

    service = build_service()
    request = ScanCreateRequest(targets=["example.com"], modules=["Security Headers Check"])
    job = service.create_job(request)
    finished = service.run_scan(job.scan_id)

    assert finished.status.value == "done"
    assert finished.results["Security Headers Check"][0].target == "example.com"
