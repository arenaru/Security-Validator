"""Target lists larger than one batch are scanned in stages, not rejected."""
import pytest

from backend.models.scan_models import MAX_TARGETS_PER_SCAN, TARGET_BATCH_SIZE
from backend.schemas.scan_schemas import ScanCreateRequest
from backend.services import scan_service as scan_service_module
from backend.services.scan_service import InMemoryScanStore, ScanService
from backend.utils import scanner_engine
from backend.utils import target_resolver


def build_service():
    return ScanService(store=InMemoryScanStore())


def fake_getaddrinfo(host, port):
    return [(target_resolver.socket.AF_INET, target_resolver.socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0))]


@pytest.fixture
def batched(monkeypatch):
    """Batch after 2 targets so batching is exercised with tiny target lists."""
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(scan_service_module, "probe_targets", lambda targets, **kwargs: {})
    monkeypatch.setattr(scan_service_module, "resolve_targets", lambda targets, **kwargs: list(targets))
    monkeypatch.setattr(scan_service_module, "TARGET_BATCH_SIZE", 2)
    return monkeypatch


def make_job(service, targets, modules=("Security Headers Check",)):
    return service.create_job(ScanCreateRequest(targets=list(targets), modules=list(modules)))


def test_create_job_counts_batches(batched):
    service = build_service()
    job = make_job(service, ["a.example.com", "b.example.com", "c.example.com"])

    # 3 targets at a batch size of 2 → 2 batches.
    assert job.total_batches == 2


def test_results_accumulate_across_batches(batched):
    """Each batch must extend the module's rows, not replace the previous batch."""
    seen_batches = []

    def capture_module(targets, max_threads=20):
        seen_batches.append(list(targets))
        return [{"URL": t, "Status": "INSECURE", "Detail": "missing header"} for t in targets]

    batched.setattr(scanner_engine, "check_security_headers", capture_module)

    service = build_service()
    targets = ["a.example.com", "b.example.com", "c.example.com", "d.example.com", "e.example.com"]
    job = make_job(service, targets)
    finished = service.run_scan(job.scan_id)

    assert seen_batches == [
        ["a.example.com", "b.example.com"],
        ["c.example.com", "d.example.com"],
        ["e.example.com"],
    ]
    rows = finished.results["Security Headers Check"]
    assert [row.target for row in rows] == targets
    assert finished.counts["Security Headers Check"]["insecure"] == 5


def test_progress_is_monotonic_and_completes(batched):
    """Progress must not pin at 100% after batch 1, and must reach it at the end."""
    service = build_service()
    targets = ["a.example.com", "b.example.com", "c.example.com", "d.example.com"]
    job = make_job(service, targets, modules=["Security Headers Check", "Response Code Check"])

    percents = []

    def record(targets_arg, max_threads=20):
        percents.append(service.store.get(job.scan_id).progress().percent)
        return [{"URL": t, "Status": "SAFE", "Detail": "ok"} for t in targets_arg]

    batched.setattr(scanner_engine, "check_security_headers", record)
    batched.setattr(scanner_engine, "run_response_code_scan", record)

    finished = service.run_scan(job.scan_id)

    assert percents == sorted(percents)
    assert all(value < 100 for value in percents)

    progress = finished.progress()
    assert (progress.completed_batches, progress.total_batches) == (2, 2)
    assert progress.percent == 100.0


def test_module_failure_in_one_batch_keeps_other_batches(batched):
    """A module raising on batch 1 must not erase the rows batch 2 returns."""
    calls = {"n": 0}

    def flaky_module(targets, max_threads=20):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("module blew up on first batch")
        return [{"URL": t, "Status": "INSECURE", "Detail": "missing header"} for t in targets]

    batched.setattr(scanner_engine, "check_security_headers", flaky_module)

    service = build_service()
    job = make_job(service, ["a.example.com", "b.example.com", "c.example.com"])
    finished = service.run_scan(job.scan_id)

    rows = finished.results["Security Headers Check"]
    assert [row.target for row in rows] == ["c.example.com"]
    assert finished.status.value == "partial"
    assert len(finished.errors) == 1


def test_unreachable_batch_does_not_stop_later_batches(batched):
    """An entire batch being unreachable is not fatal; later batches still run."""
    dead = {"dead1.example.com", "dead2.example.com"}

    def probe(targets, **kwargs):
        return {
            target: target_resolver.PortProbe(
                host=target,
                open_ports=() if target in dead else (443,),
                latency_ms=None if target in dead else 12.0,
                error="connect timed out after 3s (no response)" if target in dead else None,
            )
            for target in targets
        }

    batched.setattr(scan_service_module, "probe_targets", probe)
    batched.setattr(
        scanner_engine,
        "check_security_headers",
        lambda targets, max_threads=20: [
            {"URL": t, "Status": "INSECURE", "Detail": "missing header"} for t in targets
        ],
    )

    service = build_service()
    # First batch is entirely dead, second is live.
    job = make_job(service, ["dead1.example.com", "dead2.example.com", "live.example.com"])
    finished = service.run_scan(job.scan_id)

    assert [row.target for row in finished.results["Security Headers Check"]] == ["live.example.com"]
    assert sorted(s.target for s in finished.skipped_targets) == ["dead1.example.com", "dead2.example.com"]
    assert finished.progress().percent == 100.0


def test_validate_accepts_more_than_one_batch():
    """The old behaviour rejected anything over the batch size."""
    request = ScanCreateRequest(
        targets=[f"host-{i}.example.com" for i in range(TARGET_BATCH_SIZE + 1)],
        modules=["SSL Certificate Check"],
    )

    request.validate()


def test_validate_still_rejects_above_absolute_ceiling():
    request = ScanCreateRequest(
        targets=[f"host-{i}.example.com" for i in range(MAX_TARGETS_PER_SCAN + 1)],
        modules=["SSL Certificate Check"],
    )

    with pytest.raises(ValueError, match="targets must not exceed"):
        request.validate()
