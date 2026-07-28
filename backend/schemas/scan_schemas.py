from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any
from urllib.parse import urlparse

from backend.models.scan_models import (
    MODULE_NAMES,
    ModuleError,
    ModuleResult,
    Progress,
    ResultStatus,
    ScanJob,
    ScanJobStatus,
    ScanOptions,
)


@dataclass(slots=True)
class ScanCreateRequest:
    targets: list[str]
    modules: list[str]
    options: ScanOptions = field(default_factory=ScanOptions)

    def validate(self) -> None:
        if not self.targets:
            raise ValueError("targets must not be empty")
        if not self.modules:
            raise ValueError("modules must not be empty")

        invalid_modules = [name for name in self.modules if name not in MODULE_NAMES]
        if invalid_modules:
            raise ValueError(f"unknown modules: {', '.join(invalid_modules)}")


@dataclass(slots=True)
class HealthResponse:
    status: str
    service: str
    version: str
    time: datetime
    dependencies: dict[str, str]


@dataclass(slots=True)
class ScanAcceptedResponse:
    scan_id: str
    status: ScanJobStatus
    created_at: datetime
    message: str = "Scan accepted"


@dataclass(slots=True)
class ScanStatusResponse:
    scan_id: str
    status: ScanJobStatus
    created_at: datetime
    updated_at: datetime
    started_at: datetime | None
    finished_at: datetime | None
    targets: list[str]
    modules: list[str]
    progress: Progress
    results: dict[str, list[ModuleResult]] | None
    errors: list[ModuleError]

    @classmethod
    def from_job(cls, job: ScanJob, include_results: bool = True) -> "ScanStatusResponse":
        return cls(
            scan_id=job.scan_id,
            status=job.status,
            created_at=job.created_at,
            updated_at=job.updated_at,
            started_at=job.started_at,
            finished_at=job.finished_at,
            targets=job.targets,
            modules=job.modules,
            progress=job.progress(),
            results=job.results if include_results else None,
            errors=job.errors,
        )


@dataclass(slots=True)
class ModuleSummary:
    module: str
    count: int
    secure: int = 0
    warning: int = 0
    insecure: int = 0
    error: int = 0


@dataclass(slots=True)
class SummaryTotals:
    items: int
    secure: int
    warning: int
    insecure: int
    error: int


@dataclass(slots=True)
class ScanSummaryResponse:
    scan_id: str
    by_module: list[ModuleSummary]
    totals: SummaryTotals

    @classmethod
    def from_job(cls, job: ScanJob) -> "ScanSummaryResponse":
        by_module: list[ModuleSummary] = []
        totals = {"items": 0, "secure": 0, "warning": 0, "insecure": 0, "error": 0}
        domain_status: dict[str, ResultStatus] = {}

        for target in job.targets:
            domain = normalize_target_domain(target)
            if domain:
                domain_status.setdefault(domain, ResultStatus.INFO)

        for module_name in job.modules:
            items = job.results.get(module_name, [])
            summary = ModuleSummary(module=module_name, count=len(items))

            for item in items:
                if item.status == ResultStatus.SECURE:
                    summary.secure += 1
                elif item.status == ResultStatus.WARNING:
                    summary.warning += 1
                elif item.status == ResultStatus.INSECURE:
                    summary.insecure += 1
                elif item.status == ResultStatus.ERROR:
                    summary.error += 1

                domain = normalize_target_domain(item.target)
                if domain:
                    current_status = domain_status.get(domain, ResultStatus.INFO)
                    domain_status[domain] = merge_domain_status(current_status, item.status)

            by_module.append(summary)

        for status in domain_status.values():
            effective_status = ResultStatus.ERROR if status == ResultStatus.INFO else status
            totals["items"] += 1
            if effective_status == ResultStatus.SECURE:
                totals["secure"] += 1
            elif effective_status == ResultStatus.WARNING:
                totals["warning"] += 1
            elif effective_status == ResultStatus.INSECURE:
                totals["insecure"] += 1
            elif effective_status == ResultStatus.ERROR:
                totals["error"] += 1

        return cls(
            scan_id=job.scan_id,
            by_module=by_module,
            totals=SummaryTotals(**totals),
        )


@dataclass(slots=True)
class ErrorDetail:
    field: str
    message: str


@dataclass(slots=True)
class ErrorPayload:
    code: str
    message: str
    trace_id: str


@dataclass(slots=True)
class ErrorResponse:
    error: ErrorPayload
    details: list[ErrorDetail] | None = None


def normalize_target_domain(target: str) -> str:
    target = str(target or "").strip()
    if not target:
        return ""

    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        target = parsed.netloc or parsed.path

    target = target.split("/")[0]
    if ":" in target:
        target = target.split(":")[0]

    return target.strip().lower()


def merge_domain_status(current: ResultStatus, next_status: ResultStatus) -> ResultStatus:
    priority = {
        ResultStatus.ERROR: 4,
        ResultStatus.INSECURE: 3,
        ResultStatus.WARNING: 2,
        ResultStatus.SECURE: 1,
        ResultStatus.INFO: 0,
    }
    return next_status if priority[next_status] > priority.get(current, 0) else current


def to_dict(payload: Any) -> dict[str, Any]:
    """Serialize dataclasses to plain dict with existing field names."""
    return asdict(payload)
