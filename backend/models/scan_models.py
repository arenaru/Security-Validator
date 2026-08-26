from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


MODULE_NAMES: tuple[str, ...] = (
    "SSL Certificate Check",
    "SSL Certificate Hostname Mismatch",
    "SSLv3 Detection",
    "TLS 1.0 Detection",
    "TLS 1.1 Detection",
    "Response Code Check",
    "HSTS Security Check",
    "Security Headers Check",
    "Cookie Secure Flag",
    "Cookie HttpOnly Flag",
    "Laravel Debug Mode",
    "Node.js Debug Mode",
    "PHP Version Disclosure",
)


class ScanJobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    DONE = "done"
    FAILED = "failed"
    PARTIAL = "partial"


class ResultStatus(str, Enum):
    SECURE = "secure"
    WARNING = "warning"
    INSECURE = "insecure"
    ERROR = "error"
    INFO = "info"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def normalize_result_status(raw_status: str | None) -> ResultStatus:
    value = (raw_status or "").strip().lower()

    if value in {"valid", "safe", "secure", "ok"}:
        return ResultStatus.SECURE
    if value in {"warning", "warn", "expired", "invalid_status", "not found"}:
        return ResultStatus.WARNING
    if value in {"insecure", "vulnerable", "critical"}:
        return ResultStatus.INSECURE
    if value in {"error", "failed", "dns_error", "timeout"}:
        return ResultStatus.ERROR

    return ResultStatus.INFO


@dataclass(slots=True)
class ScanOptions:
    timeout_seconds: int = 30
    parallelism: int = 6


@dataclass(slots=True)
class Progress:
    completed_modules: int
    total_modules: int

    @property
    def percent(self) -> float:
        if self.total_modules <= 0:
            return 0.0
        return round((self.completed_modules / self.total_modules) * 100, 2)


@dataclass(slots=True)
class ModuleResult:
    module: str
    target: str
    status: ResultStatus
    details: str
    severity: Severity | None = None
    code: str | None = None
    vuln_name: str | None = None
    raw: dict[str, Any] | None = None

    @classmethod
    def from_legacy(cls, module: str, payload: dict[str, Any]) -> "ModuleResult":
        target = str(
            payload.get("URL")
            or payload.get("url")
            or payload.get("target")
            or payload.get("Target")
            or ""
        )
        raw_status = str(payload.get("Status") or payload.get("status") or payload.get("Category") or "")
        details = str(
            payload.get("Detail")
            or payload.get("details")
            or payload.get("Message")
            or payload.get("Error")
            or "-"
        )
        vuln_name = payload.get("vuln_name")

        return cls(
            module=module,
            target=target,
            status=normalize_result_status(raw_status),
            details=details,
            vuln_name=str(vuln_name) if vuln_name else None,
            raw=payload,
        )


@dataclass(slots=True)
class ModuleError:
    module: str
    message: str
    target: str | None = None


@dataclass(slots=True)
class ScanJob:
    targets: list[str]
    modules: list[str]
    options: ScanOptions = field(default_factory=ScanOptions)
    scan_id: str = field(default_factory=lambda: str(uuid4()))
    status: ScanJobStatus = ScanJobStatus.PENDING
    created_at: datetime = field(default_factory=utc_now)
    updated_at: datetime = field(default_factory=utc_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None
    results: dict[str, list[ModuleResult]] = field(default_factory=dict)
    errors: list[ModuleError] = field(default_factory=list)

    def progress(self) -> Progress:
        completed = len(self.results)
        total = max(len(self.modules), 1)
        return Progress(completed_modules=completed, total_modules=total)

    def touch(self) -> None:
        self.updated_at = utc_now()
