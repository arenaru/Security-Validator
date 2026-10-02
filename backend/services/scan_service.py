from __future__ import annotations

import concurrent.futures
from dataclasses import dataclass
from io import BytesIO

import pandas as pd

from backend.models.scan_models import INFORMATIONAL_MODULES, ModuleError, ModuleResult, ResultStatus, ScanJob, ScanJobStatus, ScanOptions, SkippedTarget, TRUE_POSITIVE_STATUSES, utc_now
from backend.schemas.scan_schemas import ScanCreateRequest, ScanStatusResponse, ScanSummaryResponse, merge_domain_status, normalize_target_domain
from backend.utils.scanner_engine import iter_scanning_engine_results
from backend.utils.target_resolver import (
	UnsafeTargetError,
	partition_by_reachability,
	probe_targets,
	resolve_targets,
	validate_target_safety,
)


_STORE_TTL_SECONDS = 4 * 3600  # 4 hours

# TCP connects are cheap (no TLS, no body), so the pre-flight runs far wider
# than job parallelism, which governs the expensive HTTP modules.
_PORT_PROBE_THREADS = 50


class InMemoryScanStore:
	"""Simple in-memory store for scan jobs. No database required."""

	def __init__(self) -> None:
		self._jobs: dict[str, ScanJob] = {}

	def _evict_expired(self, ttl_seconds: int = _STORE_TTL_SECONDS) -> None:
		cutoff = utc_now().timestamp() - ttl_seconds
		expired = [
			scan_id for scan_id, job in self._jobs.items()
			if job.updated_at.timestamp() < cutoff
		]
		for scan_id in expired:
			del self._jobs[scan_id]

	def save(self, job: ScanJob) -> None:
		self._evict_expired()
		self._jobs[job.scan_id] = job

	def get(self, scan_id: str) -> ScanJob | None:
		self._evict_expired()
		return self._jobs.get(scan_id)


@dataclass(slots=True)
class ScanService:
	store: InMemoryScanStore

	def create_job(self, request: ScanCreateRequest) -> ScanJob:
		request.validate()

		clean_targets = [item.strip() for item in request.targets if item and item.strip()]
		if not clean_targets:
			raise ValueError("targets must not be empty")

		clean_modules = [item for item in request.modules if item]
		if not clean_modules:
			raise ValueError("modules must not be empty")

		options = request.options if isinstance(request.options, ScanOptions) else ScanOptions()

		valid_targets, skipped = self._validate_targets(
			clean_targets,
			allow_private=options.allow_private_targets,
			workers=max(1, options.parallelism),
		)

		if not valid_targets:
			skipped_summary = "; ".join(f"{s.target}: {s.reason}" for s in skipped)
			raise ValueError(f"no valid targets remaining after validation — skipped: {skipped_summary}")

		job = ScanJob(targets=valid_targets, modules=clean_modules, options=options, skipped_targets=skipped)
		self.store.save(job)
		return job

	def _validate_targets(self, targets: list[str], allow_private: bool, workers: int = 10) -> tuple[list[str], list[SkippedTarget]]:
		if not targets:
			return [], []

		results: list[tuple[str, str | None]] = [(t, None) for t in targets]
		with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
			futures = {
				executor.submit(validate_target_safety, target, allow_private): index
				for index, target in enumerate(targets)
			}
			for future in concurrent.futures.as_completed(futures):
				index = futures[future]
				try:
					future.result()
				except UnsafeTargetError as exc:
					results[index] = (targets[index], str(exc))

		valid_targets: list[str] = []
		skipped: list[SkippedTarget] = []
		for target, error in results:
			if error is None:
				valid_targets.append(target)
			else:
				skipped.append(SkippedTarget(target=target, reason=error))

		return valid_targets, skipped

	def run_scan(self, scan_id: str) -> ScanJob:
		job = self.require_job(scan_id)
		job.status = ScanJobStatus.RUNNING
		job.started_at = utc_now()
		job.finished_at = None
		job.touch()
		self.store.save(job)

		try:
			# TCP pre-flight before any HTTP work. Hosts that silently drop
			# packets otherwise cost a full connect timeout per scheme per
			# module, which is what pushes large subdomain lists (often inflated
			# by wildcard DNS) past the job deadline. A TCP connect needs no TLS
			# handshake, so it can run at much higher concurrency than the scan
			# modules themselves.
			probes = probe_targets(job.targets, max_threads=_PORT_PROBE_THREADS)
			reachable, unreachable = partition_by_reachability(job.targets, probes)

			for target, reason in unreachable:
				job.skipped_targets.append(SkippedTarget(target=target, reason=reason))
			if unreachable:
				job.touch()
				self.store.save(job)

			if not reachable:
				job.status = ScanJobStatus.DONE
				return job

			resolved_targets = resolve_targets(
				reachable,
				max_threads=max(1, job.options.parallelism),
				probes=probes,
			)

			for module_name, payload, err in iter_scanning_engine_results(
				resolved_targets,
				job.modules,
				timeout=job.options.timeout_seconds,
				parallelism=max(1, job.options.parallelism),
			):
				if err is not None:
					job.results[module_name] = []
					job.counts[module_name] = {"secure": 0, "warning": 0, "insecure": 0, "error": 1, "info": 0}
					job.errors.append(ModuleError(module=module_name, message=str(err)[:200]))
					job.touch()
					self.store.save(job)
					continue

				normalized, module_errors, module_counts = self._normalize_module_output(module_name, payload)
				job.results[module_name] = normalized
				job.counts[module_name] = module_counts
				job.errors.extend(module_errors)
				if module_name not in INFORMATIONAL_MODULES:
					for item in normalized:
						domain = normalize_target_domain(item.target)
						if domain:
							current = job.domain_worst.get(domain, ResultStatus.INFO)
							job.domain_worst[domain] = merge_domain_status(current, item.status)
				job.touch()
				self.store.save(job)

			if job.errors and job.results:
				job.status = ScanJobStatus.PARTIAL
			elif job.errors and not job.results:
				job.status = ScanJobStatus.FAILED
			else:
				job.status = ScanJobStatus.DONE

		except Exception as exc:
			job.status = ScanJobStatus.FAILED
			job.errors.append(ModuleError(module="engine", message=str(exc)[:200]))
		finally:
			job.finished_at = utc_now()
			job.touch()
			self.store.save(job)

		return job

	def get_status(self, scan_id: str, include_results: bool = True) -> ScanStatusResponse:
		job = self.require_job(scan_id)
		return ScanStatusResponse.from_job(job, include_results=include_results)

	def get_summary(self, scan_id: str) -> ScanSummaryResponse:
		job = self.require_job(scan_id)
		return ScanSummaryResponse.from_job(job)

	def build_xlsx_report(self, scan_id: str) -> bytes:
		job = self.require_job(scan_id)

		summary_rows = []
		for module_name in job.modules:
			module_items = job.results.get(module_name, [])
			summary_rows.append({"module": module_name, "count": len(module_items)})

		bio = BytesIO()
		with pd.ExcelWriter(bio, engine="openpyxl") as writer:
			pd.DataFrame(summary_rows).to_excel(writer, index=False, sheet_name="summary")

			for module_name in job.modules:
				module_items = job.results.get(module_name, [])
				rows = [
					{
						"module": item.module,
						"target": item.target,
						"status": item.status.value,
						"details": item.details,
						"severity": item.severity.value if item.severity else None,
						"code": item.code,
						"vuln_name": item.vuln_name,
					}
					for item in module_items
				]
				df = pd.DataFrame(rows)
				sheet_name = module_name[:31] if module_name else "results"
				df.to_excel(writer, index=False, sheet_name=sheet_name)

		return bio.getvalue()

	def require_job(self, scan_id: str) -> ScanJob:
		job = self.store.get(scan_id)
		if not job:
			raise KeyError(f"scan_id not found: {scan_id}")
		return job

	def _normalize_module_output(
		self,
		module_name: str,
		payload: object,
	) -> tuple[list[ModuleResult], list[ModuleError], dict[str, int]]:
		all_results: list[ModuleResult] = []
		errors: list[ModuleError] = []

		if payload is None:
			errors.append(ModuleError(module=module_name, message="module returned no payload"))
			return [], errors, {"secure": 0, "warning": 0, "insecure": 0, "error": 0, "info": 0}

		if module_name == "HSTS Security Check" and isinstance(payload, tuple) and len(payload) == 2:
			for row in self._flatten_hsts_tuple(payload):
				all_results.append(ModuleResult.from_legacy(module_name, row))

		elif isinstance(payload, list):
			for item in payload:
				if isinstance(item, dict):
					all_results.append(ModuleResult.from_legacy(module_name, item))
				else:
					errors.append(ModuleError(module=module_name, message="unsupported list item", target=str(item)))

		elif isinstance(payload, dict):
			all_results.append(ModuleResult.from_legacy(module_name, payload))

		else:
			errors.append(ModuleError(module=module_name, message="unsupported payload type", target=str(type(payload))))

		counts = {"secure": 0, "warning": 0, "insecure": 0, "error": 0, "info": 0}
		for r in all_results:
			counts[r.status.value] = counts.get(r.status.value, 0) + 1

		if module_name in INFORMATIONAL_MODULES:
			return all_results, errors, counts

		filtered = [r for r in all_results if r.status in TRUE_POSITIVE_STATUSES]
		return filtered, errors, counts

	def _flatten_hsts_tuple(self, payload: tuple[object, object]) -> list[dict[str, object]]:
		secure_list, failed_list = payload
		output: list[dict[str, object]] = []

		if isinstance(secure_list, list):
			for item in secure_list:
				row = self._parse_hsts_line(item, default_status="SECURE")
				if row:
					output.append(row)

		if isinstance(failed_list, list):
			for item in failed_list:
				row = self._parse_hsts_line(item, default_status="INSECURE")
				if row:
					output.append(row)

		return output

	def _parse_hsts_line(self, raw: object, default_status: str) -> dict[str, object] | None:
		if not isinstance(raw, str):
			return None

		parts = [chunk.strip() for chunk in raw.split(" | ")]
		if not parts:
			return None

		target = parts[0]

		if len(parts) >= 3 and parts[1] == "ERROR":
			return {"URL": target, "Status": "ERROR", "Detail": parts[2]}
		if len(parts) >= 4 and parts[1] == "HTTP_STATUS":
			return {
				"URL": target,
				"Status": "INVALID_STATUS",
				"Detail": f"HTTP {parts[2]} {parts[3]}",
			}
		if len(parts) >= 4 and parts[1] == "NOT_FOUND":
			return {
				"URL": target,
				"Status": "NOT FOUND",
				"Detail": f"HTTP {parts[2]} {parts[3]}",
			}
		if len(parts) >= 2:
			detail = parts[1]
			status = default_status
			return {"URL": target, "Status": status, "Detail": detail}

		return {"URL": target, "Status": "INFO", "Detail": "Unknown HSTS result"}
