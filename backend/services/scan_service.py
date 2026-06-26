from __future__ import annotations

from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from tempfile import NamedTemporaryFile

import pandas as pd

from backend.models.scan_models import ModuleError, ModuleResult, ScanJob, ScanJobStatus, ScanOptions, utc_now
from backend.schemas.scan_schemas import ScanCreateRequest, ScanStatusResponse, ScanSummaryResponse
from backend.utils.scanner_engine import iter_scanning_engine_results


class InMemoryScanStore:
	"""Simple in-memory store for scan jobs. No database required."""

	def __init__(self) -> None:
		self._jobs: dict[str, ScanJob] = {}

	def save(self, job: ScanJob) -> None:
		self._jobs[job.scan_id] = job

	def get(self, scan_id: str) -> ScanJob | None:
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

		job = ScanJob(targets=clean_targets, modules=clean_modules, options=options)
		self.store.save(job)
		return job

	def run_scan(self, scan_id: str) -> ScanJob:
		job = self.require_job(scan_id)
		job.status = ScanJobStatus.RUNNING
		job.started_at = utc_now()
		job.finished_at = None
		job.touch()
		self.store.save(job)

		temp_path: str | None = None

		try:
			with NamedTemporaryFile(mode="w", suffix="_targets.txt", delete=False, encoding="utf-8") as temp_file:
				temp_file.write("\n".join(job.targets))
				temp_path = temp_file.name

			for module_name, payload, err in iter_scanning_engine_results(job.targets, job.modules, temp_path):
				if err is not None:
					job.results[module_name] = []
					job.errors.append(ModuleError(module=module_name, message=str(err)))
					job.touch()
					self.store.save(job)
					continue

				normalized, module_errors = self._normalize_module_output(module_name, payload)
				job.results[module_name] = normalized
				job.errors.extend(module_errors)
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
			job.errors.append(ModuleError(module="engine", message=str(exc)))
		finally:
			job.finished_at = utc_now()
			job.touch()
			self.store.save(job)
			try:
				if temp_path:
					Path(temp_path).unlink(missing_ok=True)
			except Exception:
				pass

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
	) -> tuple[list[ModuleResult], list[ModuleError]]:
		results: list[ModuleResult] = []
		errors: list[ModuleError] = []

		if payload is None:
			errors.append(ModuleError(module=module_name, message="module returned no payload"))
			return results, errors

		if module_name == "HSTS Security Check" and isinstance(payload, tuple) and len(payload) == 2:
			parsed_rows = self._flatten_hsts_tuple(payload)
			for row in parsed_rows:
				results.append(ModuleResult.from_legacy(module_name, row))
			return results, errors

		if isinstance(payload, list):
			for item in payload:
				if isinstance(item, dict):
					results.append(ModuleResult.from_legacy(module_name, item))
				else:
					errors.append(
						ModuleError(module=module_name, message="unsupported list item", target=str(item))
					)
			return results, errors

		if isinstance(payload, dict):
			results.append(ModuleResult.from_legacy(module_name, payload))
			return results, errors

		errors.append(ModuleError(module=module_name, message="unsupported payload type", target=str(type(payload))))
		return results, errors

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
