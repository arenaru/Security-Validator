from __future__ import annotations

import concurrent.futures
import shutil
import subprocess

from backend.utils.target_resolver import UnsafeTargetError, extract_nmap_host

_NMAP_CMD_BASE = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "-Pn"]
_NMAP_TIMEOUT = 60


def _parse_sslv3(target: str, output: str) -> dict:
    if "SSLv3" in output:
        return {
            "target": target,
            "status": "INSECURE",
            "details": "SSLv3 Detected (Deprecated)",
            "vuln_name": "Insecure Transportation Security Protocol Supported (SSLv3)",
        }
    if "TLSv" in output:
        return {"target": target, "status": "SECURE", "details": "SSLv3 Disabled"}
    return {"target": target, "status": "ERROR", "details": "No SSL Service"}


def _parse_tls10(target: str, output: str) -> dict:
    if "TLSv1.0" in output:
        return {
            "target": target,
            "status": "INSECURE",
            "details": "TLS 1.0 Detected (Deprecated)",
            "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.0)",
        }
    if "TLSv" in output or "SSLv" in output:
        return {"target": target, "status": "SECURE", "details": "TLS 1.0 Disabled"}
    return {"target": target, "status": "ERROR", "details": "No SSL Service"}


def _parse_tls11(target: str, output: str) -> dict:
    if "TLSv1.1" in output:
        return {
            "target": target,
            "status": "INSECURE",
            "details": "TLS 1.1 Detected (Deprecated)",
            "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.1)",
        }
    if "TLSv" in output or "SSLv" in output:
        return {"target": target, "status": "SECURE", "details": "TLS 1.1 Disabled"}
    return {"target": target, "status": "ERROR", "details": "No SSL Service / Connection Failed"}


def check_tls_protocols(target: str) -> dict[str, dict]:
    """
    Run one nmap ssl-enum-ciphers scan per target and derive SSLv3, TLS 1.0,
    and TLS 1.1 results from the single output, cutting nmap invocations from
    3-per-target to 1-per-target.
    """
    if not shutil.which("nmap"):
        err = {"target": target, "status": "ERROR", "details": "Nmap not installed"}
        return {
            "SSLv3 Detection": err,
            "TLS 1.0 Detection": err,
            "TLS 1.1 Detection": err,
        }

    try:
        domain_only = extract_nmap_host(target)
    except UnsafeTargetError as exc:
        err = {"target": target, "status": "ERROR", "details": str(exc)}
        return {
            "SSLv3 Detection": err,
            "TLS 1.0 Detection": err,
            "TLS 1.1 Detection": err,
        }

    try:
        process = subprocess.run(
            _NMAP_CMD_BASE + [domain_only],
            capture_output=True,
            text=True,
            timeout=_NMAP_TIMEOUT,
        )
        output = process.stdout
        return {
            "SSLv3 Detection": _parse_sslv3(target, output),
            "TLS 1.0 Detection": _parse_tls10(target, output),
            "TLS 1.1 Detection": _parse_tls11(target, output),
        }

    except Exception as exc:
        err = {"target": target, "status": "ERROR", "details": str(exc)[:200]}
        return {
            "SSLv3 Detection": err,
            "TLS 1.0 Detection": err,
            "TLS 1.1 Detection": err,
        }


def run_tls_scan(targets_list: list[str], max_threads: int = 20) -> dict[str, list[dict]]:
    """
    Scan all targets for SSLv3/TLS1.0/TLS1.1 in parallel, running nmap once
    per target (not once per protocol). Returns a dict keyed by module name.
    """
    combined: dict[str, list] = {
        "SSLv3 Detection": [None] * len(targets_list),
        "TLS 1.0 Detection": [None] * len(targets_list),
        "TLS 1.1 Detection": [None] * len(targets_list),
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_tls_protocols, target): index
            for index, target in enumerate(targets_list)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            result = future.result()
            for module_name in combined:
                combined[module_name][index] = result[module_name]

    return {k: [r for r in v if r is not None] for k, v in combined.items()}
