from __future__ import annotations

import concurrent.futures
import socket

import requests
import urllib3

from backend.utils.target_resolver import extract_host

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

_BATCH_URL = "http://ip-api.com/batch"
_BATCH_FIELDS = "status,message,country,countryCode,city,isp,org,as,query"
_BATCH_TIMEOUT = 15


def _resolve_to_ip(target: str) -> tuple[str, str | None, str | None]:
    """Resolve a target to its IPv4 address (IPv6 as fallback). Returns (target, ip, error)."""
    host = extract_host(target)
    if not host:
        return target, None, "Could not extract host from target"
    try:
        infos = socket.getaddrinfo(host, None)
        ipv4 = [i for i in infos if i[0] == socket.AF_INET]
        ip = (ipv4 or infos)[0][4][0]
        return target, ip, None
    except socket.gaierror as exc:
        return target, None, f"DNS resolution failed: {str(exc)[:100]}"
    except Exception as exc:
        return target, None, f"Error resolving host: {str(exc)[:100]}"


def _batch_lookup(ips: list[str]) -> dict[str, dict]:
    """POST to ip-api.com/batch and return a dict mapping ip -> response dict."""
    payload = [{"query": ip} for ip in ips]
    response = requests.post(
        f"{_BATCH_URL}?fields={_BATCH_FIELDS}",
        json=payload,
        timeout=_BATCH_TIMEOUT,
    )
    response.raise_for_status()
    data = response.json()
    return {item["query"]: item for item in data if "query" in item}


def run_ip_country_scan(targets_list: list[str], max_threads: int = 20) -> list[dict]:
    """
    Resolve each target to an IP, batch-query geolocation via ip-api.com in one
    request, and return results in original target order.
    """
    valid_targets = [t for t in targets_list if t and t.strip()]
    if not valid_targets:
        return []

    resolve_results: list[tuple[str, str | None, str | None] | None] = [None] * len(valid_targets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_resolve_to_ip, target): index
            for index, target in enumerate(valid_targets)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                resolve_results[index] = future.result()
            except Exception as exc:
                resolve_results[index] = (valid_targets[index], None, str(exc)[:100])

    ip_to_indices: dict[str, list[int]] = {}
    dns_errors: dict[int, str] = {}

    for index, (target, ip, error) in enumerate(resolve_results):
        if error:
            dns_errors[index] = error
        else:
            ip_to_indices.setdefault(ip, []).append(index)

    ip_results: dict[str, dict] = {}
    batch_error: str | None = None

    if ip_to_indices:
        try:
            ip_results = _batch_lookup(list(ip_to_indices.keys()))
        except Exception as exc:
            batch_error = f"ip-api.com batch request failed: {str(exc)[:150]}"

    results: list[dict] = []
    for index, (target, ip, _) in enumerate(resolve_results):
        if index in dns_errors:
            results.append({"URL": target, "Status": "ERROR", "Detail": dns_errors[index]})
            continue

        if batch_error:
            results.append({"URL": target, "Status": "ERROR", "Detail": batch_error})
            continue

        api_data = ip_results.get(ip, {})
        if api_data.get("status") == "fail":
            message = api_data.get("message", "lookup failed")
            results.append({"URL": target, "Status": "ERROR", "Detail": f"ip-api lookup failed: {message}"})
            continue

        results.append({
            "URL": target,
            "Status": "WARNING",
            "Detail": api_data.get("country", "-"),
            "IP": ip,
            "Country": api_data.get("country", "-"),
            "Country Code": api_data.get("countryCode", "-"),
            "City": api_data.get("city", "-"),
            "ISP": api_data.get("isp", "-"),
            "Org": api_data.get("org", "-"),
            "AS": api_data.get("as", "-"),
        })

    return results
