from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = (3, 5)
PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,253}$)"
    r"[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?"
    r"(\.[a-z0-9]([a-z0-9_-]{0,61}[a-z0-9])?)*$"
)

BLOCKED_IP_CHECKS = (
    "is_private",
    "is_loopback",
    "is_link_local",
    "is_reserved",
    "is_multicast",
    "is_unspecified",
)


class UnsafeTargetError(ValueError):
    """Raised when a target is malformed, unresolvable, or points to a blocked network range."""


def extract_host(target: str) -> str:
    """Extract the bare hostname/IP (no scheme, port, path, or brackets) from a target string."""
    target = str(target or "").strip()
    if not target:
        return ""
    if "://" not in target:
        target = f"https://{target}"
    host = urlparse(target).hostname or ""
    return host.rstrip(".")


def is_safe_hostname_format(host: str) -> bool:
    """Return True for well-formed hostnames and IP literals (blocks nmap flag injection)."""
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(HOSTNAME_PATTERN.match(host.lower()))


def is_blocked_ip(ip: str) -> bool:
    """Return True when an IP falls in a private/loopback/link-local/reserved range."""
    address = ipaddress.ip_address(ip)
    return any(getattr(address, check) for check in BLOCKED_IP_CHECKS)


def resolve_target_ips(host: str) -> list[str]:
    """Resolve a hostname to its unique IP addresses."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise UnsafeTargetError(f"cannot resolve host '{host}'") from exc

    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in ips:
            ips.append(ip)
    return ips


def validate_target_safety(target: str, allow_private: bool = False) -> None:
    """
    Validate a scan target: hostname format, DNS resolution, and (unless
    allow_private is set) private/loopback/link-local/resolved network ranges.
    """
    host = extract_host(target)
    if not is_safe_hostname_format(host):
        raise UnsafeTargetError(f"invalid target format: '{target}'")

    ips = resolve_target_ips(host)
    if allow_private:
        return

    blocked = [ip for ip in ips if is_blocked_ip(ip)]
    if blocked:
        raise UnsafeTargetError(
            f"target '{target}' resolves to a blocked network range: {', '.join(blocked)}"
        )


def extract_nmap_host(target: str) -> str:
    """Extract a validated hostname/IP for nmap argv, rejecting flag-like input."""
    host = extract_host(target)
    if not is_safe_hostname_format(host):
        raise UnsafeTargetError(f"invalid nmap target: '{target}'")
    return host


def build_target_candidates(target: str) -> list[str]:
    """
    Build request candidates for a target. An explicit scheme in the input is
    respected (single candidate); otherwise HTTPS is tried before HTTP.
    """
    target = str(target or "").strip().rstrip("/")
    if not target:
        return []
    if target.startswith(("http://", "https://")):
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if parsed.query:
            path = f"{path}?{parsed.query}"
        return list(dict.fromkeys([f"{parsed.scheme.lower()}://{host}{path}"]))
    return [f"https://{target}", f"http://{target}"]


def resolve_reachable_target(target: str, timeout: tuple[float, float] = PROBE_TIMEOUT) -> str:
    """
    Probe a target once and return the first candidate that answers with any
    HTTP response. Falls back to the original target when nothing answers.
    """
    candidates = build_target_candidates(target)
    for candidate in candidates:
        try:
            response = requests.get(
                candidate,
                timeout=timeout,
                verify=False,
                allow_redirects=True,
                stream=True,
                headers=PROBE_HEADERS,
            )
            response.close()
            return candidate
        except requests.exceptions.RequestException:
            continue
    return str(target or "").strip()


def resolve_targets(targets: list[str], max_threads: int = 10) -> list[str]:
    """Resolve reachable target URLs in parallel, preserving input order."""
    if not targets:
        return []

    resolved: list[str | None] = [None] * len(targets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(resolve_reachable_target, target): index
            for index, target in enumerate(targets)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                resolved[index] = future.result()
            except Exception:
                resolved[index] = targets[index]

    return [target or "" for target in resolved]
