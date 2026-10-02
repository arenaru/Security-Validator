from __future__ import annotations

import concurrent.futures
import ipaddress
import re
import socket
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

PROBE_TIMEOUT = (3, 5)
PROBE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
}

# A TCP connect is orders of magnitude cheaper than an HTTP request: it needs no
# TLS handshake and no response body, so it can run at high concurrency. Hosts
# that silently DROP packets (rather than sending RST) otherwise cost a full
# timeout per scheme per module, which is what pushes large subdomain lists past
# the job deadline.
PORT_PROBE_TIMEOUT = 3.0
HTTPS_PORT = 443
HTTP_PORT = 80

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


@dataclass(slots=True)
class PortProbe:
    """Outcome of a TCP connect probe against a host's HTTP(S) ports."""

    host: str
    open_ports: tuple[int, ...] = ()
    latency_ms: float | None = None
    error: str | None = None

    @property
    def is_reachable(self) -> bool:
        return bool(self.open_ports)


_SCHEME_PORTS = {"https": HTTPS_PORT, "http": HTTP_PORT}


def probe_host_ports(
    host: str,
    ports: tuple[int, ...] = (HTTPS_PORT, HTTP_PORT),
    timeout: float = PORT_PROBE_TIMEOUT,
) -> PortProbe:
    """
    TCP-connect to each port and record which answered, plus the fastest
    connect latency. Latency is diagnostic only: a slow-but-live host is still
    a real host, so reachability is decided by connect success, never by how
    many milliseconds it took.
    """
    if not host:
        return PortProbe(host=host, error="empty host")

    open_ports: list[int] = []
    best_ms: float | None = None
    last_error: str | None = None

    for port in ports:
        sock = socket.socket()
        sock.settimeout(timeout)
        started = time.perf_counter()
        try:
            sock.connect((host, port))
            elapsed_ms = (time.perf_counter() - started) * 1000
            open_ports.append(port)
            if best_ms is None or elapsed_ms < best_ms:
                best_ms = elapsed_ms
        except socket.timeout:
            last_error = f"connect timed out after {timeout:.0f}s (packets dropped)"
        except OSError as exc:
            last_error = f"{type(exc).__name__}: {str(exc)[:60]}"
        finally:
            sock.close()

    return PortProbe(
        host=host,
        open_ports=tuple(open_ports),
        latency_ms=round(best_ms, 1) if best_ms is not None else None,
        error=None if open_ports else last_error,
    )


def probe_targets(
    targets: list[str],
    max_threads: int = 50,
    timeout: float = PORT_PROBE_TIMEOUT,
) -> dict[str, PortProbe]:
    """
    Probe many targets concurrently, keyed by original target string. Hosts are
    de-duplicated so a repeated host is only probed once.
    """
    if not targets:
        return {}

    host_by_target = {target: extract_host(target) for target in targets}
    unique_hosts = {host for host in host_by_target.values() if host}

    probes: dict[str, PortProbe] = {}
    if unique_hosts:
        workers = max(1, min(max_threads, len(unique_hosts)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            futures = {
                executor.submit(probe_host_ports, host, (HTTPS_PORT, HTTP_PORT), timeout): host
                for host in unique_hosts
            }
            for future in concurrent.futures.as_completed(futures):
                host = futures[future]
                try:
                    probes[host] = future.result()
                except Exception as exc:
                    probes[host] = PortProbe(host=host, error=f"probe failed: {str(exc)[:60]}")

    return {
        target: probes.get(host, PortProbe(host=host, error="could not extract host"))
        for target, host in host_by_target.items()
    }


def candidates_for_probe(target: str, probe: PortProbe) -> list[str]:
    """
    Narrow request candidates to schemes whose port actually answered. Skipping
    a scheme whose port is closed avoids paying a full connect timeout for it.
    """
    candidates = build_target_candidates(target)
    if not probe.open_ports:
        return []
    return [
        candidate
        for candidate in candidates
        if _SCHEME_PORTS.get(urlparse(candidate).scheme.lower()) in probe.open_ports
    ]


def resolve_reachable_target(
    target: str,
    timeout: tuple[float, float] = PROBE_TIMEOUT,
    probe: PortProbe | None = None,
) -> str:
    """
    Probe a target and return the first candidate that answers with any HTTP
    response. Falls back to the original target when nothing answers.

    A TLS failure on the HTTPS candidate does NOT downgrade to HTTP: port 443
    answered, so an HTTPS service exists and is simply misconfigured. Returning
    the HTTP URL here would hide the TLS defect and make every downstream
    module (HSTS, Cookie Secure, ...) report the target as plain-HTTP insecure.

    When a PortProbe is supplied, candidates are narrowed to schemes whose port
    answered, so no HTTP request is spent on a closed or black-holed port.
    """
    if probe is not None:
        candidates = candidates_for_probe(target, probe)
        if not candidates:
            return str(target or "").strip()
    else:
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
        except requests.exceptions.SSLError:
            # TLS is broken but present — keep HTTPS, do not try HTTP.
            return candidate
        except requests.exceptions.RequestException:
            continue
    return str(target or "").strip()


def resolve_targets(
    targets: list[str],
    max_threads: int = 10,
    probes: dict[str, PortProbe] | None = None,
) -> list[str]:
    """
    Resolve reachable target URLs in parallel, preserving input order.

    When probes are supplied, each target only attempts schemes whose port
    answered the TCP pre-flight.
    """
    if not targets:
        return []

    resolved: list[str | None] = [None] * len(targets)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(
                resolve_reachable_target,
                target,
                PROBE_TIMEOUT,
                probes.get(target) if probes else None,
            ): index
            for index, target in enumerate(targets)
        }
        for future in concurrent.futures.as_completed(futures):
            index = futures[future]
            try:
                resolved[index] = future.result()
            except Exception:
                resolved[index] = targets[index]

    return [target or "" for target in resolved]


def partition_by_reachability(
    targets: list[str],
    probes: dict[str, PortProbe],
) -> tuple[list[str], list[tuple[str, str]]]:
    """
    Split targets into (reachable, unreachable) using pre-flight results.
    Unreachable entries carry a human-readable reason for reporting, so a
    skipped host stays visible instead of vanishing from the report.
    """
    reachable: list[str] = []
    unreachable: list[tuple[str, str]] = []

    for target in targets:
        probe = probes.get(target)
        if probe is None or probe.is_reachable:
            reachable.append(target)
            continue
        reason = probe.error or "no HTTP(S) port answered"
        unreachable.append((target, f"unreachable: {reason}"))

    return reachable, unreachable
