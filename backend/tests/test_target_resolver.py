import pytest
import requests

from backend.utils import target_resolver
from backend.utils.target_resolver import (
    UnsafeTargetError,
    build_target_candidates,
    extract_host,
    extract_nmap_host,
    is_safe_hostname_format,
    resolve_reachable_target,
    validate_target_safety,
)


def fake_getaddrinfo(ips):
    def _getaddrinfo(host, port):
        return [(target_resolver.socket.AF_INET, target_resolver.socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in ips]

    return _getaddrinfo


class FakeResponse:
    def close(self):
        pass


def test_build_target_candidates_bare_target():
    assert build_target_candidates("example.com") == ["https://example.com", "http://example.com"]


def test_build_target_candidates_bare_target_with_path():
    assert build_target_candidates("example.com/app?q=1") == [
        "https://example.com/app?q=1",
        "http://example.com/app?q=1",
    ]


def test_build_target_candidates_respects_explicit_https():
    assert build_target_candidates("https://example.com") == ["https://example.com"]


def test_build_target_candidates_respects_explicit_http():
    assert build_target_candidates("http://example.com") == ["http://example.com"]


def test_build_target_candidates_strips_trailing_slash():
    assert build_target_candidates("example.com/") == ["https://example.com", "http://example.com"]


def test_extract_host_variants():
    assert extract_host("https://example.com:8443/path") == "example.com"
    assert extract_host("example.com:8443") == "example.com"
    assert extract_host("https://[2001:db8::1]:443/") == "2001:db8::1"
    assert extract_host("1.2.3.4") == "1.2.3.4"
    assert extract_host("example.com.") == "example.com"
    assert extract_host("") == ""


@pytest.mark.parametrize(
    "host",
    ["example.com", "sub.example.co.id", "a-b.example.com", "exa_mple.internal", "1.2.3.4", "::1", "2001:db8::1"],
)
def test_is_safe_hostname_format_accepts_valid(host):
    assert is_safe_hostname_format(host)


@pytest.mark.parametrize(
    "host",
    ["", "-oN/tmp/pwn", "--script", "a b", "a;b", "a|b", "foo\nbar", "example.com:8443"],
)
def test_is_safe_hostname_format_rejects_invalid(host):
    assert not is_safe_hostname_format(host)


def test_validate_target_safety_rejects_private_ip(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["10.0.0.5"]))

    with pytest.raises(UnsafeTargetError, match="blocked network range"):
        validate_target_safety("internal.example.com")


def test_validate_target_safety_rejects_mixed_public_and_private(monkeypatch):
    monkeypatch.setattr(
        target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["93.184.216.34", "192.168.1.10"])
    )

    with pytest.raises(UnsafeTargetError, match="192.168.1.10"):
        validate_target_safety("roundrobin.example.com")


def test_validate_target_safety_accepts_public_ip(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["93.184.216.34"]))

    validate_target_safety("example.com")


def test_validate_target_safety_allows_private_when_opted_in(monkeypatch):
    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", fake_getaddrinfo(["127.0.0.1"]))

    validate_target_safety("localhost", allow_private=True)


def test_validate_target_safety_rejects_unresolvable(monkeypatch):
    def _getaddrinfo(host, port):
        raise target_resolver.socket.gaierror("name resolution failed")

    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", _getaddrinfo)

    with pytest.raises(UnsafeTargetError, match="cannot resolve"):
        validate_target_safety("nope.invalid")


def test_validate_target_safety_rejects_bad_format_without_resolution(monkeypatch):
    def _fail(host, port):
        raise AssertionError("getaddrinfo must not be called for malformed targets")

    monkeypatch.setattr(target_resolver.socket, "getaddrinfo", _fail)

    with pytest.raises(UnsafeTargetError, match="invalid target format"):
        validate_target_safety("-oN /tmp/pwn")


def test_extract_nmap_host_valid():
    assert extract_nmap_host("https://example.com/path") == "example.com"
    assert extract_nmap_host("example.com") == "example.com"


def test_extract_nmap_host_rejects_flag_like():
    with pytest.raises(UnsafeTargetError, match="invalid nmap target"):
        extract_nmap_host("--script=blah")


def test_resolve_reachable_target_prefers_https(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)

    assert resolve_reachable_target("example.com") == "https://example.com"
    assert calls == ["https://example.com"]


def test_resolve_reachable_target_falls_back_to_http(monkeypatch):
    def fake_get(url, **kwargs):
        if url.startswith("https://"):
            raise requests.exceptions.ConnectionError("no tls")
        return FakeResponse()

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)

    assert resolve_reachable_target("example.com") == "http://example.com"


def test_resolve_reachable_target_returns_original_when_unreachable(monkeypatch):
    def fake_get(url, **kwargs):
        raise requests.exceptions.ConnectionError("down")

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)

    assert resolve_reachable_target("example.com") == "example.com"


def test_resolve_reachable_target_keeps_https_on_tls_error(monkeypatch):
    """
    A TLS failure means port 443 answered, so the HTTPS URL must be kept.
    Downgrading to http:// here would make every downstream module (HSTS,
    Cookie Secure, ...) scan plain HTTP and report cascading false positives.
    SSLError subclasses ConnectionError, so this guards clause ordering too.
    """
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        if url.startswith("https://"):
            raise requests.exceptions.SSLError("certificate has expired")
        return FakeResponse()

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)

    assert resolve_reachable_target("example.com") == "https://example.com"
    assert calls == ["https://example.com"]


# ---------------------------------------------------------------------------
# TCP pre-flight
# ---------------------------------------------------------------------------


class FakeSocket:
    """Minimal socket stub driven by a {port: outcome} map."""

    def __init__(self, outcomes):
        self._outcomes = outcomes
        self.timeout = None
        self.closed = False

    def settimeout(self, timeout):
        self.timeout = timeout

    def connect(self, address):
        outcome = self._outcomes.get(address[1], "timeout")
        if outcome == "open":
            return None
        if outcome == "refused":
            raise ConnectionRefusedError("connection refused")
        raise target_resolver.socket.timeout("timed out")

    def close(self):
        self.closed = True


def patch_sockets(monkeypatch, outcomes):
    """Patch socket.socket so probes resolve from the given {port: outcome} map."""
    created = []

    def factory(*args, **kwargs):
        sock = FakeSocket(outcomes)
        created.append(sock)
        return sock

    monkeypatch.setattr(target_resolver.socket, "socket", factory)
    return created


def test_probe_host_ports_records_open_ports_and_latency(monkeypatch):
    patch_sockets(monkeypatch, {443: "open", 80: "open"})

    probe = target_resolver.probe_host_ports("example.com")

    assert probe.is_reachable is True
    assert probe.open_ports == (443, 80)
    assert probe.latency_ms is not None
    assert probe.error is None


def test_probe_host_ports_reports_dropped_packets(monkeypatch):
    patch_sockets(monkeypatch, {})

    probe = target_resolver.probe_host_ports("blackhole.example.com")

    assert probe.is_reachable is False
    assert probe.open_ports == ()
    assert probe.latency_ms is None
    assert "dropped" in probe.error


def test_probe_host_ports_closes_every_socket(monkeypatch):
    created = patch_sockets(monkeypatch, {443: "open", 80: "refused"})

    target_resolver.probe_host_ports("example.com")

    assert created and all(sock.closed for sock in created)


def test_probe_host_ports_slow_but_live_host_stays_reachable(monkeypatch):
    """
    Latency is diagnostic only. A slow host that still completes the connect is
    a real host, so gating on milliseconds would turn it into a false negative.
    """
    patch_sockets(monkeypatch, {443: "open"})

    ticks = iter([0.0, 4.0])
    monkeypatch.setattr(target_resolver.time, "perf_counter", lambda: next(ticks))

    probe = target_resolver.probe_host_ports("slow.example.com", ports=(443,))

    assert probe.is_reachable is True
    assert probe.latency_ms == 4000.0


def test_probe_targets_dedupes_hosts(monkeypatch):
    probed = []

    def fake_probe(host, ports=None, timeout=None):
        probed.append(host)
        return target_resolver.PortProbe(host=host, open_ports=(443,), latency_ms=1.0)

    monkeypatch.setattr(target_resolver, "probe_host_ports", fake_probe)

    probes = target_resolver.probe_targets(
        ["example.com", "https://example.com/path", "other.example.com"]
    )

    assert sorted(probed) == ["example.com", "other.example.com"]
    assert probes["example.com"].is_reachable is True
    assert probes["https://example.com/path"].is_reachable is True


def test_candidates_for_probe_narrows_to_open_ports():
    https_only = target_resolver.PortProbe(host="example.com", open_ports=(443,))
    http_only = target_resolver.PortProbe(host="example.com", open_ports=(80,))
    closed = target_resolver.PortProbe(host="example.com", open_ports=())

    assert target_resolver.candidates_for_probe("example.com", https_only) == [
        "https://example.com"
    ]
    assert target_resolver.candidates_for_probe("example.com", http_only) == [
        "http://example.com"
    ]
    assert target_resolver.candidates_for_probe("example.com", closed) == []


def test_resolve_reachable_target_skips_closed_scheme(monkeypatch):
    """Only port 80 answered, so no HTTP request should be spent on HTTPS."""
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)
    probe = target_resolver.PortProbe(host="example.com", open_ports=(80,))

    assert resolve_reachable_target("example.com", probe=probe) == "http://example.com"
    assert calls == ["http://example.com"]


def test_resolve_reachable_target_makes_no_request_when_all_ports_closed(monkeypatch):
    calls = []

    def fake_get(url, **kwargs):
        calls.append(url)
        return FakeResponse()

    monkeypatch.setattr(target_resolver.requests, "get", fake_get)
    probe = target_resolver.PortProbe(host="example.com", open_ports=())

    assert resolve_reachable_target("example.com", probe=probe) == "example.com"
    assert calls == []


def test_partition_by_reachability_splits_and_explains():
    probes = {
        "live.example.com": target_resolver.PortProbe(
            host="live.example.com", open_ports=(443,), latency_ms=12.3
        ),
        "dead.example.com": target_resolver.PortProbe(
            host="dead.example.com",
            open_ports=(),
            error="connect timed out after 3s (packets dropped)",
        ),
    }

    reachable, unreachable = target_resolver.partition_by_reachability(
        ["live.example.com", "dead.example.com"], probes
    )

    assert reachable == ["live.example.com"]
    assert len(unreachable) == 1
    target, reason = unreachable[0]
    assert target == "dead.example.com"
    assert "unreachable" in reason
    assert "dropped" in reason


def test_partition_by_reachability_keeps_unprobed_targets():
    """A missing probe must not silently drop a target."""
    reachable, unreachable = target_resolver.partition_by_reachability(["example.com"], {})

    assert reachable == ["example.com"]
    assert unreachable == []
