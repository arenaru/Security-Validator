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
