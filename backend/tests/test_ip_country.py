import socket

import pytest
import requests as requests_lib

from backend.services import ipCountry
from backend.services.ipCountry import run_ip_country_scan


class FakeResponse:
    def __init__(self, data):
        self._data = data

    def raise_for_status(self):
        pass

    def json(self):
        return self._data


def fake_getaddrinfo_ip(ip):
    def _getaddrinfo(host, port):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]
    return _getaddrinfo


def _geo_entry(ip, country="United States", country_code="US", city="Los Angeles",
               isp="Example ISP", org="Example Org", asn="AS12345 Example"):
    return {
        "query": ip,
        "status": "success",
        "country": country,
        "countryCode": country_code,
        "city": city,
        "isp": isp,
        "org": org,
        "as": asn,
    }


# ---------------------------------------------------------------------------
# DNS resolution
# ---------------------------------------------------------------------------

def test_resolves_hostname_to_ip(monkeypatch):
    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo_ip("93.184.216.34"))
    monkeypatch.setattr(
        ipCountry.requests, "post",
        lambda url, **kwargs: FakeResponse([_geo_entry("93.184.216.34")])
    )

    results = run_ip_country_scan(["example.com"])

    assert len(results) == 1
    assert results[0]["IP"] == "93.184.216.34"
    assert results[0]["Status"] == "INFO"


# ---------------------------------------------------------------------------
# Successful batch lookup
# ---------------------------------------------------------------------------

def test_batch_lookup_populates_all_fields(monkeypatch):
    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo_ip("1.2.3.4"))
    monkeypatch.setattr(
        ipCountry.requests, "post",
        lambda url, **kwargs: FakeResponse([
            _geo_entry("1.2.3.4", country="Germany", country_code="DE",
                       city="Berlin", isp="Deutsche Telekom", org="DT AG", asn="AS3320 DT")
        ])
    )

    results = run_ip_country_scan(["https://example.de"])

    assert results[0]["Country"] == "Germany"
    assert results[0]["Country Code"] == "DE"
    assert results[0]["City"] == "Berlin"
    assert results[0]["ISP"] == "Deutsche Telekom"
    assert results[0]["AS"] == "AS3320 DT"
    assert results[0]["Detail"] == "Germany"


def test_results_preserve_input_order(monkeypatch):
    call_count = [0]

    def fake_getaddrinfo(host, port):
        ip = f"1.0.0.{call_count[0] + 1}"
        call_count[0] += 1
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    def fake_post(url, **kwargs):
        payload = kwargs["json"]
        return FakeResponse([_geo_entry(item["query"], country=f"Country-{item['query']}") for item in payload])

    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(ipCountry.requests, "post", fake_post)

    targets = [f"https://t{i}.example.com" for i in range(5)]
    results = run_ip_country_scan(targets)

    assert len(results) == 5
    assert [r["URL"] for r in results] == targets


# ---------------------------------------------------------------------------
# Shared IP deduplication
# ---------------------------------------------------------------------------

def test_shared_ip_sends_one_query_to_api(monkeypatch):
    batch_calls = []

    def fake_post(url, **kwargs):
        batch_calls.append(kwargs["json"])
        return FakeResponse([_geo_entry("5.5.5.5")])

    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo_ip("5.5.5.5"))
    monkeypatch.setattr(ipCountry.requests, "post", fake_post)

    results = run_ip_country_scan(["https://a.example.com", "https://b.example.com"])

    assert len(batch_calls) == 1
    assert len(batch_calls[0]) == 1
    assert batch_calls[0][0]["query"] == "5.5.5.5"
    assert all(r["IP"] == "5.5.5.5" for r in results)
    assert all(r["Status"] == "INFO" for r in results)


# ---------------------------------------------------------------------------
# DNS failure
# ---------------------------------------------------------------------------

def test_dns_failure_produces_error_result(monkeypatch):
    api_calls = []

    def fail_getaddrinfo(host, port):
        raise socket.gaierror("Name or service not known")

    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fail_getaddrinfo)
    monkeypatch.setattr(ipCountry.requests, "post", lambda *a, **kw: api_calls.append(1) or FakeResponse([]))

    results = run_ip_country_scan(["https://nope.invalid"])

    assert len(results) == 1
    assert results[0]["Status"] == "ERROR"
    assert "DNS" in results[0]["Detail"]
    assert len(api_calls) == 0


# ---------------------------------------------------------------------------
# Batch API failure
# ---------------------------------------------------------------------------

def test_batch_api_failure_produces_error_for_all(monkeypatch):
    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo_ip("1.2.3.4"))

    def fail_post(url, **kwargs):
        raise requests_lib.exceptions.ConnectionError("api unreachable")

    monkeypatch.setattr(ipCountry.requests, "post", fail_post)

    results = run_ip_country_scan(["a.example.com", "b.example.com"])

    assert all(r["Status"] == "ERROR" for r in results)
    assert all("batch request failed" in r["Detail"] for r in results)


# ---------------------------------------------------------------------------
# Partial batch failure (single entry status: fail)
# ---------------------------------------------------------------------------

def test_partial_batch_failure(monkeypatch):
    ips = {"good.example.com": "1.1.1.1", "bad.example.com": "2.2.2.2"}

    def fake_getaddrinfo(host, port):
        ip = ips.get(host, "0.0.0.0")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))]

    def fake_post(url, **kwargs):
        return FakeResponse([
            _geo_entry("1.1.1.1", country="Australia"),
            {"query": "2.2.2.2", "status": "fail", "message": "reserved range"},
        ])

    monkeypatch.setattr(ipCountry.socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(ipCountry.requests, "post", fake_post)

    results = run_ip_country_scan(["good.example.com", "bad.example.com"])

    good = next(r for r in results if r["URL"] == "good.example.com")
    bad = next(r for r in results if r["URL"] == "bad.example.com")

    assert good["Status"] == "INFO"
    assert good["Country"] == "Australia"
    assert bad["Status"] == "ERROR"
    assert "reserved range" in bad["Detail"]


# ---------------------------------------------------------------------------
# Empty input
# ---------------------------------------------------------------------------

def test_empty_input_returns_empty_without_api_call(monkeypatch):
    api_calls = []
    monkeypatch.setattr(ipCountry.requests, "post", lambda *a, **kw: api_calls.append(1))

    assert run_ip_country_scan([]) == []
    assert run_ip_country_scan(["", "   "]) == []
    assert len(api_calls) == 0
