"""All-in-one Acunetix-mode detectors.

This file consolidates the previously separate detector scripts under ./script into one module.
The scan engine (utils/scanner_engine.py) imports detectors from here.

Detectors included:
- SSL certificate expiry/validation
- HSTS header presence
- Common security headers presence
- Cookie Secure flag checking
- Laravel debug / Ignition exposure
- Node.js dev-mode stack trace exposure
- PHP version disclosure via headers
- SSLv3 / TLS 1.0 / TLS 1.1 support via nmap ssl-enum-ciphers
"""

from __future__ import annotations

import concurrent.futures
import math
import re
import shutil
import socket
import ssl
import subprocess
from datetime import datetime
from urllib.parse import urlparse

import pytz
import requests
import urllib3


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================
# Shared helpers
# ============================

_WIB = pytz.timezone("Asia/Jakarta")


def _fix_url(url: str) -> str:
    u = (url or "").strip()
    if not u:
        return u
    if not u.startswith("http"):
        u = "https://" + u
    return u.rstrip("/")


def _sanitize_domain(domain: str) -> str:
    d = (domain or "").strip()
    if d.startswith("http://") or d.startswith("https://"):
        d = urlparse(d).netloc
    return d.split("/")[0]


# ============================
# SSL Certificate Expiry
# ============================

def cek_ssl_expiry(domain: str, port: int = 443, warning_days: int = 30) -> dict:
    context = ssl.create_default_context()

    result = {
        "URL": f"https://{domain}",
        "Status": "Error",
        "Sisa Hari": "-",
        "Expired Date": "-",
        "Detail": "-",
        "vuln_name": None,
    }

    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

                expiry_date_utc = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                expiry_date_wib = expiry_date_utc.replace(tzinfo=pytz.utc).astimezone(_WIB)
                now = datetime.now(pytz.utc).astimezone(_WIB)
                delta = expiry_date_wib - now
                days_remaining = math.ceil(delta.total_seconds() / 86400)

                result["Expired Date"] = expiry_date_wib.strftime("%d-%m-%Y")
                result["Sisa Hari"] = days_remaining

                if days_remaining < 0:
                    result["Status"] = "EXPIRED"
                    result["Detail"] = "Certificate has expired"
                    result["vuln_name"] = "Invalid SSL Certificate"
                elif days_remaining < warning_days:
                    result["Status"] = "WARNING"
                    result["Detail"] = f"Expiring soon ({days_remaining} days)"
                    result["vuln_name"] = "SSL Certificate Is About To Expire"
                else:
                    result["Status"] = "VALID"
                    result["Detail"] = "Certificate is valid"
                    result["vuln_name"] = None

    except ssl.CertificateError:
        result["Status"] = "WARNING"
        result["Detail"] = "Hostname Mismatch"
        result["vuln_name"] = "SSL Certificate Name Hostname Mismatch"
    except ssl.SSLError:
        result["Status"] = "WARNING"
        result["Detail"] = "Self-Signed / Handshake Failed"
        result["vuln_name"] = "Invalid SSL Certificate"
    except socket.timeout:
        result["Status"] = "Error"
        result["Detail"] = "Connection Timeout (Web Down)"
        result["vuln_name"] = None
    except socket.gaierror:
        result["Status"] = "Error"
        result["Detail"] = "DNS Error (Domain not found)"
        result["vuln_name"] = None
    except Exception as e:
        result["Status"] = "Error"
        result["Detail"] = str(e)
        result["vuln_name"] = None

    return result


def run_ssl_scan(list_file_path: str) -> list[dict]:
    output_data: list[dict] = []
    try:
        with open(list_file_path, "r", encoding="utf-8") as f:
            domains = [_sanitize_domain(line) for line in f if line.strip()]
        for domain in domains:
            if not domain:
                continue
            output_data.append(cek_ssl_expiry(domain))
    except Exception as e:
        print(f"Error reading file: {e}")
    return output_data


# ============================
# HSTS
# ============================

_HSTS_TIMEOUT = 10
_HSTS_THREADS = 20
_HSTS_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"


def run_hsts_scan(targets: list[str]) -> tuple[list[str], list[str]]:
    results_aman: list[str] = []
    results_gagal: list[str] = []

    def scan_single(url: str):
        target = (url or "").strip()
        if not target:
            return False, "- | ERROR | Empty target"
        if not target.startswith("http"):
            target = f"https://{target}"

        headers = {"User-Agent": _HSTS_UA}
        try:
            r = requests.get(target, headers=headers, timeout=_HSTS_TIMEOUT, verify=False, allow_redirects=True)
            hsts = r.headers.get("Strict-Transport-Security")
            if hsts:
                if "max-age=0" in hsts.lower():
                    return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled"
                return True, f"{target} | {hsts}"
            return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled"
        except requests.exceptions.Timeout:
            return False, f"{target} | ERROR | Connection Timeout"
        except requests.exceptions.ConnectionError:
            return False, f"{target} | ERROR | Connection Refused / Down"
        except Exception as e:
            return False, f"{target} | ERROR | {str(e)}"

    with concurrent.futures.ThreadPoolExecutor(max_workers=_HSTS_THREADS) as executor:
        futs = {executor.submit(scan_single, url): url for url in targets}
        for fut in concurrent.futures.as_completed(futs):
            is_secure, message = fut.result()
            if is_secure:
                results_aman.append(message)
            else:
                results_gagal.append(message)

    return results_aman, results_gagal


# ============================
# Security headers
# ============================

_SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (Enforce HTTPS)",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti-MIME Sniffing",
    "Content-Security-Policy": "Anti-XSS (CSP)",
    "Referrer-Policy": "Privacy Referrer",
}


def check_security_headers(targets: list[str]) -> list[dict]:
    results: list[dict] = []
    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.0.0 Safari/537.36"
    }

    for url in targets:
        domain = (url or "").strip()
        if not domain:
            continue
        if not domain.startswith("http"):
            domain = f"https://{domain}"

        scan_data = {"URL": domain, "Missing Headers": [], "Score": 0}

        try:
            response = requests.get(domain, headers=headers_req, verify=False, timeout=5, allow_redirects=True)
            headers_server = response.headers
            found_count = 0

            missing_list = []
            server_keys = [h.lower() for h in headers_server.keys()]
            for header in _SECURITY_HEADERS.keys():
                if header.lower() not in server_keys:
                    missing_list.append(header)
                else:
                    found_count += 1

            scan_data["Score"] = f"{found_count}/{len(_SECURITY_HEADERS)}"

            if not missing_list:
                scan_data["Status"] = "SECURE"
                scan_data["Missing Headers"] = "None (All Found)"
            else:
                scan_data["Status"] = "VULNERABLE"
                scan_data["Missing Headers"] = ", ".join(missing_list)

        except Exception:
            scan_data["Status"] = "ERROR"
            scan_data["Missing Headers"] = "Connection Failed"
            scan_data["Score"] = "0/5"

        results.append(scan_data)

    return results


# ============================
# Laravel debug
# ============================

_LARAVEL_TIMEOUT = 10
_LARAVEL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VA-Dashboard/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}


def _laravel_signatures() -> list[str]:
    return [
        "Whoops! There was an error.",
        "Spatie\\Ignition",
        "Facade\\Ignition",
        "window.ignition",
        "vendor/laravel/framework",
        "Illuminate\\Routing\\Pipeline",
        "MethodNotAllowedHttpException",
        "NotFoundHttpException",
        "can_execute_commands",
        '"can_execute_commands":true',
        "sf-dump",
        "Lumen",
        "RoutesRequests.php",
    ]


def scan_laravel_single_target(target: str) -> dict:
    url = _fix_url(target)
    signatures = _laravel_signatures()

    result = {
        "URL": url,
        "status": "SECURE",
        "payload": "-",
        "finding": "Debug mode disabled",
        "vuln_name": None,
    }

    endpoints = [url, f"{url}/index.php", f"{url}/api/index.php"]
    methods = ["PUT", "PATCH", "DELETE", "POST"]

    try:
        # Phase 1: Ignition check
        try:
            target_ign = f"{url}/_ignition/health-check"
            r_health = requests.get(target_ign, headers=_LARAVEL_HEADERS, timeout=_LARAVEL_TIMEOUT, verify=False)
            if r_health.status_code == 200 and "can_execute_commands" in r_health.text:
                result["status"] = "CRITICAL"
                result["payload"] = f"GET {target_ign}"
                result["finding"] = "Ignition RCE Exposed"
                result["vuln_name"] = "Laravel debug mode enabled"
                return result
        except Exception:
            pass

        # Phase 2: method fuzzing
        for endpoint in endpoints:
            for method in methods:
                try:
                    resp = requests.request(method=method, url=endpoint, headers=_LARAVEL_HEADERS, timeout=_LARAVEL_TIMEOUT, verify=False)
                    for sig in signatures:
                        if sig in resp.text:
                            result["status"] = "WARNING"
                            path_only = endpoint.replace(url, "") or "/"
                            result["payload"] = f"{method} {path_only}"
                            result["finding"] = f"Signature Found: {sig}"
                            result["vuln_name"] = "Laravel debug mode enabled"
                            return result
                except Exception:
                    continue

        # Phase 3: 404 trigger
        try:
            bad_path = "/halaman_ini_pasti_tidak_ada_12345"
            r_404 = requests.get(f"{url}{bad_path}", headers=_LARAVEL_HEADERS, timeout=_LARAVEL_TIMEOUT, verify=False)
            for sig in signatures:
                if sig in r_404.text:
                    result["status"] = "WARNING"
                    result["payload"] = f"GET {bad_path}"
                    result["finding"] = f"Signature Found: {sig}"
                    result["vuln_name"] = "Laravel debug mode enabled"
                    return result
        except Exception:
            pass

    except Exception as e:
        result["status"] = "ERROR"
        result["finding"] = str(e)
        result["vuln_name"] = None

    return result


def run_laravel_scan(targets_list: list[str], max_threads: int = 20) -> list[dict]:
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_laravel_single_target, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


# ============================
# Node.js debug
# ============================

_NODE_TIMEOUT = 10
_NODE_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VA-Dashboard/1.0",
    "Content-Type": "application/json",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
}

_NODE_BAD_PAYLOADS = ["z=1", '{"test":', "'invalid_json'"]


def _node_signatures() -> list[str]:
    return [
        "SyntaxError: Unexpected token",
        "node_modules/body-parser",
        "node_modules/express",
        "/var/www/node_modules",
        "at JSON.parse (<anonymous>)",
        "ReferenceError:",
        "TypeError:",
        "at createStrictSyntaxError",
        "Unexpected end of JSON input",
    ]


def scan_node_single_target(target: str) -> dict:
    url = _fix_url(target)
    signatures = _node_signatures()

    result = {
        "URL": url,
        "status": "SECURE",
        "payload": "-",
        "finding": "No Stack Trace exposed",
        "vuln_name": None,
    }

    methods_to_try = ["POST", "PUT", "GET"]

    try:
        for method in methods_to_try:
            for payload in _NODE_BAD_PAYLOADS:
                try:
                    response = requests.request(
                        method=method,
                        url=url,
                        headers=_NODE_HEADERS,
                        data=payload,
                        timeout=_NODE_TIMEOUT,
                        verify=False,
                    )

                    if response.status_code in [400, 500]:
                        for sig in signatures:
                            if sig in response.text:
                                result["status"] = "WARNING"
                                result["payload"] = f"{method} (Body: '{payload}')"
                                result["finding"] = f"Debug Trace Leak: {sig}"
                                result["vuln_name"] = "Node.js Running in Development Mode"
                                return result
                except Exception:
                    continue

    except Exception as e:
        result["status"] = "ERROR"
        result["finding"] = str(e)
        result["vuln_name"] = None

    return result


def run_node_scan(targets_list: list[str], max_threads: int = 20) -> list[dict]:
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_node_single_target, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results


# ============================
# PHP version disclosure
# ============================

_PHP_VERSION_RE = re.compile(r"PHP\/([0-9]+\.[0-9]+(\.[0-9]+)?)", re.IGNORECASE)


def check_php_version(target: str) -> dict:
    url = (target or "").strip()
    if not url.startswith("http"):
        url = f"https://{url}"

    headers_req = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.0.0 Safari/537.36"
    }

    result = {
        "URL": url,
        "status": "SECURE",
        "details": "No PHP version detected",
        "vuln_name": None,
    }

    try:
        response = requests.head(url, headers=headers_req, verify=False, timeout=10, allow_redirects=True)
        all_responses = response.history + [response]

        found_versions: set[str] = set()
        for resp in all_responses:
            headers = resp.headers
            for header_name in ["X-Powered-By", "Server"]:
                header_val = headers.get(header_name, "")
                match = _PHP_VERSION_RE.search(header_val)
                if match:
                    found_versions.add(f"PHP {match.group(1)} (in {header_name})")
                elif "php" in header_val.lower() and any(c.isdigit() for c in header_val):
                    found_versions.add(f"{header_val.strip()} (in {header_name})")

        if found_versions:
            result["status"] = "DISCLOSURE"
            result["details"] = ", ".join(sorted(found_versions))
            result["vuln_name"] = "Version Disclosure (PHP)"

    except requests.exceptions.Timeout:
        result["status"] = "ERROR"
        result["details"] = "Connection Timeout"
        result["vuln_name"] = None
    except Exception as e:
        result["status"] = "ERROR"
        result["details"] = str(e)
        result["vuln_name"] = None

    return result


def run_php_scan(targets_list: list[str], max_threads: int = 20) -> list[dict]:
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(check_php_version, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass
    return results


# ============================
# Protocol checks via nmap
# ============================

def _nmap_ssl_enum(domain_only: str) -> str:
    cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "-Pn", domain_only]
    process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    return process.stdout or ""


def check_sslv3(target: str) -> dict:
    if not shutil.which("nmap"):
        return {"target": target, "status": "ERROR", "details": "Nmap not installed", "vuln_name": None}

    if "://" not in (target or ""):
        target = "https://" + (target or "")

    parsed = urlparse(target)
    domain_only = parsed.netloc

    try:
        output = _nmap_ssl_enum(domain_only)
        if "SSLv3" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "SSLv3 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (SSLv3)",
            }
        if "TLSv" in output:
            return {"target": target, "status": "SECURE", "details": "SSLv3 Disabled", "vuln_name": None}
        return {"target": target, "status": "ERROR", "details": "No SSL Service", "vuln_name": None}
    except Exception as e:
        return {"target": target, "status": "ERROR", "details": str(e), "vuln_name": None}


def check_tls10(target: str) -> dict:
    if not shutil.which("nmap"):
        return {"target": target, "status": "ERROR", "details": "Nmap not installed", "vuln_name": None}

    if "://" not in (target or ""):
        target = "https://" + (target or "")

    parsed = urlparse(target)
    domain_only = parsed.netloc

    try:
        output = _nmap_ssl_enum(domain_only)
        if "TLSv1.0" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "TLS 1.0 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.0)",
            }
        if "TLSv" in output or "SSLv" in output:
            return {"target": target, "status": "SECURE", "details": "TLS 1.0 Disabled", "vuln_name": None}
        return {"target": target, "status": "ERROR", "details": "No SSL Service", "vuln_name": None}
    except Exception as e:
        return {"target": target, "status": "ERROR", "details": str(e), "vuln_name": None}


def check_tls11(target: str) -> dict:
    if not shutil.which("nmap"):
        return {"target": target, "status": "ERROR", "details": "Nmap not installed", "vuln_name": None}

    target_clean = (target or "").strip()
    if "://" not in target_clean:
        target_clean = "https://" + target_clean

    try:
        parsed = urlparse(target_clean)
        domain_only = parsed.netloc
    except Exception:
        domain_only = (target or "").strip()

    try:
        output = _nmap_ssl_enum(domain_only)
        if "TLSv1.1" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "TLS 1.1 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.1)",
            }
        if "TLSv" in output or "SSLv" in output:
            return {"target": target, "status": "SECURE", "details": "TLS 1.1 Disabled", "vuln_name": None}
        return {"target": target, "status": "ERROR", "details": "No SSL Service / Connection Failed", "vuln_name": None}
    except Exception as e:
        return {"target": target, "status": "ERROR", "details": str(e), "vuln_name": None}


# ============================
# Cookie Secure Flag Check
# ============================

def check_cookie_secure(target: str) -> dict:
    """Check if cookies are marked with Secure flag."""
    url = _fix_url(target)
    
    result = {
        "target": url,
        "status": "INFO",
        "details": "No Cookies Found",
        "vuln_name": None,
    }
    
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"
    }
    
    try:
        response = requests.get(url, headers=headers, timeout=5, verify=False, allow_redirects=True)
        
        # Get all Set-Cookie headers
        cookies = response.cookies
        if not cookies:
            result["status"] = "INFO"
            result["details"] = "No Cookies Found"
            return result
        
        # Check each cookie for secure flag
        insecure_cookies = []
        secure_cookies = []
        
        for cookie in cookies:
            if cookie.secure:
                secure_cookies.append(cookie.name)
            else:
                insecure_cookies.append(cookie.name)
        
        if insecure_cookies:
            result["status"] = "VULNERABLE"
            result["details"] = f"Cookies Not Marked as Secure: {', '.join(insecure_cookies)}"
            result["vuln_name"] = "Cookie Without Secure Flag Set"
        elif secure_cookies:
            result["status"] = "SAFE"
            result["details"] = "All Cookies are Secure"
            result["vuln_name"] = None
        
    except requests.exceptions.Timeout:
        result["status"] = "ERROR"
        result["details"] = "Connection Timeout"
    except requests.exceptions.ConnectionError:
        result["status"] = "ERROR"
        result["details"] = "Connection Refused / Down"
    except Exception as e:
        result["status"] = "ERROR"
        result["details"] = str(e)
    
    return result


def run_cookie_scan(targets: list[str]) -> list[dict]:
    """Run cookie secure flag check on multiple targets."""
    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        futures = {executor.submit(check_cookie_secure, t): t for t in targets}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results
