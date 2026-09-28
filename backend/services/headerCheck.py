import concurrent.futures
import requests
import urllib3
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from backend.utils.target_resolver import build_target_candidates

# Disable warning SSL self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Header yang wajib dicek
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (Enforce HTTPS)",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti-MIME Sniffing",
    "Content-Security-Policy": "Anti-XSS (CSP)",
    "Referrer-Policy": "Privacy Referrer",
    "Permissions-Policy": "Browser Features Control"
}

_RETRY_STRATEGY = Retry(
    total=2,
    backoff_factor=1,
    status_forcelist=[429, 500, 502, 503, 504],
    allowed_methods=["HEAD", "GET", "OPTIONS"]
)

_HEADERS_REQ = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
}


def _check_single_target(url: str) -> dict:
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=_RETRY_STRATEGY)
    session.mount("http://", adapter)
    session.mount("https://", adapter)

    domain = url.strip()
    candidates = build_target_candidates(domain)

    scan_data = {
        "URL": candidates[0] if candidates else domain,
        "Status Code": "N/A",
        "Redirects": 0,
        "Missing Headers": [],
        "Score": 0,
        "Status": "UNKNOWN",
        "Error": None,
    }

    request_succeeded = False
    last_error = None

    try:
        for candidate in candidates:
            try:
                response = session.get(
                    candidate,
                    headers=_HEADERS_REQ,
                    verify=False,
                    timeout=12,
                    allow_redirects=True,
                    stream=False,
                )

                scan_data["URL"] = candidate
                scan_data["Status Code"] = response.status_code
                scan_data["Redirects"] = len(response.history)

                if not (200 <= response.status_code < 300):
                    scan_data["Status"] = "INVALID_STATUS"
                    scan_data["Error"] = f"HTTP {response.status_code} (Expected 2xx)"
                    request_succeeded = True
                    break

                headers_server = response.headers
                found_count = 0
                missing_list = []

                for header in SECURITY_HEADERS:
                    header_found = False
                    header_value = None

                    for h in headers_server.keys():
                        if h.lower() == header.lower():
                            header_found = True
                            header_value = headers_server[h]
                            break

                    if not header_found:
                        missing_list.append(header)
                    else:
                        if header_value and header_value.strip():
                            found_count += 1
                        else:
                            missing_list.append(f"{header} (Empty Value)")

                scan_data["Score"] = f"{found_count}/{len(SECURITY_HEADERS)}"

                if not missing_list:
                    scan_data["Status"] = "SECURE"
                    scan_data["Missing Headers"] = "None (All Found)"
                else:
                    scan_data["Status"] = "VULNERABLE"
                    scan_data["Missing Headers"] = ", ".join(missing_list)

                request_succeeded = True
                break

            except requests.exceptions.Timeout:
                last_error = ("TIMEOUT", "Connection timeout (12s)", candidate)
                continue
            except requests.exceptions.ConnectionError as e:
                last_error = ("CONNECTION_ERROR", str(e)[:100], candidate)
                continue
            except requests.exceptions.RequestException as e:
                last_error = ("REQUEST_ERROR", str(e)[:100], candidate)
                continue
            except Exception as e:
                last_error = ("ERROR", f"Unexpected: {str(e)[:100]}", candidate)
                continue
    finally:
        session.close()

    if request_succeeded:
        return scan_data

    if last_error:
        scan_data["URL"] = last_error[2]
        scan_data["Status"] = last_error[0]
        scan_data["Error"] = last_error[1]
        scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
    else:
        scan_data["Status"] = "ERROR"
        scan_data["Error"] = "Unknown request error"
        scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"

    return scan_data


def check_security_headers(targets, max_threads=20):
    valid_targets = [t for t in targets if t and t.strip()]
    results = [None] * len(valid_targets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(_check_single_target, target): index
            for index, target in enumerate(valid_targets)
        }
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()

    return results
