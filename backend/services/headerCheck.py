import requests
import urllib3
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse

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


def build_target_candidates(target):
    """
    Return request candidates in priority order: HTTPS first, then HTTP.
    """
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if parsed.query:
            path = f"{path}?{parsed.query}"
        candidates = [f"https://{host}{path}", f"http://{host}{path}"]
        return list(dict.fromkeys(candidates))
    return [f"https://{target}", f"http://{target}"]

def check_security_headers(targets):
    results = []
    
    # Setup retry strategy with exponential backoff
    retry_strategy = Retry(
        total=2,  # Max 2 retries
        backoff_factor=1,  # 1s, 2s, 4s
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"]
    )
    
    # Create session dengan retry
    session = requests.Session()
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    # User Agent biar ga diblok WAF
    headers_req = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for url in targets:
        domain = url.strip()
        candidates = build_target_candidates(domain)

        scan_data = {
            "URL": candidates[0] if candidates else domain,
            "Status Code": "N/A",
            "Redirects": 0,
            "Missing Headers": [],
            "Score": 0,
            "Status": "UNKNOWN",
            "Error": None
        }

        request_succeeded = False
        last_error = None

        for candidate in candidates:
            try:
                # Request dengan timeout lebih panjang & redirect limit
                response = session.get(
                    candidate,
                    headers=headers_req,
                    verify=False,
                    timeout=12,  # 12 detik
                    allow_redirects=True,
                    stream=False
                )

                scan_data["URL"] = candidate
                scan_data["Status Code"] = response.status_code
                scan_data["Redirects"] = len(response.history)  # Count redirect chain

                # Validasi status code (hanya accept 200-299)
                if not (200 <= response.status_code < 300):
                    scan_data["Status"] = "INVALID_STATUS"
                    scan_data["Error"] = f"HTTP {response.status_code} (Expected 2xx)"
                    request_succeeded = True
                    break

                headers_server = response.headers
                found_count = 0
                missing_list = []

                # Loop cek satu-satu dengan validasi value
                for header, desc in SECURITY_HEADERS.items():
                    # Case Insensitive check
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
                        # Validasi header value tidak kosong
                        if header_value and header_value.strip():
                            found_count += 1
                        else:
                            # Header ada tapi value kosong = bahaya
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

        if request_succeeded:
            results.append(scan_data)
            continue

        if last_error:
            scan_data["URL"] = last_error[2]
            scan_data["Status"] = last_error[0]
            scan_data["Error"] = last_error[1]
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        else:
            scan_data["Status"] = "ERROR"
            scan_data["Error"] = "Unknown request error"
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        
        results.append(scan_data)
    
    session.close()
    return results
