import requests
import urllib3
import concurrent.futures
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VA-Dashboard/1.0",
    "Content-Type": "application/json", 
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

# --- UPDATE: Dibuat List Payload ---
# 1. z=1 (Invalid token di awal)
# 2. {"test": (JSON kepotong/Unexpected end of input)
# 3. 'single_quotes' (JSON wajib double quotes, ini sering bikin parser error)
BAD_PAYLOADS = [
    "z=1", 
    '{"test":', 
    "'invalid_json'"
]

def get_signatures():
    return [
        "SyntaxError: Unexpected token",
        "node_modules/body-parser",
        "node_modules/express",
        "/var/www/node_modules",
        "at JSON.parse (<anonymous>)",
        "ReferenceError:",
        "TypeError:",
        "at createStrictSyntaxError",
        "Unexpected end of JSON input" # Signature baru untuk payload {"test":
    ]

def fix_url(url):
    url = url.strip()
    url = url.rstrip('/')
    if url.startswith(('http://', 'https://')):
        parsed = urlparse(url)
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if parsed.query:
            path = f"{path}?{parsed.query}"
        candidates = [f"https://{host}{path}", f"http://{host}{path}"]
        return list(dict.fromkeys(candidates))
    return [f"https://{url}", f"http://{url}"]

def scan_single_target(target):
    candidate_urls = fix_url(target)
    signatures = get_signatures()
    last_error = None

    for url in candidate_urls:
        result = {
            "URL": url,
            "status": "SECURE",
            "payload": "-",
            "finding": "No Stack Trace exposed",
            "vuln_name": None # <--- Field Wajib untuk PDF Gen
        }

        methods_to_try = ["POST", "PUT", "GET"]
        request_succeeded = False

        try:
            # Loop Method (POST/PUT/GET)
            for method in methods_to_try:
                # Loop Payload (Coba berbagai jenis sampah)
                for payload in BAD_PAYLOADS:
                    try:
                        response = requests.request(
                            method=method,
                            url=url,
                            headers=HEADERS,
                            data=payload,
                            timeout=TIMEOUT,
                            verify=False
                        )
                        request_succeeded = True

                        if response.status_code in [400, 500]:
                            for sig in signatures:
                                if sig in response.text:
                                    result["status"] = "WARNING"
                                    # Catat payload mana yang tembus
                                    result["payload"] = f"{method} (Body: '{payload}')"
                                    result["finding"] = f"Debug Trace Leak: {sig}"

                                    # Mapping ke nama standar Acunetix (High Severity)
                                    result["vuln_name"] = "Node.js Running in Development Mode"
                                    return result
                    except requests.exceptions.RequestException:
                        continue

            if not request_succeeded:
                raise requests.exceptions.ConnectionError("No response from target")

            return result

        except (requests.exceptions.Timeout, requests.exceptions.ConnectionError) as e:
            last_error = (url, str(e))
            continue
        except Exception as e:
            last_error = (url, str(e))
            continue

    if last_error:
        return {
            "URL": last_error[0],
            "status": "ERROR",
            "payload": "-",
            "finding": last_error[1],
            "vuln_name": None
        }

    return {
        "URL": target.strip(),
        "status": "ERROR",
        "payload": "-",
        "finding": "Unknown Error",
        "vuln_name": None
    }

def run_node_scan(targets_list, max_threads=20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_target, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results