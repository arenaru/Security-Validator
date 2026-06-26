import requests
import urllib3
import concurrent.futures
from urllib.parse import urlparse

# Matikan warning SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Konfigurasi
TIMEOUT = 10
HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) VA-Dashboard/1.0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
}

def get_signatures():
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
        "RoutesRequests.php"
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
        # Default Result
        result = {
            "URL": url,
            "status": "SECURE",
            "payload": "-",
            "finding": "Debug mode disabled",
            "vuln_name": None # <--- Field Wajib untuk PDF Gen
        }

        endpoints = [
            url,
            f"{url}/index.php",
            f"{url}/api/index.php"
        ]

        methods = ['PUT', 'PATCH', 'DELETE', 'POST']

        try:
            # --- PHASE 1: Ignition RCE Check (CRITICAL) ---
            target_ign = f"{url}/_ignition/health-check"
            r_health = requests.get(target_ign, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if r_health.status_code == 200 and "can_execute_commands" in r_health.text:
                result["status"] = "CRITICAL"
                result["payload"] = f"GET {target_ign}"
                result["finding"] = "Ignition RCE Exposed"
                # RCE biasanya efek dari Debug Mode yang terekspos juga
                # Kita mapping ke nama standar agar kedetect Severity-nya
                result["vuln_name"] = "Laravel debug mode enabled"
                return result

            # --- PHASE 2: Method Fuzzing (WARNING) ---
            for endpoint in endpoints:
                for method in methods:
                    try:
                        resp = requests.request(
                            method=method,
                            url=endpoint,
                            headers=HEADERS,
                            timeout=TIMEOUT,
                            verify=False
                        )

                        for sig in signatures:
                            if sig in resp.text:
                                result["status"] = "WARNING"
                                path_only = endpoint.replace(url, "")
                                if path_only == "":
                                    path_only = "/"

                                result["payload"] = f"{method} {path_only}"
                                result["finding"] = f"Signature Found: {sig}"
                                # Mapping ke nama standar Acunetix
                                result["vuln_name"] = "Laravel debug mode enabled"
                                return result
                    except requests.exceptions.RequestException:
                        continue

            # --- PHASE 3: 404 Trigger (WARNING) ---
            bad_path = "/halaman_ini_pasti_tidak_ada_12345"
            r_404 = requests.get(f"{url}{bad_path}", headers=HEADERS, timeout=TIMEOUT, verify=False)
            for sig in signatures:
                if sig in r_404.text:
                    result["status"] = "WARNING"
                    result["payload"] = f"GET {bad_path}"
                    result["finding"] = f"Signature Found: {sig}"
                    # Mapping ke nama standar Acunetix
                    result["vuln_name"] = "Laravel debug mode enabled"
                    return result

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

def run_laravel_scan(targets_list, max_threads=20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_target, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results
