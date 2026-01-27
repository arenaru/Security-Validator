import requests
import urllib3
import concurrent.futures

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
        "Spatie\\\\Ignition",
        "Facade\\\\Ignition",
        "window.ignition",
        "vendor/laravel/framework",
        "Illuminate\\\\Routing\\\\Pipeline",
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
    if not url.startswith("http"):
        url = "https://" + url
    return url.rstrip('/')

def scan_single_target(target):
    url = fix_url(target)
    signatures = get_signatures()
    
    # Default Result: Tambahkan key 'payload' kosong
    result = {
        "URL": url,
        "status": "SECURE",
        "payload": "-",  # <--- KOLOM BARU
        "finding": "Debug mode disabled"
    }

    endpoints = [
        url, 
        f"{url}/index.php", 
        f"{url}/api/index.php"
    ]
    
    methods = ['PUT', 'PATCH', 'DELETE', 'POST']

    try:
        # --- PHASE 1: Ignition RCE Check ---
        try:
            target_ign = f"{url}/_ignition/health-check"
            r_health = requests.get(target_ign, headers=HEADERS, timeout=TIMEOUT, verify=False)
            if r_health.status_code == 200 and "can_execute_commands" in r_health.text:
                result["status"] = "CRITICAL"
                result["payload"] = f"GET {target_ign}" # <--- Catat Payload
                result["finding"] = "Ignition RCE Exposed"
                return result
        except:
            pass

        # --- PHASE 2: Method Fuzzing ---
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
                            # Catat method dan path spesifik yang bocor
                            path_only = endpoint.replace(url, "")
                            if path_only == "": path_only = "/"
                            
                            result["payload"] = f"{method} {path_only}" # <--- Catat Payload (misal: PUT /index.php)
                            result["finding"] = f"Signature Found: {sig}"
                            return result 
                except:
                    continue
        
        # --- PHASE 3: 404 Trigger ---
        try:
            # Generate random path
            bad_path = "/halaman_ini_pasti_tidak_ada_12345"
            r_404 = requests.get(f"{url}{bad_path}", headers=HEADERS, timeout=TIMEOUT, verify=False)
            for sig in signatures:
                if sig in r_404.text:
                    result["status"] = "WARNING"
                    result["payload"] = f"GET {bad_path}" # <--- Catat Payload
                    result["finding"] = f"Signature Found: {sig}"
                    return result
        except:
            pass

    except Exception as e:
        result["status"] = "ERROR"
        result["finding"] = str(e)

    return result

def run_laravel_scan(targets_list, max_threads=20):
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_target, t): t for t in targets_list}
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
    return results