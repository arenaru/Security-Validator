import requests
import urllib3
import concurrent.futures
from urllib.parse import urlparse

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================
# CONFIGURATION
# ============================
TIMEOUT = 10
THREADS = 20  # Fast scanning
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"


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

def run_hsts_scan(targets):
    """
    Fungsi utama untuk scanning HSTS yang dipanggil oleh scanner_engine.py.
    Mengembalikan tuple (list_aman, list_vuln).
    """
    results_aman = []
    results_gagal = []
    
    # Fungsi worker untuk 1 URL
    def scan_single(url):
        candidates = build_target_candidates(url)
        headers = {'User-Agent': USER_AGENT}
        last_error = None

        for target in candidates:
            try:
                # allow_redirects=True PENTING: Header HSTS harus ada di final destination
                r = requests.get(target, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)

                # Cek Header HSTS (Case Insensitive sudah dihandle requests.headers)
                hsts = r.headers.get('Strict-Transport-Security')

                if hsts:
                    # Cek Robustness: max-age=0 artinya HSTS sengaja dimatikan
                    if "max-age=0" in hsts.lower():
                        # [VULN] HSTS Disabled via max-age=0
                        # Format output string: URL | Nama Vuln
                        return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled"

                    # [SECURE] HSTS Valid
                    return True, f"{target} | {hsts}"
                else:
                    # [VULN] HSTS Hilang sama sekali
                    return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled"

            # --- ERROR HANDLING ---
            except requests.exceptions.Timeout:
                last_error = f"{target} | ERROR | Connection Timeout"
                continue
            except requests.exceptions.ConnectionError:
                last_error = f"{target} | ERROR | Connection Refused / Down"
                continue
            except Exception as e:
                last_error = f"{target} | ERROR | {str(e)}"
                continue

        return False, last_error if last_error else f"{url.strip()} | ERROR | Unknown Error"

    # --- EKSEKUSI PARALLEL ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Submit task
        futures = {executor.submit(scan_single, url): url for url in targets}
        
        # Collect result
        for future in concurrent.futures.as_completed(futures):
            is_secure, message = future.result()
            
            if is_secure:
                results_aman.append(message)
            else:
                # Filter: Hanya masukkan ke list gagal jika itu benar-benar VULN atau ERROR
                # Pesan format: "URL | PESAN"
                results_gagal.append(message)
            
    return results_aman, results_gagal