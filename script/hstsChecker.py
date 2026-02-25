import requests
import urllib3
import concurrent.futures

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================
# CONFIGURATION
# ============================
TIMEOUT = 15  # Increased for serverless environments (Vercel, AWS Lambda, etc.)
THREADS = 20  # Fast scanning
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

def run_hsts_scan(targets):
    """
    Fungsi utama untuk scanning HSTS yang dipanggil oleh scanner_engine.py.
    Mengembalikan tuple (list_aman, list_vuln).
    """
    results_aman = []
    results_gagal = []
    
    # Fungsi worker untuk 1 URL
    def scan_single(url):
        target = url.strip()
        # Force HTTPS to properly check HSTS (HSTS only works over HTTPS)
        if target.startswith("http://"):
            target = target.replace("http://", "https://", 1)
        elif not target.startswith("https://"):
            target = f"https://{target}"
        headers = {'User-Agent': USER_AGENT}

        try:
            # allow_redirects=True PENTING: Header HSTS harus ada di final destination
            r = requests.get(target, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
            
            # Ensure we received HTTPS response (HSTS is only valid over HTTPS)
            if not r.url.startswith('https://'):
                return False, f"{target} | ERROR | Final URL not HTTPS (got {r.url})"
            
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
            # Error koneksi tidak dianggap Vulnerability HSTS (tapi Error)
            # Kita bisa return False tapi pesannya ERROR biar tidak masuk statistik Vuln
            return False, f"{target} | ERROR | Connection Timeout"
        except requests.exceptions.ConnectionError:
            return False, f"{target} | ERROR | Connection Refused / Down"
        except Exception as e:
            return False, f"{target} | ERROR | {str(e)}"

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