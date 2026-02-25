import requests
import urllib3
import concurrent.futures
import os
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================
# CONFIGURATION
# ============================
# Detect if running on Vercel/serverless (shorter timeouts needed)
IS_SERVERLESS = os.getenv('VERCEL') or os.getenv('AWS_LAMBDA_FUNCTION_NAME') or os.getenv('FUNCTIONS_WORKER_RUNTIME')
TIMEOUT = 5 if IS_SERVERLESS else 15  # Very short timeout for serverless to avoid function timeout
THREADS = 2 if IS_SERVERLESS else 5   # Minimal concurrency for serverless
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

def create_session():
    """Create a requests session with retry logic for serverless environments"""
    session = requests.Session()
    
    # Configure retry strategy - lightweight for serverless
    retry_strategy = Retry(
        total=2 if IS_SERVERLESS else 3,  # Fewer retries on serverless
        backoff_factor=0.3,  # Faster backoff for serverless
        status_forcelist=[429, 500, 502, 503, 504],  # Retry on these status codes
        allowed_methods=["GET", "HEAD"]  # Only retry safe methods
    )
    
    # Mount adapter with retry strategy
    adapter = HTTPAdapter(
        max_retries=retry_strategy,
        pool_connections=5,
        pool_maxsize=5
    )
    
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    
    return session

def run_hsts_scan(targets):
    """
    Fungsi utama untuk scanning HSTS yang dipanggil oleh scanner_engine.py.
    Mengembalikan tuple (list_aman, list_vuln).
    """
    results_aman = []
    results_gagal = []
    
    # Create session once and reuse (better for serverless)
    session = create_session()
    
    # Fungsi worker untuk 1 URL
    def scan_single(url):
        target = url.strip()
        # Force HTTPS to properly check HSTS (HSTS only works over HTTPS)
        if target.startswith("http://"):
            target = target.replace("http://", "https://", 1)
        elif not target.startswith("https://"):
            target = f"https://{target}"
        
        # Enhanced headers to bypass bot detection
        headers = {
            'User-Agent': USER_AGENT,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        try:
            # Use session.get instead of requests.get for connection pooling
            r = session.get(target, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
            
            # Ensure we received HTTPS response (HSTS is only valid over HTTPS)
            if not r.url.startswith('https://'):
                return False, f"{target} | ERROR | Final URL not HTTPS (got {r.url})"
            
            # Check if request was successful
            r.raise_for_status()
            
            # Cek Header HSTS (Case Insensitive sudah dihandle requests.headers)
            hsts = r.headers.get('Strict-Transport-Security')
            
            # If no HSTS found in GET response, check if it might be in initial request
            # (Some redirects might lose headers, so try direct HEAD to final URL)
            if not hsts and r.history:
                # Check all redirect responses for HSTS
                for resp in r.history:
                    hsts = resp.headers.get('Strict-Transport-Security')
                    if hsts:
                        break
            
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
        except requests.exceptions.HTTPError as e:
            # HTTP errors (4xx, 5xx) should still check for HSTS header
            if hasattr(e.response, 'headers'):
                hsts = e.response.headers.get('Strict-Transport-Security')
                if hsts and "max-age=0" not in hsts.lower():
                    return True, f"{target} | {hsts} (HTTP {e.response.status_code})"
            return False, f"{target} | ERROR | HTTP {e.response.status_code if hasattr(e, 'response') else 'Error'}"
        except Exception as e:
            return False, f"{target} | ERROR | {str(e)}"

    # --- EKSEKUSI PARALLEL ---
    try:
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
    finally:
        # Close session to free resources (important for serverless)
        session.close()
            
    return results_aman, results_gagal