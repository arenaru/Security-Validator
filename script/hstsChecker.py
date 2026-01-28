import requests
import urllib3
import concurrent.futures
import sys
import os
import threading

# Disable SSL warnings for cleaner output
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ============================
# CONFIGURATION
# ============================
TIMEOUT = 10
THREADS = 20  # Fast scanning
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

# Files
OUTPUT_DIR = "scan_results_hsts"
FILE_WITH_HSTS = os.path.join(OUTPUT_DIR, "with_hsts.txt")
FILE_WITHOUT_HSTS = os.path.join(OUTPUT_DIR, "without_hsts.txt")
FILE_ERROR = os.path.join(OUTPUT_DIR, "unreachable.txt")

file_lock = threading.Lock()

class Color:
    GREEN = '\033[92m'
    RED = '\033[91m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'

def setup_files():
    if not os.path.exists(OUTPUT_DIR):
        os.makedirs(OUTPUT_DIR)
    # Clear previous runs (optional)
    for f in [FILE_WITH_HSTS, FILE_WITHOUT_HSTS, FILE_ERROR]:
        open(f, 'w').close()

def save_to_file(filepath, content):
    with file_lock:
        with open(filepath, "a") as f:
            f.write(f"{content}\n")

def check_hsts(url):
    target = url.strip()
    # Force HTTPS scheme
    if not target.startswith("http"):
        target = f"https://{target}"
    
    headers = {'User-Agent': USER_AGENT}

    try:
        # allow_redirects=True is CRITICAL to find the final landing page
        response = requests.get(target, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
        
        # Check for header (Case Insensitive)
        hsts_header = response.headers.get('Strict-Transport-Security', None)
        final_url = response.url

        if hsts_header:
            # ROBUSTNESS CHECK: Ensure max-age is not 0
            if "max-age=0" in hsts_header.lower():
                print(f"{Color.RED}[FAIL] {target} -> HSTS disabled (max-age=0){Color.RESET}")
                save_to_file(FILE_WITHOUT_HSTS, f"{target} | Final: {final_url} | Reason: HSTS Not Enabled (max-age=0)")
            else:
                print(f"{Color.GREEN}[PASS] {target} -> HSTS Found{Color.RESET}")
                save_to_file(FILE_WITH_HSTS, f"{target} | Final: {final_url} | Header: {hsts_header}")
        else:
            print(f"{Color.RED}[FAIL] {target} -> No HSTS Header{Color.RESET}")
            save_to_file(FILE_WITHOUT_HSTS, f"{target}")

    except requests.exceptions.RequestException as e:
        print(f"{Color.YELLOW}[ERR]  {target}{Color.RESET}")
        save_to_file(FILE_ERROR, f"{target} | Error: {str(e)}")

def main():
    print(f"{Color.BLUE}========================================")
    print(f"    ROBUST HSTS CHECKER")
    print(f"    Threads: {THREADS}")
    print(f"========================================{Color.RESET}")

    setup_files()

    if not os.path.exists("list.txt"):
        print("Error: list.txt not found.")
        sys.exit()

    with open("list.txt", "r") as f:
        targets = [line.strip() for line in f if line.strip()]

    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        executor.map(check_hsts, targets)

    print(f"\n{Color.BLUE}[+] Scan Complete. Results in '{OUTPUT_DIR}'{Color.RESET}")

def run_hsts_scan(targets):
    results_aman = []
    results_gagal = []
    
    # Fungsi kecil untuk cek 1 URL (Helper)
    def scan_single(url):
        target = url.strip()
        if not target.startswith("http"): target = f"https://{target}"
        headers = {'User-Agent': USER_AGENT} # Penting biar ga diblok WAF

        try:
            # allow_redirects=True PENTING buat ngejar final landing page
            r = requests.get(target, headers=headers, timeout=TIMEOUT, verify=False, allow_redirects=True)
            hsts = r.headers.get('Strict-Transport-Security')
            
            if hsts:
                if "max-age=0" in hsts.lower():
                     # [VULN] HSTS ada tapi dimatikan (max-age=0)
                     return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled (max-age=0)"
                # [SECURE]
                return True, f"{target} | {hsts}"
            else:
                # [VULN] HSTS Hilang
                return False, f"{target} | HTTP Strict Transport Security (HSTS) Policy Not Enabled"
        
        # --- ERROR HANDLING SPESIFIK ---
        except requests.exceptions.Timeout:
            return False, f"{target} | ERROR | Connection Timeout"
        except requests.exceptions.ConnectionError:
            return False, f"{target} | ERROR | Connection Refused / Down"
        except Exception as e:
            return False, f"{target} | ERROR | {str(e)}"

    # --- JALANIN SECARA PARALLEL (MULTITHREADING) ---
    with concurrent.futures.ThreadPoolExecutor(max_workers=THREADS) as executor:
        # Submit semua target ke workers
        futures = {executor.submit(scan_single, url): url for url in targets}
        
        # Ambil hasil saat worker selesai
        for future in concurrent.futures.as_completed(futures):
            is_secure, message = future.result()
            if is_secure:
                results_aman.append(message)
            else:
                results_gagal.append(message)
            
    return results_aman, results_gagal

# if __name__ == "__main__":
#     main()
