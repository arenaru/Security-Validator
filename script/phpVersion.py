import requests
import urllib3
import re
import concurrent.futures
from urllib.parse import urlparse

# Matikan warning sertifikat SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Regex untuk menangkap versi PHP (misal: 7.4.3, 8.0, 5.6)
# Menangkap pola angka.angka(.angka optional)
PHP_VERSION_REGEX = re.compile(r'PHP\/([0-9]+\.[0-9]+(\.[0-9]+)?)', re.IGNORECASE)


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

def check_php_version(target):
    candidates = build_target_candidates(target)
    
    # Header palsu standard
    headers_req = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    # Struktur Default
    result = {
        "URL": candidates[0] if candidates else target.strip(),
        "status": "SECURE",
        "details": "No PHP version detected",
        "vuln_name": None # Field wajib untuk PDF Gen
    }

    last_error = None

    for url in candidates:
        try:
            # Request HEAD (Hemat bandwidth)
            # allow_redirects=True agar kita bisa melacak chain redirect
            response = requests.head(url, headers=headers_req, verify=False, timeout=10, allow_redirects=True)

            result["URL"] = url

            # --- LOGIC ROBUST: Cek History (Redirects) & Final Response ---
            # Kita gabungkan semua respon (redirect 301, 302, sampai 200 OK)
            all_responses = response.history + [response]

            found_versions = set()

            for resp in all_responses:
                headers = resp.headers

                # Cek header X-Powered-By dan Server
                for header_name in ['X-Powered-By', 'Server']:
                    header_val = headers.get(header_name, '')

                    # 1. Cek Regex Versi (Paling Akurat)
                    # Contoh: "X-Powered-By: PHP/7.4.3"
                    match = PHP_VERSION_REGEX.search(header_val)
                    if match:
                        # Ambil grup 1 (angkanya saja, misal 7.4.3)
                        found_versions.add(f"PHP {match.group(1)} (in {header_name})")

                    # 2. Cek String "PHP" biasa (Fallback)
                    elif "php" in header_val.lower():
                        # Pastikan ada angka biar gak false positive sama string biasa
                        if any(c.isdigit() for c in header_val):
                            found_versions.add(f"{header_val.strip()} (in {header_name})")

            # --- KEPUTUSAN ---
            if found_versions:
                result["status"] = "DISCLOSURE"
                result["details"] = ", ".join(list(found_versions))
                # Nama Vulnerability Standar Acunetix (Severity: Low)
                # Pastikan nama ini ada di acunetix_vulnerabilities.json Anda
                result["vuln_name"] = "Version Disclosure (PHP)"

            return result

        except requests.exceptions.Timeout:
            last_error = (url, "Connection Timeout")
            continue
        except requests.exceptions.ConnectionError as e:
            last_error = (url, str(e))
            continue
        except Exception as e:
            last_error = (url, str(e))
            continue

    if last_error:
        result["URL"] = last_error[0]
        result["status"] = "ERROR"
        result["details"] = last_error[1]
        result["vuln_name"] = None
        return result

    return result

def run_php_scan(targets_list, max_threads=20):
    """
    Fungsi utama yang dipanggil oleh scanner_engine.py
    Menggunakan Multithreading agar cepat.
    """
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        # Submit task paralel
        futures = {executor.submit(check_php_version, t): t for t in targets_list}
        
        for future in concurrent.futures.as_completed(futures):
            try:
                results.append(future.result())
            except Exception:
                pass # Skip jika ada error thread fatal
                
    return results