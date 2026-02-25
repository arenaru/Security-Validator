import requests
import urllib3
import pandas as pd

# Disable warning SSL self-signed
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Header yang wajib dicek
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS (Enforce HTTPS)",
    "X-Frame-Options": "Anti-Clickjacking",
    "X-Content-Type-Options": "Anti-MIME Sniffing",
    "Content-Security-Policy": "Anti-XSS (CSP)",
    "Referrer-Policy": "Privacy Referrer"
}

def check_security_headers(targets):
    results = []
    
    # User Agent biar ga diblok WAF
    headers_req = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    }

    for url in targets:
        domain = url.strip()
        if not domain.startswith("http"):
            domain = f"https://{domain}"

        scan_data = {
            "URL": domain,
            "Missing Headers": [],
            "Score": 0 # Hitung berapa header yang ada
        }

        try:
            # PENTING: allow_redirects=True biar dapet header dari Final Page (200 OK)
            # Timeout 5 detik biar ga lama
            response = requests.get(domain, headers=headers_req, verify=False, timeout=5, allow_redirects=True)
            
            headers_server = response.headers
            found_count = 0

            # Loop cek satu-satu
            missing_list = []
            for header, desc in SECURITY_HEADERS.items():
                # Case Insensitive check
                if header.lower() not in [h.lower() for h in headers_server.keys()]:
                    missing_list.append(header)
                else:
                    found_count += 1
            
            scan_data["Score"] = f"{found_count}/{len(SECURITY_HEADERS)}"
            
            if not missing_list:
                scan_data["Status"] = "SECURE"
                scan_data["Missing Headers"] = "None (All Found)"
            else:
                scan_data["Status"] = "VULNERABLE"
                scan_data["Missing Headers"] = ", ".join(missing_list)

        except Exception as e:
            scan_data["Status"] = "ERROR"
            scan_data["Missing Headers"] = "Connection Failed"
            scan_data["Score"] = "0/5"
        
        results.append(scan_data)

    return results