import requests
import urllib3
import pandas as pd
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

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
        if not domain.startswith("http"):
            domain = f"https://{domain}"

        scan_data = {
            "URL": domain,
            "Status Code": "N/A",
            "Redirects": 0,
            "Missing Headers": [],
            "Score": 0,
            "Status": "UNKNOWN",
            "Error": None
        }

        try:
            # Request dengan timeout lebih panjang & redirect limit
            response = session.get(
                domain, 
                headers=headers_req, 
                verify=False, 
                timeout=12,  # 12 detik
                allow_redirects=True,
                stream=False
            )
            
            scan_data["Status Code"] = response.status_code
            scan_data["Redirects"] = len(response.history)  # Count redirect chain
            
            # Validasi status code (hanya accept 200-299)
            if not (200 <= response.status_code < 300):
                scan_data["Status"] = "INVALID_STATUS"
                scan_data["Error"] = f"HTTP {response.status_code} (Expected 2xx)"
                results.append(scan_data)
                continue
            
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

        except requests.exceptions.Timeout:
            scan_data["Status"] = "TIMEOUT"
            scan_data["Error"] = f"Connection timeout (12s)"
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        except requests.exceptions.ConnectionError as e:
            scan_data["Status"] = "CONNECTION_ERROR"
            scan_data["Error"] = str(e)[:100]
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        except requests.exceptions.RequestException as e:
            scan_data["Status"] = "REQUEST_ERROR"
            scan_data["Error"] = str(e)[:100]
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        except Exception as e:
            scan_data["Status"] = "ERROR"
            scan_data["Error"] = f"Unexpected: {str(e)[:100]}"
            scan_data["Score"] = f"0/{len(SECURITY_HEADERS)}"
        
        results.append(scan_data)
    
    session.close()
    return results