import ssl
import socket
from datetime import datetime
from urllib.parse import urlparse
import pytz
import math

# Zona waktu WIB
wib = pytz.timezone('Asia/Jakarta')

def sanitize(domain):
    domain = domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc
    return domain.split("/")[0]

def cek_ssl_expiry(domain, port=443, warning_days=30):
    # KEMBALI KE MODE STRICT (Standard Browser Check)
    # Ini akan otomatis Error jika Hostname Mismatch atau Self-Signed
    context = ssl.create_default_context()
    
    result = {
        "URL": f"https://{domain}",
        "Status": "Error",       # Default Status
        "Sisa Hari": "-",
        "Expired Date": "-",
        "Detail": "-"            # <--- KOLOM BARU
    }
    
    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                
                # Parsing Tanggal
                expiry_date_utc = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                expiry_date_wib = expiry_date_utc.replace(tzinfo=pytz.utc).astimezone(wib)
                now = datetime.now(pytz.utc).astimezone(wib)
                delta = expiry_date_wib - now
                days_remaining = math.ceil(delta.total_seconds() / 86400)

                # Isi Data Tanggal
                result["Expired Date"] = expiry_date_wib.strftime('%d-%m-%Y')
                result["Sisa Hari"] = days_remaining
                
                # Logic Status (Hanya Valid / Warning / Expired)
                if days_remaining < 0:
                    result["Status"] = "EXPIRED"
                    result["Detail"] = "Certificate has expired"
                elif days_remaining < warning_days:
                    result["Status"] = "WARNING"
                    result["Detail"] = f"Expiring soon ({days_remaining} days)"
                else:
                    result["Status"] = "VALID"
                    result["Detail"] = "Certificate is valid"
                    
    # --- MENANGKAP PENYEBAB ERROR ---
    except ssl.CertificateError as e:
        # Ini error yang kemarin kamu temui (Hostname Mismatch)
        result["Status"] = "Error"
        result["Detail"] = "Hostname Mismatch (Salah Sertifikat)" 
    except ssl.SSLError as e:
        result["Status"] = "Error"
        result["Detail"] = "SSL Handshake Failed / Self-Signed"
    except socket.timeout:
        result["Status"] = "Error"
        result["Detail"] = "Connection Timeout (Web Down)"
    except socket.gaierror:
        result["Status"] = "Error"
        result["Detail"] = "DNS Error (Domain not found)"
    except Exception as e:
        result["Status"] = "Error"
        result["Detail"] = str(e)
    
    return result

def run_ssl_scan(list_file_path):
    output_data = []
    try:
        with open(list_file_path, "r") as f:
            domains = [sanitize(line) for line in f if line.strip()]
            for domain in domains:
                res = cek_ssl_expiry(domain)
                output_data.append(res)
    except Exception as e:
        print(f"Error reading file: {e}")
    return output_data