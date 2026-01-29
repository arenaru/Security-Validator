import json
import os
import streamlit as st

# Lokasi file JSON hasil scraper (sesuai nama file yang kamu upload)
SCRAPED_DB_FILE = os.path.join(os.path.dirname(__file__), 'acunetix_vulnerabilities.json')

# --- MAPPING VITAL ---
# Menjembatani nama output script scanner dengan severity Acunetix
CUSTOM_OVERRIDES = {
    # SSL & HSTS
    "SSL Certificate Name Hostname Mismatch": "Medium",
    "SSL Certificate Expired": "Medium",
    "SSL Self-Signed": "Medium",
    "HTTP Strict Transport Security (HSTS) Policy Not Enabled": "Medium",
    "HSTS Not Enabled": "Medium",
    
    # SSL Version Detection
    "SSLv3 Detected (POODLE Vulnerability)": "High",
    "TLS 1.0 Detected (Deprecated)": "Medium",
    "TLS 1.1 Detected (Deprecated)": "Medium",
    
    # Debug Modes
    "Laravel Debug Mode Enabled": "Medium",
    "Node.js Debug Mode Enabled": "Medium",
    "Ignition RCE Exposed": "Critical",
    
    # Cookies & Headers
    "Cookie Without Secure Flag": "Low",
    "Missing Security Headers": "Low",
    "Cookie Without HttpOnly Flag": "Low"
}

@st.cache_resource
def load_severity_db():
    master_db = {}
    
    # 1. LOAD JSON SCRAPER
    if os.path.exists(SCRAPED_DB_FILE):
        try:
            with open(SCRAPED_DB_FILE, 'r', encoding='utf-8') as f:
                scraped_list = json.load(f)
                for item in scraped_list:
                    name = item.get("vulnerability_name")
                    severity_raw = item.get("severity", "info")
                    master_db[name] = severity_raw.capitalize()
        except Exception as e:
            print(f"[Warning] Gagal load JSON: {e}")

    # 2. TIMPA DENGAN CUSTOM OVERRIDES (Prioritas Utama)
    for name, severity in CUSTOM_OVERRIDES.items():
        master_db[name] = severity
        
    return master_db

def get_vuln_severity(vuln_name):
    """Mengembalikan string Severity (Critical, High, Medium, Low, Info)"""
    if not vuln_name: return "Informational"

    db = load_severity_db()
    
    # 1. Cek Exact Match
    if vuln_name in db:
        return db[vuln_name]
    
    # 2. Cek Case Insensitive
    vuln_lower = vuln_name.lower()
    for db_name, severity in db.items():
        if db_name.lower() == vuln_lower:
            return severity
            
    # 3. Fuzzy Match (Cari sebagian string)
    for db_name, severity in db.items():
        if vuln_name.lower() in db_name.lower():
            return severity

    return "Informational"