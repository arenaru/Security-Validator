import json
import os
import streamlit as st

# Lokasi file JSON hasil scraper
SCRAPED_DB_FILE = os.path.join(os.path.dirname(__file__), 'acunetix_vulnerabilities.json')

@st.cache_resource
def load_severity_db():
    """
    Load database langsung dari file JSON tanpa mapping manual.
    Disimpan dalam dictionary dengan key lowercase untuk pencarian yang case-insensitive.
    """
    master_db = {}
    
    if os.path.exists(SCRAPED_DB_FILE):
        try:
            with open(SCRAPED_DB_FILE, 'r', encoding='utf-8') as f:
                data = json.load(f)
                
                # Loop semua item di JSON
                for item in data:
                    name = item.get('vulnerability_name', '').strip()
                    severity = item.get('severity', 'Info').strip()
                    
                    if name:
                        # Kita simpan key dalam lowercase agar pencarian tidak sensitif huruf besar/kecil
                        # Value (Severity) kita format jadi Title Case (misal: "medium" -> "Medium")
                        master_db[name.lower()] = severity.capitalize()
                        
        except Exception as e:
            print(f"[ERROR] Gagal membaca database vulnerabilities: {e}")
    else:
        print(f"[WARNING] File database tidak ditemukan di: {SCRAPED_DB_FILE}")
        
    return master_db

def get_vuln_severity(vuln_name):
    """
    Mencari severity berdasarkan nama vulnerability.
    Langsung lookup ke database JSON yang sudah diload.
    """
    if not vuln_name:
        return "Info"
        
    db = load_severity_db()
    
    # Normalisasi input agar cocok dengan key database (lowercase & strip)
    key = str(vuln_name).strip().lower()
    
    # 1. Direct Lookup (Cepat & Akurat)
    if key in db:
        return db[key]
    
    # 2. Fallback: Jika tidak ketemu, return Info
    # Karena script scanner sudah disinkronkan namanya, harusnya selalu ketemu.
    return "Info"