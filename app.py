import streamlit as st
import os

# Import UI
from components.ui_ssl import render_ssl_card
from components.ui_hsts import render_hsts_card
from components.ui_cookie import render_cookie_card
from components.ui_header import render_header_card
from components.ui_laravel import render_laravel_card
from components.ui_nodejs import render_node_card

# Import Engine
from utils.scanner_engine import start_scanning_engine

st.set_page_config(page_title="VA Dashboard Pro", layout="wide")
st.title("⚡ Security Validator")

def load_css(file_name):
    with open(file_name) as f:
        st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

# Panggil CSS eksternal
try:
    load_css("static/style.css")
except FileNotFoundError:
    st.error("File CSS tidak ditemukan! Pastikan folder 'static/style.css' ada.")

# --- 1. SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Konfigurasi Scan")
    select_all = st.checkbox("Choose All", value=False)
    
    # Dictionary: Label di UI -> Key yang dikenali Engine
    # (Pastikan string di kanan SAMA PERSIS dengan if di scanner_engine.py)
    scan_map = {
        "SSL Certificate": "SSL Certificate Check",
        "HSTS Security": "HSTS Security Check",
        "Security Headers": "Security Headers Check",
        "Cookie Secure Flag": "Cookie Secure Flag (Bash)",
        "Laravel Debug": "Laravel Debug Mode",
        "Node.js Debug": "Node.js Debug Mode"
    }
    
    selected_scans = []
    
    # Loop bikin checkbox otomatis
    for label, engine_key in scan_map.items():
        # Kalau Select All dicentang, default-nya True. Kalau enggak, False.
        is_checked = st.checkbox(label, value=select_all)
        if is_checked:
            selected_scans.append(engine_key)

# --- INPUT USER ---
with st.form("scanner_form"):
    input_text = st.text_area("Target List (Satu per baris):", height=150)
    submitted = st.form_submit_button("🚀 Mulai Scan")

# --- MAIN LOGIC ---
if submitted:
    if not input_text.strip():
        st.warning("⚠️ Isi target dulu bos!")
    elif not selected_scans:
        st.warning("⚠️ Pilih minimal satu modul scan!")
    else:
        # Prepare Data
        temp_file = "temp_list.txt"
        with open(temp_file, "w") as f: f.write(input_text)
        targets_list = [t.strip() for t in input_text.splitlines() if t.strip()]

        # PANGGIL ENGINE
        with st.spinner("Sedang memproses..."):
            # Kita lempar data ke file sebelah, trus tunggu hasilnya balik
            scan_results = start_scanning_engine(targets_list, selected_scans, temp_file)

        st.success("✅ Scanning Selesai!")
        
        # DYNAMIC RENDERING BASED ON AVAILABLE DATA (DYNAMIC POSITIONING)
        active_modules = []

        # Cek satu-satu, kalau ada datanya, masukkan ke antrian render
        # Urutan append menentukan urutan tampilan
        if scan_results["ssl"]: 
            active_modules.append({"func": render_ssl_card, "data": scan_results["ssl"]})
            
        if scan_results["hsts"]: 
            active_modules.append({"func": render_hsts_card, "data": scan_results["hsts"]})
            
        if scan_results["header"]: 
            active_modules.append({"func": render_header_card, "data": scan_results["header"]})
            
        if scan_results["cookie"]: 
            active_modules.append({"func": render_cookie_card, "data": scan_results["cookie"]})
            
        if scan_results["laravel"]: 
            active_modules.append({"func": render_laravel_card, "data": scan_results["laravel"]})
            
        if scan_results["node"]: 
            active_modules.append({"func": render_node_card, "data": scan_results["node"]})

        # --- RENDER KE 3 KOLOM SECARA BERURUTAN ---
        if active_modules:
            cols = st.columns(3) # Bikin 3 slot kolom
            
            for i, module in enumerate(active_modules):
                # Logic Modulo: 
                # Item ke-0 masuk Col 0
                # Item ke-1 masuk Col 1
                # Item ke-2 masuk Col 2
                # Item ke-3 masuk Col 0 lagi (Baris baru otomatis)
                with cols[i % 3]:
                    module["func"](module["data"])
        else:
            st.warning("Scan selesai tapi tidak ada data yang dihasilkan.")