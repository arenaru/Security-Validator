import streamlit as st
import os
from io import BytesIO

import pandas as pd

# Import UI Components
from components.ui_ssl import render_ssl_card
from components.ui_hsts import render_hsts_card
from components.ui_cookie import render_cookie_card
from components.ui_header import render_header_card
from components.ui_laravel import render_laravel_card
from components.ui_nodejs import render_node_card
from components.ui_sslv3 import render_sslv3_card
from components.ui_tlsv10 import render_tlsv10_card
from components.ui_tlsv11 import render_tlsv11_card
from components.ui_phpversion import render_phpversion_card

# Import Engine
from utils.scanner_engine import start_scanning_engine

st.set_page_config(page_title="VA Dashboard Pro", layout="wide")
st.title("⚡ Security Validator")


def _df_from_value(value):
    if value is None:
        return pd.DataFrame()
    if isinstance(value, list):
        return pd.json_normalize(value)
    if isinstance(value, dict):
        return pd.json_normalize([value])
    return pd.DataFrame([{"value": value}])


def _to_xlsx_bytes(results: dict) -> bytes:
    summary = []
    for module, data in results.items():
        count = len(data) if isinstance(data, list) else (1 if data is not None else 0)
        summary.append({"module": module, "count": count})

    bio = BytesIO()
    with pd.ExcelWriter(bio, engine="openpyxl") as writer:
        pd.DataFrame(summary).to_excel(writer, index=False, sheet_name="summary")
        for module, data in results.items():
            sheet_name = module[:31] if module else "results"
            df = _df_from_value(data)
            df.to_excel(writer, index=False, sheet_name=sheet_name)
    return bio.getvalue()

def load_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

load_css("static/style.css")

# --- SIDEBAR ---
with st.sidebar:
    st.header("⚙️ Scan Configuration")
    select_all = st.checkbox("Choose All", value=False)
    
    scan_map = {
        "SSL Certificate": "SSL Certificate Check",
        "SSLv3 Detection": "SSLv3 Detection",
        "TLS 1.0 Detection": "TLS 1.0 Detection",
        "TLS 1.1 Detection": "TLS 1.1 Detection",
        "HSTS Security": "HSTS Security Check",
        # "Security Headers": "Security Headers Check",
        "Cookie Secure Flag": "Cookie Secure Flag (Bash)",
        "Laravel Debug": "Laravel Debug Mode",
        "Node.js Debug": "Node.js Debug Mode",
        "PHP Version Disclosure": "PHP Version Disclosure"
    }
    
    selected_scans = []
    for label, engine_key in scan_map.items():
        if st.checkbox(label, value=select_all):
            selected_scans.append(engine_key)

# --- INPUT ---
with st.form("scanner_form"):
    input_text = st.text_area("Target List:", height=150, placeholder="example.com\n192.168.1.1")
    submitted = st.form_submit_button("🚀 Run Scan")

if "scan_results" not in st.session_state:
    st.session_state["scan_results"] = None

# --- SCANNING PROCESS ---
if submitted:
    if not input_text.strip():
        st.warning("⚠️ Isi target dulu!")
    elif not selected_scans:
        st.warning("⚠️ Pilih minimal satu modul!")
    else:
        targets_list = [t.strip() for t in input_text.splitlines() if t.strip()]
        
        temp_file = "temp_list.txt"
        with open(temp_file, "w") as f: 
            f.write("\n".join(targets_list))
        
        with st.spinner("Scanning..."):
            st.session_state["scan_results"] = start_scanning_engine(targets_list, selected_scans, temp_file)
        
        st.success("✅ Scanning Done!")

# --- DISPLAY RESULTS ---
if st.session_state["scan_results"]:
    scan_results = st.session_state["scan_results"]
    
    # Mapping Data Engine ke UI Component
    # Format Engine Baru: { "SSL Certificate Check": [...], ... }
    ui_modules = [
        {"key": "SSL Certificate Check", "func": render_ssl_card},
        {"key": "SSLv3 Detection", "func": render_sslv3_card},
        {"key": "TLS 1.0 Detection", "func": render_tlsv10_card},
        {"key": "TLS 1.1 Detection", "func": render_tlsv11_card},
        {"key": "HSTS Security Check", "func": render_hsts_card},
        {"key": "Security Headers Check", "func": render_header_card},
        {"key": "Cookie Secure Flag (Bash)", "func": render_cookie_card},
        {"key": "Laravel Debug Mode", "func": render_laravel_card},
        {"key": "Node.js Debug Mode", "func": render_node_card},
        {"key": "PHP Version Disclosure", "func": render_phpversion_card}
    ]

    active_modules = [m for m in ui_modules if scan_results.get(m["key"]) is not None]

    if active_modules:
        cols = st.columns(3)
        for i, module in enumerate(active_modules):
            with cols[i % 3]:
                data = scan_results[module["key"]]
                # Render hanya jika data tidak kosong/None
                if data: 
                    module["func"](data)
                else:
                    st.info(f"No results for {module['key']}")
    
    # --- XLSX EXPORT ---
    st.write("---")
    st.subheader("📄 Export Report")

    xlsx_bytes = _to_xlsx_bytes(scan_results)
    
    st.download_button(
        label="📥 Download XLSX Report",
        data=xlsx_bytes,
        file_name="VA_Scan_Report.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )