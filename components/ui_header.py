import streamlit as st
import pandas as pd

def render_header_card(header_results):
    st.subheader("🛡️ Security Headers")
    
    if header_results:
        df_headers = pd.DataFrame(header_results)
        st.dataframe(df_headers, use_container_width=True)
        
        # Cek apakah ada kolom 'Status' untuk hitung vulnerability
        if 'Status' in df_headers.columns:
            vuln_sites = df_headers[df_headers['Status'] == 'VULNERABLE'].shape[0]
            
            if vuln_sites > 0:
                st.warning(f"⚠️ {vuln_sites} Domain missing headers")
            else:
                st.success("✅ Headers Lengkap!")
    else:
        st.warning("Gagal scan headers atau data kosong.")