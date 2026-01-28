import streamlit as st
import pandas as pd

def render_laravel_card(data):
    st.subheader("🛠️ Laravel Debug Check")
    
    if data:
        df = pd.DataFrame(data)

        # Rename kolom biar header tabelnya rapi
        # Pastikan key 'payload' ada di dictionary backend
        df_display = df.rename(columns={
            "URL": "Target Domain",
            "status": "Status",
            "payload": "Trigger Payload", # <--- Kolom Baru
            "finding": "Bukti Error"
        })

        # Render Tabel dengan Konfigurasi Kolom
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "Target Domain": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Trigger Payload": st.column_config.TextColumn(
                    "Trigger / Payload",
                    help="Request spesifik yang memicu error",
                    width="medium"
                ),
                "Bukti Error": st.column_config.TextColumn(width="large"),
            }
        )

        # Hitung Summary Statistik
        vuln_count = sum(1 for item in data if item['status'] in ['WARNING', 'CRITICAL'])
        
        if vuln_count > 0:
            st.error(f"⚠️ {vuln_count} Domain Activate Laravel Debug Mode!")
        else:
            st.success("✅ All target are safe from Debug Exposure")
    else:
        st.info("Waiting for scan results or empty data...")