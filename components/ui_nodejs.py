import streamlit as st
import pandas as pd

def render_node_card(data):
    st.subheader("🟢 Node.js Env Check")
    
    if data:
        df = pd.DataFrame(data)

        # Rename kolom agar user-friendly
        # Pastikan key 'payload' sudah ada dari backend
        df_display = df.rename(columns={
            "URL": "Target Domain",
            "status": "Status",
            "payload": "Trigger Payload", # <--- Kolom Baru
            "finding": "Indikator Error"
        })

        # Render Tabel dengan Konfigurasi
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "Target Domain": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Trigger Payload": st.column_config.TextColumn(
                    "Trigger Payload",
                    help="Method & Data yang memicu error",
                    width="medium"
                ),
                "Indikator Error": st.column_config.TextColumn(width="large"),
            }
        )

        # Hitung Summary Statistik
        vuln_count = sum(1 for item in data if item['status'] in ['WARNING', 'CRITICAL'])
        
        if vuln_count > 0:
            st.error(f"⚠️ Ditemukan {vuln_count} Target menjalankan Dev Mode!")
        else:
            st.success("✅ Semua target aman (Production Mode)")
    else:
        st.info("Menunggu hasil scan atau data kosong...")