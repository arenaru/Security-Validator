import streamlit as st
import pandas as pd

def render_ssl_card(hasil_ssl):
    st.subheader("🔒 SSL Expiry")
    
    if hasil_ssl:
        df = pd.DataFrame(hasil_ssl)
        
        # Ngehilangin kolom vuln_name yang gak perlu ditampilin
        if 'vuln_name' in df.columns:
            df = df.drop(columns=['vuln_name'])

        # Rename kolom: Tampilkan URL, Status, Sisa Hari, Expired Date, Detail
        df_display = df.rename(columns={
            "URL": "Target Domain",
            "Detail": "Keterangan Error / Detail" # <--- Header Kolom Detail
        })

        # Render Tabel Standard (Tanpa Issuer, Tanpa Warna Custom)
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "Target Domain": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Sisa Hari": st.column_config.NumberColumn(format="%d hari"),
                "Expired Date": st.column_config.TextColumn(width="small"),
                "Keterangan Error / Detail": st.column_config.TextColumn(
                    "Detail",
                    width="large",
                    help="Penjelasan kenapa status Error/Expired"
                ),
            }
        )
        
        # Summary Statistik
        if 'Status' in df.columns:
            # Hitung yang statusnya 'EXPIRED', 'WARNING', atau 'Error'
            expired_count = df[df['Status'].str.lower().isin(['expired'])].shape[0]
            warning_count = df[df['Status'].str.lower().isin(['warning'])].shape[0]
            err_count = df[df['Status'].str.lower().isin(['error'])].shape[0]
            
            if expired_count > 0:
                st.error(f"⚠️ {expired_count} Domain(s) Expired!")
            elif err_count > 0:
                st.error(f"⚠️ {err_count} Domain(s) Error!")
            elif warning_count > 0:
                st.warning(f"⚠️ {warning_count} Domain(s) Warning!")
            else:
                st.success("✅ All SSL Valid")
    else:
        st.warning("No SSL data or scan failed")