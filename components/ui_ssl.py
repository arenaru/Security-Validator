import streamlit as st
import pandas as pd

def render_ssl_card(hasil_ssl):
    st.subheader("🔒 SSL Expiry")
    
    if hasil_ssl:
        df = pd.DataFrame(hasil_ssl)
        
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
            # Hitung yang statusnya 'Error' atau 'EXPIRED'
            error_count = df[df['Status'].str.lower().isin(['error', 'expired'])].shape[0]
            
            if error_count > 0:
                st.error(f"⚠️ {error_count} Masalah ditemukan (Error/Expired)!")
            else:
                st.success("✅ Semua SSL Valid")
    else:
        st.warning("Tidak ada data SSL atau gagal scan.")