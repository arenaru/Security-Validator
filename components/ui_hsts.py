import streamlit as st
import pandas as pd

def render_hsts_card(hsts_data):
    st.subheader("🌐 HSTS Check")
    
    if hsts_data:
        # Unpack tuple yang dikirim dari main_app
        aman_list, gagal_list = hsts_data
        
        # --- KONVERSI KE DATAFRAME AGAR BISA DOWNLOAD CSV ---
        combined_data = []

        # Parsing list Aman
        for item in aman_list:
            # Format item dari backend: "url | header_value"
            parts = item.split(" | ")
            combined_data.append({
                "URL": parts[0],
                "Status": "SECURE",
                "Details": parts[1] if len(parts) > 1 else "OK"
            })

        # Parsing list Gagal
        for item in gagal_list:
            parts = item.split(" | ")
            combined_data.append({
                "URL": parts[0],
                "Status": "INSECURE",
                "Details": parts[1] if len(parts) > 1 else "Missing/Error"
            })

        # Render Tabel
        if combined_data:
            df = pd.DataFrame(combined_data)
            st.dataframe(df, use_container_width=True)
            
            # Statistik
            insecure_count = df[df['Status'] == 'INSECURE'].shape[0]
            if insecure_count > 0:
                st.error(f"⚠️ {insecure_count} Domain tidak aktif HSTS")
            else:
                st.success("✅ Semua domain aktif HSTS")
        else:
            st.warning("Hasil scan HSTS kosong.")
    else:
        st.error("Gagal menerima data HSTS.")