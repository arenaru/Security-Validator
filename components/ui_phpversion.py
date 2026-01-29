import streamlit as st
import pandas as pd

def render_phpversion_card(hasil_php_version):
    st.subheader("📄 PHP Version Disclosure")
    
    if hasil_php_version:
        df = pd.DataFrame(hasil_php_version)
        
        # Rename kolom untuk tampilan yang lebih baik
        df_display = df.rename(columns={
            "target": "URL",
            "status": "Status",
            "details": "Detail"
        })
        
        # Drop vuln_name kolom (tidak perlu ditampilkan)
        if 'vuln_name' in df_display.columns:
            df_display = df_display.drop(columns=['vuln_name'])

        # Render Tabel dengan Status color coding
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "URL": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Detail": st.column_config.TextColumn(
                    width="large",
                    help="Penjelasan status atau versi PHP yang terdeteksi"
                ),
            }
        )
        
        # Summary Statistik
        if 'status' in df.columns:
            disclosure_count = df[df['status'].str.upper() == 'DISCLOSURE'].shape[0]
            error_count = df[df['status'].str.upper() == 'ERROR'].shape[0]
            secure_count = df[df['status'].str.upper() == 'SECURE'].shape[0]
            
            if disclosure_count > 0:
                st.warning(f"⚠️ {disclosure_count} Domain(s) with PHP Version Disclosure!")
            elif error_count > 0:
                st.warning(f"⚠️ {error_count} Domain(s) with Error!")
            else:
                st.success("✅ All Domains Secure (No PHP Version Disclosure)")
    else:
        st.warning("No PHP Version Disclosure data or scan failed")
