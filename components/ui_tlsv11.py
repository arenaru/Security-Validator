import streamlit as st
import pandas as pd

def render_tlsv11_card(hasil_tlsv11):
    st.subheader("🔒 TLS 1.1 Detection")
    
    if hasil_tlsv11:
        df = pd.DataFrame(hasil_tlsv11)
        
        # Rename kolom untuk tampilan yang lebih baik
        df_display = df.rename(columns={
            "target": "URL",
            "status": "Status",
            "details": "Detail"
        })

        # Render Tabel dengan Status color coding
        st.dataframe(
            df_display, 
            use_container_width=True,
            column_config={
                "URL": st.column_config.TextColumn(width="medium"),
                "Status": st.column_config.TextColumn(width="small"),
                "Detail": st.column_config.TextColumn(
                    width="large",
                    help="Penjelasan status atau alasan error"
                ),
            }
        )
        
        # Summary Statistik
        if 'status' in df.columns:
            insecure_count = df[df['status'].str.upper() == 'INSECURE'].shape[0]
            error_count = df[df['status'].str.upper() == 'ERROR'].shape[0]
            secure_count = df[df['status'].str.upper() == 'SECURE'].shape[0]
            
            # col1, col2, col3 = st.columns(3)
            # with col1:
            #     st.metric("Insecure", insecure_count, delta=None, delta_color="inverse")
            # with col2:
            #     st.metric("Error", error_count, delta=None, delta_color="off")
            # with col3:
            #     st.metric("Secure", secure_count, delta=None, delta_color="normal")
            
            if insecure_count > 0:
                st.error(f"⚠️ {insecure_count} Domain(s) with TLS 1.1 Enabled!")
            elif error_count > 0:
                st.warning(f"⚠️ {error_count} Domain(s) with Error!")
            else:
                st.success("✅ All TLS 1.1 Disabled (Secure)")
    else:
        st.warning("No TLS 1.1 scan data available or scan failed")

