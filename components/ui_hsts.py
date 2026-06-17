import streamlit as st
import pandas as pd

def render_hsts_card(hsts_data):
    st.subheader("🌐 HSTS Check")
    
    if hsts_data:
        # Unpack tuple dari scanner engine
        aman_list, gagal_list = hsts_data
        
        combined_data = []

        # 1. Parsing List AMAN (SECURE)
        for item in aman_list:
            parts = item.split(" | ")
            combined_data.append({
                "URL": parts[0].strip(),
                "Status": "SECURE",
                "Details": parts[1].strip() if len(parts) > 1 else "OK"
            })

        # 2. Parsing List GAGAL (INSECURE vs ERROR)
        for item in gagal_list:
            parts = item.split(" | ")
            domain = parts[0].strip()
            
            # Cek apakah ini ERROR Koneksi atau Vulnerability
            # Format Scanner: "URL | ERROR | Reason"
            if len(parts) >= 3 and parts[1].strip() == "ERROR":
                combined_data.append({
                    "URL": domain,
                    "Status": "ERROR",  # Status Khusus Error
                    "Details": parts[2].strip() # Ambil pesan errornya (Timeout/Refused)
                })
            elif len(parts) >= 4 and parts[1].strip() == "HTTP_STATUS":
                combined_data.append({
                    "URL": domain,
                    "Status": f"HTTP {parts[2].strip()}",
                    "Details": parts[3].strip()
                })
            elif len(parts) >= 3 and parts[1].strip() == "NOT_FOUND":
                combined_data.append({
                    "URL": domain,
                    "Status": "NOT FOUND",
                    "Details": f"HTTP {parts[2].strip()} {parts[3].strip()}"
                })
            else:
                # Format Scanner: "URL | HSTS Not Enabled"
                combined_data.append({
                    "URL": domain,
                    "Status": "INSECURE",
                    "Details": parts[1].strip() if len(parts) > 1 else "Missing"
                })

        # --- RENDER TABLE ---
        if combined_data:
            df = pd.DataFrame(combined_data)
            
            st.dataframe(df, use_container_width=True)
            
            # --- SUMMARY METRICS ---
            # Hitung jumlah berdasarkan Status
            secure_count = df[df['Status'] == 'SECURE'].shape[0]
            insecure_count = df[df['Status'] == 'INSECURE'].shape[0]
            error_count = df[df['Status'] == 'ERROR'].shape[0]
            not_found_count = df[df['Status'] == 'NOT FOUND'].shape[0]
            http_status_count = df[df['Status'].astype(str).str.startswith('HTTP ')].shape[0]

            # Tampilkan Summary
            if 'Status' in df.columns:
                # Hitung jumlah masalah (INSECURE atau ERROR)
                problem_count = df[df['Status'].isin(['INSECURE', 'ERROR'])].shape[0]
                
                if problem_count > 0:
                    # Tampilkan detail jumlah di dalam pesan error
                    vuln_count = df[df['Status'] == 'INSECURE'].shape[0]
                    # err_count = df[df['Status'] == 'ERROR'].shape[0]
                    
                    st.error(f"⚠️{vuln_count} Domain(s) not Activate HSTS!")
                else:
                    st.success("✅ All Domain are Safe (HSTS Enabled)")
                if not_found_count > 0:
                    st.info(f"{not_found_count} target(s) returned HTTP 404 Not Found and were excluded from insecure count.")
                if http_status_count > 0:
                    st.info(f"{http_status_count} target(s) returned non-200/302 HTTP status and were excluded from insecure count.")
                
    else:
        st.info("Belum ada data HSTS.")