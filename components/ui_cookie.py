import streamlit as st
import pandas as pd

def render_cookie_card(raw_output_bash):
    st.subheader("🍪 Cookie (Bash)")
    
    # Cek apakah output bash ada isinya (String tidak kosong)
    if raw_output_bash and raw_output_bash.strip():
        
        # Split output menjadi list per baris
        lines = raw_output_bash.splitlines()
        data_cookie = []

        for line in lines:
            # Format dari script bash: URL|STATUS|MSG
            parts = line.split("|")
            if len(parts) == 3:
                data_cookie.append({
                    "URL": parts[0],
                    "Status": parts[1],
                    "Keterangan": parts[2]
                })
        
        # Render jika parsing berhasil
        if data_cookie:
            df_cookie = pd.DataFrame(data_cookie)
            st.dataframe(df_cookie, use_container_width=True)
            
            vuln_count = df_cookie[df_cookie['Status'] == 'VULNERABLE'].shape[0]
            err_count = df_cookie[df_cookie['Status'] == 'ERROR'].shape[0]

            if vuln_count > 0:
                st.error(f"⚠️ {vuln_count} Vulnerable Cookies Found!")
            elif err_count > 0:
                st.error(f"⚠️ {err_count} Domain Error!")
            else:
                st.success("✅ All Cookies Secure!")
        else:
            st.warning("Format output bash tidak sesuai (Cek script bash).")
            st.code(raw_output_bash) # Debugging: Tampilkan raw output
    else:
        st.warning("Tidak ada output dari script bash (Mungkin error/kosong).")