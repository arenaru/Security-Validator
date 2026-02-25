import streamlit as st
import pandas as pd

def render_cookie_card(results):
    st.subheader("🍪 Cookie Security Check")
    
    # Results is a list of dicts from cookieSecure.py
    if results and isinstance(results, list):
        # Convert to DataFrame
        df_cookie = pd.DataFrame(results)
        
        # Rename columns for display
        df_cookie.columns = ['URL', 'Status', 'Message']
        
        # Display table
        st.dataframe(df_cookie, use_container_width=True)
        
        # Count vulnerabilities and errors
        vuln_count = df_cookie[df_cookie['Status'] == 'VULNERABLE'].shape[0]
        err_count = df_cookie[df_cookie['Status'] == 'ERROR'].shape[0]
        safe_count = df_cookie[df_cookie['Status'] == 'SAFE'].shape[0]

        # Show only highest priority message
        if vuln_count > 0:
            st.error(f"⚠️ {vuln_count} site(s) with insecure cookies found!")
        elif err_count > 0:
            st.warning(f"⚠️ {err_count} site(s) had connection errors")
        else:
            st.success(f"✅ All {safe_count} site(s) have secure cookies!")
    else:
        st.warning("No cookie data available")