import streamlit as st
import pandas as pd


def render_httponly_card(results):
    st.subheader("🍪 Cookie HttpOnly Check")

    if results and isinstance(results, list):
        df_cookie = pd.DataFrame(results)
        df_cookie.columns = ['URL', 'Status', 'Message']
        st.dataframe(df_cookie, use_container_width=True)

        vuln_count = df_cookie[df_cookie['Status'] == 'VULNERABLE'].shape[0]
        err_count = df_cookie[df_cookie['Status'] == 'ERROR'].shape[0]
        safe_count = df_cookie[df_cookie['Status'] == 'SAFE'].shape[0]

        if vuln_count > 0:
            st.error(f"⚠️ {vuln_count} site(s) with missing HttpOnly cookies found!")
        elif err_count > 0:
            st.warning(f"⚠️ {err_count} site(s) had connection errors")
        else:
            st.success(f"✅ All {safe_count} site(s) have HttpOnly cookies!")
    else:
        st.warning("No HttpOnly cookie data available")
