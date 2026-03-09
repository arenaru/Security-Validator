import pandas as pd
import streamlit as st


def render_ssl_hostname_card(results):
    st.subheader("🔐 SSL Hostname Mismatch")

    if results and isinstance(results, list):
        df = pd.DataFrame(results)
        df_display = df.rename(
            columns={
                "URL": "Target Domain",
                "Detail": "Detail",
            }
        )

        if "vuln_name" in df_display.columns:
            df_display = df_display.drop(columns=["vuln_name"])

        st.dataframe(df_display, use_container_width=True)

        warning_count = df[df["Status"].str.lower() == "warning"].shape[0] if "Status" in df.columns else 0
        error_count = df[df["Status"].str.lower() == "error"].shape[0] if "Status" in df.columns else 0
        valid_count = df[df["Status"].str.lower() == "valid"].shape[0] if "Status" in df.columns else 0

        if warning_count > 0:
            st.error(f"⚠️ {warning_count} domain(s) have SSL hostname mismatch")
        elif error_count > 0:
            st.warning(f"⚠️ {error_count} domain(s) failed to check")
        else:
            st.success(f"✅ All {valid_count} domain(s) match certificate hostname")
    else:
        st.warning("No SSL hostname mismatch data available")
