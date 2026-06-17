import streamlit as st
import pandas as pd


def render_response_code_card(response_code_results):
    st.subheader("🔎 Response Code Check")

    if response_code_results and isinstance(response_code_results, list):
        df = pd.DataFrame(response_code_results)

        display_columns = [col for col in ["URL", "Status Code", "Reason", "Category", "Message"] if col in df.columns]
        df_display = df[display_columns] if display_columns else df

        st.dataframe(df_display, use_container_width=True)

        if "Category" in df.columns:
            success_count = df[df["Category"] == "SUCCESS"].shape[0]
            redirect_count = df[df["Category"] == "REDIRECT"].shape[0]
            client_error_count = df[df["Category"] == "CLIENT_ERROR"].shape[0]
            server_error_count = df[df["Category"] == "SERVER_ERROR"].shape[0]
            error_count = df[df["Category"] == "ERROR"].shape[0]

            if client_error_count > 0 or server_error_count > 0:
                st.warning(
                    f"⚠️ {client_error_count} client error(s) and {server_error_count} server error(s) found."
                )
            elif redirect_count > 0:
                st.info(f"ℹ️ {redirect_count} target(s) returned redirect response codes.")
            elif error_count > 0:
                st.warning(f"⚠️ {error_count} target(s) could not be reached.")
            else:
                st.success(f"✅ All {success_count} target(s) returned successful response codes.")
    else:
        st.warning("No response code data available")
