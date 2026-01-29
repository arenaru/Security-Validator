import streamlit as st

def show_sidebar():
    with st.sidebar:
        st.header("⚙️Scan Configuration")
        options = ["SSL", "SSLv3", "TLS 1.0", "TLS 1.1", "HSTS", "Cookie", "Laravel", "Node.js", "Header"]
        return st.multiselect("Pilih Modul:", options, default=options)