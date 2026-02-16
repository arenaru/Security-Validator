import streamlit as st
import os

st.set_page_config(page_title="VA Dashboard Pro", layout="wide")


def _top_nav():
    cols = st.columns(2)
    with cols[0]:
        if st.button("Acunetix", use_container_width=True):
            st.switch_page("pages/1_Acunetix.py")
    with cols[1]:
        if st.button("Burp", use_container_width=True):
            st.switch_page("pages/2_Burp.py")

def load_css(file_name):
    if os.path.exists(file_name):
        with open(file_name) as f:
            st.markdown(f'<style>{f.read()}</style>', unsafe_allow_html=True)

load_css("static/style.css")

st.title("Security Validator")
st.subheader("Welcome")
st.write("Choose a scanner mode to continue.")

_top_nav()

st.write("---")
st.write(
    "- Acunetix-mode: runs your existing module-based checks and exports the PDF report.\n"
    "- Burp-mode: runs the Burp-like heuristic scanner (including the aggressive detectors you asked for)."
)