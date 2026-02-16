from concurrent.futures import ThreadPoolExecutor, as_completed
from io import BytesIO
import json

import streamlit as st
import pandas as pd

from utils.burp_scanner import BurpScanner


st.set_page_config(page_title="VA Dashboard Pro - Burp", layout="wide")


def _top_nav():
    cols = st.columns(3)
    with cols[0]:
        if st.button("Dashboard", use_container_width=True):
            st.switch_page("app.py")
    with cols[1]:
        if st.button("Acunetix", use_container_width=True):
            st.switch_page("pages/1_Acunetix.py")
    with cols[2]:
        st.button("Burp", disabled=True, use_container_width=True)


st.title("Burp-like Vulnerability Scan")
_top_nav()

with st.sidebar:
    st.header("Scan Settings (Burp-mode)")

    aggressive = st.checkbox("Aggressive", value=True)
    crawl = st.checkbox("Crawl (same-origin)", value=True)
    verify_tls = st.checkbox("Verify TLS", value=True)

    max_pages = st.slider("Max pages", min_value=1, max_value=50, value=12)
    max_req = st.slider("Max requests per detector", min_value=1, max_value=100, value=20)

    concurrency = st.slider("Concurrency", min_value=1, max_value=10, value=3)

st.caption("Note: This is a Burp-like heuristic scanner. Aggressive mode may generate additional requests.")

with st.form("burp_form"):
    targets_text = st.text_area(
        "Target List (URLs):",
        height=160,
        placeholder="https://example.com\nhttps://target.tld/app?x=1",
    )
    submitted = st.form_submit_button("Run Burp Scan")

if "burp_results" not in st.session_state:
    st.session_state["burp_results"] = None


def _scan_one(target: str):
    scanner = BurpScanner(
        aggressive=aggressive,
        crawl=crawl,
        max_pages=max_pages,
        max_requests_per_detector=max_req,
        verify_tls=verify_tls,
    )
    return scanner.scan_target(target)


if submitted:
    targets = [t.strip() for t in (targets_text or "").splitlines() if t.strip()]
    if not targets:
        st.warning("Isi target dulu!")
    else:
        progress = st.progress(0)
        status = st.empty()

        results = {}
        completed = 0

        with st.spinner("Scanning..."):
            with ThreadPoolExecutor(max_workers=concurrency) as ex:
                fut_map = {ex.submit(_scan_one, t): t for t in targets}
                total = len(fut_map)

                for fut in as_completed(fut_map):
                    t = fut_map[fut]
                    try:
                        results[t] = fut.result()
                    except Exception as e:
                        results[t] = [{"name": "scan", "status": "ERROR", "details": str(e)}]

                    completed += 1
                    progress.progress(int(completed / total * 100))
                    status.write(f"Done {completed}/{total}: {t}")

        st.session_state["burp_results"] = results
        st.success("Scanning Done!")


if st.session_state["burp_results"]:
    all_results = st.session_state["burp_results"]

    st.subheader("Summary")

    summary_rows = []
    for target, items in all_results.items():
        counts = {}
        for it in items:
            s = (it.get("status") or "UNKNOWN")
            counts[s] = counts.get(s, 0) + 1
        summary_rows.append(
            {
                "target": target,
                "total": len(items),
                "VULNERABLE": counts.get("VULNERABLE", 0),
                "FOUND": counts.get("FOUND", 0),
                "RISKY": counts.get("RISKY", 0),
                "WEAK": counts.get("WEAK", 0),
                "MISSING": counts.get("MISSING", 0),
                "POTENTIAL": counts.get("POTENTIAL", 0),
                "ERROR": counts.get("ERROR", 0),
                "NOT_IMPLEMENTED": counts.get("NOT_IMPLEMENTED", 0),
            }
        )

    st.dataframe(summary_rows, use_container_width=True, hide_index=True)

    def _df_safe_for_excel(df: pd.DataFrame) -> pd.DataFrame:
        # Excel writers struggle with dict/list objects; serialize them.
        if df is None or df.empty:
            return df
        out = df.copy()
        for col in out.columns:
            out[col] = out[col].apply(
                lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
            )
        return out

    def _to_xlsx_bytes(summary: list[dict], details: list[dict]) -> bytes:
        bio = BytesIO()
        with pd.ExcelWriter(bio, engine="openpyxl") as writer:
            pd.DataFrame(summary).to_excel(writer, index=False, sheet_name="summary")
            details_df = pd.json_normalize(details)
            _df_safe_for_excel(details_df).to_excel(writer, index=False, sheet_name="results")
        return bio.getvalue()

    st.write("---")
    st.subheader("Details")

    for target, items in all_results.items():
        with st.expander(target, expanded=False):
            # Build per-target summary row (same columns as global summary)
            counts = {}
            for it in items:
                s = (it.get("status") or "UNKNOWN")
                counts[s] = counts.get(s, 0) + 1
            target_summary = [
                {
                    "target": target,
                    "total": len(items),
                    "VULNERABLE": counts.get("VULNERABLE", 0),
                    "FOUND": counts.get("FOUND", 0),
                    "RISKY": counts.get("RISKY", 0),
                    "WEAK": counts.get("WEAK", 0),
                    "MISSING": counts.get("MISSING", 0),
                    "POTENTIAL": counts.get("POTENTIAL", 0),
                    "ERROR": counts.get("ERROR", 0),
                    "NOT_IMPLEMENTED": counts.get("NOT_IMPLEMENTED", 0),
                }
            ]

            xlsx_bytes = _to_xlsx_bytes(summary=target_summary, details=items)
            st.download_button(
                label="Download Excel (XLSX)",
                data=xlsx_bytes,
                file_name="burp_scan_results.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            )

            st.dataframe(pd.json_normalize(items), use_container_width=True, hide_index=True)
