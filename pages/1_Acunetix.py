import os
from io import BytesIO
import json

import streamlit as st
import pandas as pd

# Import Engine
from utils.scanner_engine import start_scanning_engine
from utils.db_loader import get_vuln_severity


st.set_page_config(page_title="VA Dashboard Pro - Acunetix", layout="wide")


def _top_nav():
    cols = st.columns(3)
    with cols[0]:
        if st.button("Dashboard", use_container_width=True):
            st.switch_page("app.py")
    with cols[1]:
        st.button("Acunetix", disabled=True, use_container_width=True)
    with cols[2]:
        if st.button("Burp", use_container_width=True):
            st.switch_page("pages/2_Burp.py")


st.title("Acunetix-like Vulnerability Scan")

_top_nav()


def _df_safe_for_excel(df: pd.DataFrame) -> pd.DataFrame:
    if df is None or df.empty:
        return df
    out = df.copy()
    for col in out.columns:
        out[col] = out[col].apply(
            lambda v: json.dumps(v, ensure_ascii=False) if isinstance(v, (dict, list)) else v
        )
    return out


def _host_of(url: str | None) -> str | None:
    if not url:
        return None
    u = str(url).strip()
    if not u or u in ("-", "None"):
        return None
    return u.replace("https://", "").replace("http://", "").split("/")[0]


def _burp_style_status(module_name: str, raw_status: str | None, details: str | None = None) -> str:
    mod = (module_name or "").strip()
    stt = (raw_status or "").strip().upper() if raw_status is not None else ""

    if mod == "SSL Certificate Check":
        if stt in ("VALID", "SAFE", "PASS"):
            return "FOUND"
        if stt in ("EXPIRED", "INVALID", "FAIL"):
            return "VULNERABLE"
        if stt == "WARNING":
            return "RISKY"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod in ("SSLv3 Detection", "TLS 1.0 Detection", "TLS 1.1 Detection"):
        if stt == "INSECURE":
            return "WEAK"
        if stt == "SECURE":
            return "FOUND"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "HSTS Security Check":
        if stt == "PASS":
            return "FOUND"
        if stt == "FAIL":
            return "MISSING"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "Security Headers Check":
        if stt == "SECURE":
            return "FOUND"
        if stt == "VULNERABLE":
            return "MISSING"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "Cookie Secure Flag (Bash)":
        if stt == "SAFE":
            return "FOUND"
        if stt == "VULNERABLE":
            return "WEAK"
        if stt == "INFO":
            return "FOUND"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "Laravel Debug Mode":
        if stt in ("WARNING", "CRITICAL"):
            return "VULNERABLE"
        if stt == "SECURE":
            return "FOUND"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "Node.js Debug Mode":
        if stt == "WARNING":
            return "VULNERABLE"
        if stt == "SECURE":
            return "FOUND"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    if mod == "PHP Version Disclosure":
        if stt == "DISCLOSURE":
            return "RISKY"
        if stt == "SECURE":
            return "FOUND"
        if stt == "ERROR":
            return "ERROR"
        return "POTENTIAL"

    return "POTENTIAL"


def _to_burp_style_results(scan_results: dict) -> dict[str, list[dict]]:
    """Convert module-based results into Burp-like per-target finding rows."""

    per_target: dict[str, list[dict]] = {}

    def add(target_url: str | None, module: str, name: str, severity: str, status: str, details: str, detector: str | None = None):
        if not target_url:
            return
        t = str(target_url).strip()
        if not t:
            return
        per_target.setdefault(t, []).append(
            {
                "name": name,
                "severity": severity,
                "classifications": [],
                "detector": detector or module,
                "status": status,
                "details": details,
                "module": module,
            }
        )

    for module_name, items in (scan_results or {}).items():
        if not items:
            continue

        if module_name == "HSTS Security Check":
            safe_list, vuln_list = items
            for msg in safe_list or []:
                parts = [p.strip() for p in str(msg).split("|")]
                url = parts[0] if parts else None
                hsts_val = parts[1] if len(parts) > 1 else "HSTS present"
                add(url, module_name, "HSTS Present", "Info", "FOUND", hsts_val)
            for msg in vuln_list or []:
                parts = [p.strip() for p in str(msg).split("|")]
                url = parts[0] if parts else None
                if any(p.upper() == "ERROR" for p in parts):
                    details = " | ".join(parts[2:]) if len(parts) >= 3 else "HSTS check error"
                    add(url, module_name, "HSTS Check", "Info", "ERROR", details)
                else:
                    vuln_name = parts[1] if len(parts) > 1 else "HTTP Strict Transport Security (HSTS) Policy Not Enabled"
                    sev = get_vuln_severity(vuln_name)
                    add(url, module_name, vuln_name, sev, "MISSING", "HSTS header missing")

        elif module_name == "Cookie Secure Flag (Bash)":
            if isinstance(items, list):
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    url = it.get("target")
                    raw_status = it.get("status")
                    details_text = it.get("details") or ""
                    vuln_name = it.get("vuln_name")
                    
                    status = _burp_style_status(module_name, raw_status, details=details_text)
                    sev = get_vuln_severity(vuln_name) if vuln_name else "Info"
                    name = vuln_name or "Cookie Secure Flag"
                    add(url, module_name, name, sev, status, details_text)

        elif module_name == "Security Headers Check":
            if isinstance(items, list):
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    url = it.get("URL")
                    raw_status = it.get("Status")
                    missing = it.get("Missing Headers")
                    score = it.get("Score")
                    details = f"Missing: {missing} | Score: {score}" if raw_status != "SECURE" else f"Score: {score}"
                    status = _burp_style_status(module_name, raw_status, details=details)
                    name = "Missing Security Headers" if raw_status != "SECURE" else "Security Headers"
                    sev = "Info"
                    add(url, module_name, name, sev, status, details)

        else:
            if isinstance(items, list):
                for it in items:
                    if not isinstance(it, dict):
                        continue
                    url = it.get("URL") or it.get("url") or it.get("target")
                    raw_status = it.get("status") or it.get("Status")
                    vuln_name = it.get("vuln_name")
                    sev = get_vuln_severity(vuln_name) if vuln_name else "Info"

                    details_parts = []
                    for k in ("Detail", "details", "finding", "payload"):
                        if it.get(k):
                            details_parts.append(f"{k}: {it.get(k)}")
                    if module_name == "SSL Certificate Check":
                        if it.get("Expired Date"):
                            details_parts.append(f"Expired Date: {it.get('Expired Date')}")
                        if it.get("Sisa Hari") not in (None, "-"):
                            details_parts.append(f"Days left: {it.get('Sisa Hari')}")
                    details = " | ".join(details_parts) if details_parts else ""

                    status = _burp_style_status(module_name, str(raw_status) if raw_status is not None else None, details=details)
                    name = vuln_name or module_name
                    add(url, module_name, name, sev, status, details)

    # Stable ordering
    for t in list(per_target.keys()):
        per_target[t] = sorted(per_target[t], key=lambda r: (r.get("status") or "", r.get("name") or ""))

    return per_target


def load_css(file_name: str):
    if os.path.exists(file_name):
        with open(file_name, encoding="utf-8") as f:
            st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)


load_css("static/style.css")

# --- SIDEBAR ---
with st.sidebar:
    st.header("Scan Configuration (Acunetix-mode)")
    select_all = st.checkbox("Choose All", value=False)

    scan_map = {
        "SSL Certificate": "SSL Certificate Check",
        "SSLv3 Detection": "SSLv3 Detection",
        "TLS 1.0 Detection": "TLS 1.0 Detection",
        "TLS 1.1 Detection": "TLS 1.1 Detection",
        "HSTS Security": "HSTS Security Check",
        "Security Headers": "Security Headers Check",
        "Cookie Secure Flag": "Cookie Secure Flag (Bash)",
        "Laravel Debug": "Laravel Debug Mode",
        "Node.js Debug": "Node.js Debug Mode",
        "PHP Version Disclosure": "PHP Version Disclosure",
    }

    selected_scans = []
    for label, engine_key in scan_map.items():
        if st.checkbox(label, value=select_all):
            selected_scans.append(engine_key)

# --- INPUT ---
with st.form("scanner_form"):
    input_text = st.text_area("Target List:", height=150, placeholder="example.com\n192.168.1.1")
    submitted = st.form_submit_button("Run Scan")

if "scan_results_acunetix" not in st.session_state:
    st.session_state["scan_results_acunetix"] = None

# --- SCANNING PROCESS ---
if submitted:
    if not input_text.strip():
        st.warning("Isi target dulu!")
    else:
        targets_list = [t.strip() for t in input_text.splitlines() if t.strip()]

        # If user didn't pick any module, run everything implemented.
        if not selected_scans:
            selected_scans = list(scan_map.values())

        temp_file = "temp_list.txt"
        with open(temp_file, "w", encoding="utf-8") as f:
            f.write("\n".join(targets_list))

        with st.spinner("Scanning..."):
            st.session_state["scan_results_acunetix"] = start_scanning_engine(targets_list, selected_scans, temp_file)

        st.success("Scanning Done!")

# --- DISPLAY RESULTS ---
if st.session_state["scan_results_acunetix"]:
    scan_results = st.session_state["scan_results_acunetix"]

    per_target = _to_burp_style_results(scan_results)

    st.subheader("Summary")
    summary_rows = []
    for target, items in per_target.items():
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

    def _to_xlsx_bytes(summary: list[dict], details: list[dict]) -> bytes:
        bio = BytesIO()
        with pd.ExcelWriter(bio, engine="openpyxl") as writer:
            pd.DataFrame(summary).to_excel(writer, index=False, sheet_name="summary")
            details_df = pd.json_normalize(details)
            _df_safe_for_excel(details_df).to_excel(writer, index=False, sheet_name="results")
        return bio.getvalue()

    # Consolidated export for ALL domains
    all_findings = []
    for target, items in per_target.items():
        for item in items:
            finding = item.copy()
            finding["target"] = target  # Ensure target is in each row
            all_findings.append(finding)

    if all_findings:
        consolidated_xlsx = _to_xlsx_bytes(summary=summary_rows, details=all_findings)
        st.download_button(
            label="📥 Download All Domains (Consolidated Excel)",
            data=consolidated_xlsx,
            file_name="acunetix_all_domains.xlsx",
            mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            key="download_all_domains",
            use_container_width=True,
        )

    st.write("---")
    st.subheader("Details")

    for target, items in per_target.items():
        with st.expander(target, expanded=False):
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
                file_name="acunetix_scan_results.xlsx",
                mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                key=f"download_xlsx_{target}",
            )

            st.dataframe(pd.json_normalize(items), use_container_width=True, hide_index=True)
