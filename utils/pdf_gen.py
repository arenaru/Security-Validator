import json
import os
from fpdf import FPDF
from datetime import datetime

# [INTEGRASI BARU] Import logika severity dari db_loader
# Pastikan db_loader.py ada di folder utils/
try:
    from utils.db_loader import get_vuln_severity
except ImportError:
    # Fallback jika dijalankan manual/testing di luar folder
    from db_loader import get_vuln_severity

class VAReport(FPDF):
    def header(self):
        if self.page_no() == 1:
            self.set_font('Arial', 'B', 16)
            self.cell(0, 10, 'Security Assessment Report', 0, 1, 'C')
            self.set_font('Arial', 'I', 10)
            self.cell(0, 10, f'Generated on: {datetime.now().strftime("%Y-%m-%d %H:%M")}', 0, 1, 'C')
            self.line(10, 30, 200, 30)
            self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', 'I', 8)
        self.cell(0, 10, f'Page {self.page_no()}', 0, 0, 'C')

    def chapter_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_fill_color(44, 62, 80)
        self.set_text_color(255, 255, 255)
        self.cell(0, 8, f"  {title}", 0, 1, 'L', 1)
        self.set_text_color(0, 0, 0)
        self.ln(4)

    def chapter_body(self, headers, data, col_widths):
        self.set_font('Arial', 'B', 10)
        self.set_fill_color(230, 230, 230)
        for i, header in enumerate(headers):
            self.cell(col_widths[i], 7, header, 1, 0, 'C', 1)
        self.ln()
        
        self.set_font('Arial', '', 9)
        for row in data:
            nb_lines = []
            for i, content in enumerate(row):
                txt = str(content)
                cw = self.get_string_width(txt)
                width = col_widths[i] - 2 
                lines = int(cw / width) + 1 if cw > width else 1
                lines += txt.count('\n')
                nb_lines.append(lines)
            max_lines = max(nb_lines) if nb_lines else 1
            row_height = 6 * max_lines

            if self.get_y() + row_height > 275:
                self.add_page()
                # self.set_font('Arial', 'B', 10)
                # self.set_fill_color(230, 230, 230)
                # for i, header in enumerate(headers):
                #     self.cell(col_widths[i], 7, header, 1, 0, 'C', 1)
                # self.ln()
                # self.set_font('Arial', '', 9)

            x_start = self.get_x()
            y_start = self.get_y()
            for i, content in enumerate(row):
                width = col_widths[i]
                self.rect(x_start, y_start, width, row_height)
                
                # Warnai kolom Severity (Kolom terakhir)
                if i == len(row) - 1:
                    val = str(content).strip().lower()
                    if "critical" in val: self.set_text_color(192, 57, 43)
                    elif "high" in val: self.set_text_color(230, 126, 34)
                    elif "medium" in val: self.set_text_color(241, 196, 15)
                    elif "low" in val: self.set_text_color(46, 204, 113)
                    else: self.set_text_color(0, 0, 0)
                else:
                    self.set_text_color(0, 0, 0)

                self.multi_cell(width, 6, str(content), border=0, align='L')
                self.set_xy(x_start + width, y_start)
                x_start += width
            
            self.set_xy(10, y_start + row_height)
            self.set_text_color(0, 0, 0)

        self.ln(5)

# --- FUNGSI UTAMA ---
def generate_report(results):
    pdf = VAReport()
    pdf.add_page()
    
    # --- SUMMARY TABLE ---
    summary_data = {} 
    def init_host(url):
        if not url or url in ["-", "None"]: return
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        if host not in summary_data:
            summary_data[host] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}

    # Loop semua hasil untuk mendaftarkan Host (tanpa menghitung vuln dulu)
    for module_name, items in results.items():
        if not items: continue
        
        if module_name == "HSTS Security Check":
             safe, vuln = items
             for msg in safe + vuln:
                 parts = msg.split("|")
                 if parts: init_host(parts[0].strip())

        elif module_name == "Cookie Secure Flag (Bash)":
            if isinstance(items, str):
                for line in items.splitlines():
                    parts = line.split("|")
                    if len(parts) >= 1: init_host(parts[0].strip())

        elif module_name == "Security Headers Check":
             for item in items:
                 init_host(item.get("URL"))
        
        else: # Standard List of Dicts (SSL, PHP, Laravel, Node, etc)
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        init_host(item.get('URL') or item.get('url') or item.get('target'))

    # --- 2. COUNT VULNERABILITIES ---
    def count_vuln(url, vuln_name):
        if not url or url in ["-", "None"]: return
        host = url.replace("https://", "").replace("http://", "").split("/")[0]
        # Host pasti sudah ada di summary_data karena langkah 1
        
        severity = get_vuln_severity(vuln_name)
        if severity in summary_data.get(host, {}):
            summary_data[host][severity] += 1

    # Aggregation Loop (Hitung Vuln)
    for module_name, items in results.items():
        if not items: continue
        
        if module_name == "HSTS Security Check":
             _, vuln_list = items
             for msg in vuln_list:
                 parts = msg.split("|")
                 if len(parts) >= 2: count_vuln(parts[0].strip(), parts[1].strip())
                 
        elif module_name == "Cookie Secure Flag (Bash)":
            if isinstance(items, str):
                for line in items.splitlines():
                    if "VULNERABLE" in line:
                        parts = line.split("|")
                        if len(parts) >= 3: count_vuln(parts[0].strip(), parts[2].strip())

        elif module_name == "Security Headers Check":
             for item in items:
                 if item.get("Status") == "VULNERABLE" and item.get("vuln_name"):
                     count_vuln(item.get("URL"), item["vuln_name"])
        
        else:
            if isinstance(items, list):
                for item in items:
                    if isinstance(item, dict):
                        target = item.get('URL') or item.get('url') or item.get('target')
                        vuln_name = item.get('vuln_name')
                        status = str(item.get("status") or item.get("Status")).upper()
                        
                        # Hitung hanya jika statusnya error/vuln
                        if status in ["WARNING", "INSECURE", "DISCLOSURE", "CRITICAL", "ERROR"]:
                            if vuln_name: count_vuln(target, vuln_name)

    # RENDER SUMMARY TABLE
    pdf.chapter_title('Executive Summary (Vulnerability Counts)')
    headers = ['Domain', 'Critical', 'High', 'Med', 'Low', 'Info']
    cols = [80, 20, 20, 20, 20, 20]
    
    rows = []
    # Sort host secara alfabetis agar rapi
    for host in sorted(summary_data.keys()):
        c = summary_data[host]
        rows.append([host, c['Critical'], c['High'], c['Medium'], c['Low'], c['Info']])
    
    if rows: 
        pdf.chapter_body(headers, rows, cols)
    else: 
        pdf.set_font('Arial', 'I', 10)
        pdf.cell(0, 10, 'No targets scanned.', 0, 1)
    pdf.ln(10)

    # --- DETAIL MODULES ---

    # SSL
    if results.get("SSL Certificate Check"):
        pdf.chapter_title('SSL Certificate Check')
        data = []
        for item in results["SSL Certificate Check"]:
            # [INTEGRASI]
            sev = get_vuln_severity(item.get('vuln_name')) if item.get('Status') != 'VALID' else "Safe"
            data.append([item.get('URL','-'), item.get('Status','-'), item.get('Expired Date','-')[:10], sev])
        pdf.chapter_body(['URL', 'Status', 'Expiry', 'Severity'], data, [80, 25, 30, 55])

    # HSTS
    if results.get("HSTS Security Check"):
        pdf.chapter_title('HSTS Security Check')
        safe, vuln = results["HSTS Security Check"]
        data = []
        for m in vuln:
            p = m.split("|")
            url = p[0].strip()
            v_name = p[1].strip() if len(p)>1 else "Error"
            # [INTEGRASI]
            data.append([url, "FAIL", get_vuln_severity(v_name)])
        for m in safe:
            p = m.split("|")
            data.append([p[0].strip(), "PASS", "Safe"])
        if data: pdf.chapter_body(['URL', 'Status', 'Severity'], data, [80, 30, 80])

    # Security Headers
    if results.get("Security Headers Check"):
        pdf.chapter_title('Security Headers Check')
        data = []
        for item in results["Security Headers Check"]:
            # [INTEGRASI]
            sev = get_vuln_severity(item.get('vuln_name')) if item['Status'] == 'VULNERABLE' else "Safe"
            data.append([item['URL'], item['Status'], sev])
        pdf.chapter_body(['URL', 'Status', 'Severity'], data, [80, 30, 80])
    
    # PHP Version
    if results.get("PHP Version Disclosure"):
        pdf.chapter_title('PHP Version Disclosure')
        data = []
        for item in results["PHP Version Disclosure"]:
            # [INTEGRASI]
            sev = get_vuln_severity(item.get('vuln_name')) if item['status'] == "DISCLOSURE" else "Safe"
            data.append([item['URL'], item['status'], sev])
        pdf.chapter_body(['URL', 'Status', 'Severity'], data, [80, 30, 80])

    # Cookie
    if results.get("Cookie Secure Flag (Bash)"):
        pdf.chapter_title('Cookie Secure Flag')
        raw = results["Cookie Secure Flag (Bash)"]
        data = []
        if raw:
            for line in raw.splitlines():
                parts = line.split("|")
                if len(parts) >= 3:
                    # [INTEGRASI]
                    sev = get_vuln_severity(parts[2].strip()) if parts[1] == "VULNERABLE" else "Safe"
                    data.append([parts[0], parts[1], sev])
        if data: pdf.chapter_body(['URL', 'Status', 'Severity'], data, [80, 30, 80])

    # Laravel & Node & Protocols
    other_modules = [
        "Laravel Debug Mode", "Node.js Debug Mode",
        "SSLv3 Detection", "TLS 1.0 Detection", "TLS 1.1 Detection"
    ]
    for mod in other_modules:
        if results.get(mod):
            pdf.chapter_title(mod)
            data = []
            for item in results[mod]:
                status = item.get('status')
                # [INTEGRASI]
                sev = get_vuln_severity(item.get('vuln_name')) if status in ["WARNING", "CRITICAL", "INSECURE"] else "Safe"
                data.append([item.get('URL') or item.get('target'), status, sev])
            pdf.chapter_body(['URL', 'Status', 'Severity'], data, [80, 30, 80])

    return pdf.output(dest='S').encode('latin-1')