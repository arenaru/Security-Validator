from fpdf import FPDF
from datetime import datetime
from utils.db_loader import get_vuln_severity

class VAReport(FPDF):
    def header(self):
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
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(230, 230, 230)
        for i, h in enumerate(headers):
            self.cell(col_widths[i], 8, h, 1, 0, 'C', 1)
        self.ln()
        
        self.set_font('Arial', '', 9)
        for row in data:
            for i, item in enumerate(row):
                text = str(item)
                # Warnai kolom Severity (Kolom terakhir)
                if i == len(row) - 1:
                    if "Critical" in text: self.set_text_color(192, 57, 43)
                    elif "High" in text: self.set_text_color(230, 126, 34)
                    elif "Medium" in text: self.set_text_color(241, 196, 15)
                    elif "Low" in text: self.set_text_color(46, 204, 113)
                    else: self.set_text_color(0, 0, 0)
                else:
                    self.set_text_color(0, 0, 0)

                if len(text) > 50: text = text[:47] + "..."
                self.cell(col_widths[i], 7, text, 1, 0, 'L')
            self.ln()
        self.ln(5)

def generate_report(results):
    pdf = VAReport()
    pdf.add_page()
    
    # 1. HSTS CHECK
    if results.get("HSTS Security Check"):
        pdf.chapter_title('HSTS Security Check')
        headers = ['Domain', 'Status', 'Severity / Detail'] # Ubah judul header dikit
        data = []
        
        secure_list, vulnerable_list = results["HSTS Security Check"]
        
        # List Aman
        for line in secure_list:
            domain = line.split(" | ")[0].strip()
            data.append([domain, "SECURE", "Safe"])
            
        # List Bermasalah (Vuln ATAU Error)
        for line in vulnerable_list:
            parts = line.split(" | ")
            domain = parts[0].strip()
            
            # Cek apakah ini Error atau Vuln
            if len(parts) >= 3 and parts[1].strip() == "ERROR":
                # KASUS ERROR
                status = "ERROR"
                error_detail = parts[2].strip() # Ambil pesan errornya
                severity_display = error_detail # Tampilkan pesan error di kolom severity
            else:
                # KASUS VULN BIASA
                status = "INSECURE"
                vuln_name = parts[1].strip() if len(parts) > 1 else "HSTS Not Enabled"

                vuln_lookup_name = vuln_name
                if "max-age=0" in vuln_name:
                    vuln_lookup_name = "HTTP Strict Transport Security (HSTS) Policy Not Enabled"

                severity_display = get_vuln_severity(vuln_lookup_name) # Ambil "Medium" dari DB

            data.append([domain, status, severity_display])

        # Render Tabel
        pdf.chapter_body(headers, data, [80, 40, 70])

    # 2. SSL CHECK
    if results.get("SSL Certificate Check"):
        pdf.chapter_title('SSL Certificate Check')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["SSL Certificate Check"]:
            status = item['Status']
            vuln_name = item.get('vuln_name', 'SSL Certificate Check')
            if vuln_name: vuln_name = vuln_name.strip()
            
            severity = "Safe"
            if status != 'VALID':
                severity = get_vuln_severity(vuln_name)
            
            data.append([item['URL'], status, severity])
        pdf.chapter_body(headers, data, [80, 50, 60])

    # 3. LARAVEL
    if results.get("Laravel Debug Mode"):
        pdf.chapter_title('Laravel Debug Mode')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["Laravel Debug Mode"]:
            status = item['status']
            severity = "Safe"
            if status in ['VULNERABLE', 'CRITICAL', 'WARNING']:
                vuln_name = item.get('vuln_name', 'Laravel Debug Mode Enabled')
                if vuln_name: vuln_name = vuln_name.strip()
                severity = get_vuln_severity(vuln_name)
                
            data.append([item['URL'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])
        
    # 4. NODE.JS
    if results.get("Node.js Debug Mode"):
        pdf.chapter_title('Node.js Debug Mode')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["Node.js Debug Mode"]:
            status = item['status']
            severity = "Safe"
            if status in ['VULNERABLE', 'WARNING']:
                vuln_name = item.get('vuln_name', 'Node.js Debug Mode Enabled')
                if vuln_name: vuln_name = vuln_name.strip()
                severity = get_vuln_severity(vuln_name)
            data.append([item['URL'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    # 5. SECURITY HEADERS
    if results.get("Security Headers Check"):
        pdf.chapter_title('Security Headers Check')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["Security Headers Check"]:
            status = item.get('Status', 'UNKNOWN')
            severity = "Safe"
            if status == 'VULNERABLE':
                vuln_name = item.get('vuln_name', 'Missing Security Headers')
                if vuln_name: vuln_name = vuln_name.strip()
                severity = get_vuln_severity(vuln_name)
            data.append([item['URL'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    # 6. COOKIE (BASH)
    if results.get("Cookie Secure Flag (Bash)"):
        pdf.chapter_title('Cookie Secure Flag Check')
        headers = ['URL', 'Status', 'Severity']
        data = []
        raw_output = results["Cookie Secure Flag (Bash)"]
        if raw_output:
            for line in raw_output.splitlines():
                parts = line.split("|")
                if len(parts) >= 3:
                    url, status, msg = parts[0].strip(), parts[1].strip(), parts[2].strip()
                    severity = "Safe"
                    if status == "VULNERABLE":
                        severity = get_vuln_severity(msg)
                    data.append([url, status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    # 7. SSLv3 DETECTION
    if results.get("SSLv3 Detection"):
        pdf.chapter_title('SSLv3 Detection')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["SSLv3 Detection"]:
            status = item['status']
            severity = "Safe"
            if status.upper() == 'INSECURE':
                severity = get_vuln_severity('SSLv3 Detected (POODLE Vulnerability)')
            elif status.upper() == 'ERROR':
                severity = 'Unknown'
            data.append([item['target'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    # 8. TLS 1.0 DETECTION
    if results.get("TLS 1.0 Detection"):
        pdf.chapter_title('TLS 1.0 Detection')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["TLS 1.0 Detection"]:
            status = item['status']
            severity = "Safe"
            if status.upper() == 'INSECURE':
                severity = get_vuln_severity('TLS 1.0 Detected (Deprecated)')
            elif status.upper() == 'ERROR':
                severity = 'Unknown'
            data.append([item['target'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    # 9. TLS 1.1 DETECTION
    if results.get("TLS 1.1 Detection"):
        pdf.chapter_title('TLS 1.1 Detection')
        headers = ['URL', 'Status', 'Severity']
        data = []
        for item in results["TLS 1.1 Detection"]:
            status = item['status']
            severity = "Safe"
            if status.upper() == 'INSECURE':
                severity = get_vuln_severity('TLS 1.1 Detected (Deprecated)')
            elif status.upper() == 'ERROR':
                severity = 'Unknown'
            data.append([item['target'], status, severity])
        pdf.chapter_body(headers, data, [100, 30, 60])

    return pdf.output(dest='S').encode('latin-1') 