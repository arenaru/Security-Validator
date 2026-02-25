import subprocess
import shutil
from urllib.parse import urlparse

def check_tls10(target):
    if not shutil.which("nmap"):
        return {"target": target, "status": "ERROR", "details": "Nmap not installed"}

    # Parse domain from URL
    if "://" not in target:
        target = "https://" + target
    
    parsed = urlparse(target)
    domain_only = parsed.netloc # Ini cuma ambil "example.com"

    try:
        cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "-Pn", domain_only]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = process.stdout
        
        if "TLSv1.0" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "TLS 1.0 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.0)"
            }
        elif "TLSv" in output or "SSLv" in output:
            return {
                "target": target,
                "status": "SECURE",
                "details": "TLS 1.0 Disabled"
            }
        else:
            return {"target": target, "status": "ERROR", "details": "No SSL Service"}

    except Exception as e:
        return {"target": target, "status": "ERROR", "details": str(e)}