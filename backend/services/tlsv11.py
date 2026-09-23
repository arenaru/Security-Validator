import subprocess
import shutil

from backend.utils.target_resolver import UnsafeTargetError, extract_nmap_host

def check_tls11(target):
    if not shutil.which("nmap"):
        return {
            "target": target, 
            "status": "ERROR", 
            "details": "Nmap not installed", 
            "vuln_name": None
        }
    
    try:
        domain_only = extract_nmap_host(target)
    except UnsafeTargetError as exc:
        return {
            "target": target,
            "status": "ERROR",
            "details": str(exc),
            "vuln_name": None
        }

    try:
        # Menjalankan Nmap
        cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "-Pn", domain_only]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = process.stdout
        
        if "TLSv1.1" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "TLS 1.1 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (TLS 1.1)"
            }
        elif "TLSv" in output or "SSLv" in output:
            return {
                "target": target,
                "status": "SECURE",
                "details": "TLS 1.1 Disabled",
                "vuln_name": None
            }
        else:
            return {
                "target": target, 
                "status": "ERROR", 
                "details": "No SSL Service / Connection Failed", 
                "vuln_name": None
            }

    except Exception as e:
        return {
            "target": target, 
            "status": "ERROR", 
            "details": str(e), 
            "vuln_name": None
        }
