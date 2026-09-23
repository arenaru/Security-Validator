import subprocess
import shutil

from backend.utils.target_resolver import UnsafeTargetError, extract_nmap_host

def check_sslv3(target):
    if not shutil.which("nmap"):
        return {"target": target, "status": "ERROR", "details": "Nmap not installed"}

    try:
        domain_only = extract_nmap_host(target)
    except UnsafeTargetError as exc:
        return {"target": target, "status": "ERROR", "details": str(exc)}

    try:
        # Scan khusus cipher enum
        cmd = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", "-Pn", domain_only]
        process = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = process.stdout
        
        if "SSLv3" in output:
            return {
                "target": target,
                "status": "INSECURE",
                "details": "SSLv3 Detected (Deprecated)",
                "vuln_name": "Insecure Transportation Security Protocol Supported (SSLv3)"
            }
        elif "TLSv" in output: # Koneksi SSL berhasil, tapi bukan SSLv3
            return {
                "target": target,
                "status": "SECURE",
                "details": "SSLv3 Disabled"
            }
        else:
            return {"target": target, "status": "ERROR", "details": "No SSL Service"}

    except Exception as e:
        return {"target": target, "status": "ERROR", "details": str(e)}
