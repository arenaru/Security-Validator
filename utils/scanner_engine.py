import concurrent.futures
import subprocess
import os

# Import script worker (Logic Masak)
from script.certifExpired import run_ssl_scan
from script.hstsChecker import run_hsts_scan
from script.headerCheck import check_security_headers
from script.laravelCheck import run_laravel_scan
from script.nodeDebug import run_node_scan

# Helper function untuk Bash
def run_bash_worker(file_path):
    cmd = ["bash", "script/check_secure.sh", file_path]
    try:
        process = subprocess.run(cmd, capture_output=True, text=True)
        return process.stdout
    except:
        return None

def start_scanning_engine(targets_list, selected_scans, temp_file_path):
    """
    Fungsi ini menerima Input User, menjalankan Scanning Paralel,
    dan mengembalikan Dictionary berisi hasil scan.
    """
    
    # Penampung Hasil (Dictionary biar rapi)
    results = {
        "ssl": None,
        "hsts": None,
        "header": None,
        "cookie": None,
        "laravel": None,
        "node": None
    }

    # JALANIN ENGINE (The Kitchen)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}
        
        # Cek berdasarkan String yang dikirim dari App.py
        if "SSL Certificate Check" in selected_scans:
            futures["ssl"] = executor.submit(run_ssl_scan, temp_file_path)
        
        if "HSTS Security Check" in selected_scans:
            futures["hsts"] = executor.submit(run_hsts_scan, targets_list)
            
        if "Security Headers Check" in selected_scans:
            futures["header"] = executor.submit(check_security_headers, targets_list)
        
        if "Cookie Secure Flag (Bash)" in selected_scans:
            futures["cookie"] = executor.submit(run_bash_worker, temp_file_path)
        
        if "Laravel Debug Mode" in selected_scans:
            futures["laravel"] = executor.submit(run_laravel_scan, targets_list)
            
        if "Node.js Debug Mode" in selected_scans:
            futures["node"] = executor.submit(run_node_scan, targets_list)

        # AMBIL HASIL MASAKAN
        for key, future in futures.items():
            results[key] = future.result()
            
    return results