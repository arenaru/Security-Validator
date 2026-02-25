import concurrent.futures
import subprocess
import os

# Import script worker
from script.certifExpired import run_ssl_scan
from script.hstsChecker import run_hsts_scan
from script.headerCheck import check_security_headers
from script.laravelCheck import run_laravel_scan
from script.nodeDebug import run_node_scan
from script.sslv3 import check_sslv3
from script.tlsv10 import check_tls10
from script.tlsv11 import check_tls11
from script.phpVersion import run_php_scan
from script.cookieSecure import run_cookie_scan

def start_scanning_engine(targets_list, selected_scans, temp_file_path):
    """
    Menjalankan scanning paralel dan mengembalikan dictionary berdasarkan Scan Type.
    Format Return: { "SSL Certificate Check": [...data...], "HSTS...": ... }
    """
    
    scan_results = {}
    
    # JALANIN ENGINE (The Kitchen)
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = {}
        
        if "SSL Certificate Check" in selected_scans:
            futures["SSL Certificate Check"] = executor.submit(run_ssl_scan, temp_file_path)
        
        if "SSLv3 Detection" in selected_scans:
            futures["SSLv3 Detection"] = executor.submit(lambda: [check_sslv3(target) for target in targets_list])
        
        if "TLS 1.0 Detection" in selected_scans:
            futures["TLS 1.0 Detection"] = executor.submit(lambda: [check_tls10(target) for target in targets_list])
        
        if "TLS 1.1 Detection" in selected_scans:
            futures["TLS 1.1 Detection"] = executor.submit(lambda: [check_tls11(target) for target in targets_list])
        
        if "HSTS Security Check" in selected_scans:
            futures["HSTS Security Check"] = executor.submit(run_hsts_scan, targets_list)
            
        if "Security Headers Check" in selected_scans:
            futures["Security Headers Check"] = executor.submit(check_security_headers, targets_list)
        
        if "Cookie Secure Flag" in selected_scans:
            futures["Cookie Secure Flag"] = executor.submit(run_cookie_scan, targets_list)
        
        if "Laravel Debug Mode" in selected_scans:
            futures["Laravel Debug Mode"] = executor.submit(run_laravel_scan, targets_list)
            
        if "Node.js Debug Mode" in selected_scans:
            futures["Node.js Debug Mode"] = executor.submit(run_node_scan, targets_list)
        
        if "PHP Version Disclosure" in selected_scans:
            futures["PHP Version Disclosure"] = executor.submit(run_php_scan, targets_list)

        # AMBIL HASIL
        for scan_type, future in futures.items():
            try:
                scan_results[scan_type] = future.result()
            except Exception as e:
                scan_results[scan_type] = None
                print(f"[Error] {scan_type} failed: {e}")
            
    return scan_results