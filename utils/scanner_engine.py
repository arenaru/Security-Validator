import concurrent.futures

# Import all Acunetix-mode workers from a single consolidated module
from script.acunetix_all import (
    run_ssl_scan,
    run_hsts_scan,
    check_security_headers,
    run_cookie_scan,
    run_laravel_scan,
    run_node_scan,
    check_sslv3,
    check_tls10,
    check_tls11,
    run_php_scan,
)

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
        
        if "Cookie Secure Flag (Bash)" in selected_scans:
            futures["Cookie Secure Flag (Bash)"] = executor.submit(run_cookie_scan, targets_list)
        
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