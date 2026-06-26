import concurrent.futures

# Import service modules
from backend.services.certifExpired import run_ssl_scan
from backend.services.hstsChecker import run_hsts_scan
from backend.services.headerCheck import check_security_headers
from backend.services.laravelCheck import run_laravel_scan
from backend.services.nodeDebug import run_node_scan
from backend.services.sslv3 import check_sslv3
from backend.services.tlsv10 import check_tls10
from backend.services.tlsv11 import check_tls11
from backend.services.phpVersion import run_php_scan
from backend.services.cookieSecure import run_cookie_scan
from backend.services.cookieHttpOnly import run_cookie_httponly_scan
from backend.services.sslHostnameMismatch import run_ssl_hostname_mismatch_scan
from backend.services.responseCode import run_response_code_scan


def iter_scanning_engine_results(targets_list, selected_scans, temp_file_path):
    """
    Jalankan module scan paralel lalu yield hasil per module saat module tersebut selesai.
    Yield format: (scan_type, payload, error)
    """

    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_to_scan_type = {}

        if "SSL Certificate Check" in selected_scans:
            future_to_scan_type[executor.submit(run_ssl_scan, temp_file_path)] = "SSL Certificate Check"

        if "SSL Certificate Hostname Mismatch" in selected_scans:
            future_to_scan_type[
                executor.submit(run_ssl_hostname_mismatch_scan, temp_file_path)
            ] = "SSL Certificate Hostname Mismatch"

        if "SSLv3 Detection" in selected_scans:
            future_to_scan_type[
                executor.submit(lambda: [check_sslv3(target) for target in targets_list])
            ] = "SSLv3 Detection"

        if "TLS 1.0 Detection" in selected_scans:
            future_to_scan_type[
                executor.submit(lambda: [check_tls10(target) for target in targets_list])
            ] = "TLS 1.0 Detection"

        if "TLS 1.1 Detection" in selected_scans:
            future_to_scan_type[
                executor.submit(lambda: [check_tls11(target) for target in targets_list])
            ] = "TLS 1.1 Detection"

        if "HSTS Security Check" in selected_scans:
            future_to_scan_type[executor.submit(run_hsts_scan, targets_list)] = "HSTS Security Check"

        if "Security Headers Check" in selected_scans:
            future_to_scan_type[
                executor.submit(check_security_headers, targets_list)
            ] = "Security Headers Check"

        if "Cookie Secure Flag" in selected_scans:
            future_to_scan_type[executor.submit(run_cookie_scan, targets_list)] = "Cookie Secure Flag"

        if "Cookie HttpOnly Flag" in selected_scans:
            future_to_scan_type[
                executor.submit(run_cookie_httponly_scan, targets_list)
            ] = "Cookie HttpOnly Flag"

        if "Response Code Check" in selected_scans:
            future_to_scan_type[
                executor.submit(run_response_code_scan, targets_list)
            ] = "Response Code Check"

        if "Laravel Debug Mode" in selected_scans:
            future_to_scan_type[executor.submit(run_laravel_scan, targets_list)] = "Laravel Debug Mode"

        if "Node.js Debug Mode" in selected_scans:
            future_to_scan_type[executor.submit(run_node_scan, targets_list)] = "Node.js Debug Mode"

        if "PHP Version Disclosure" in selected_scans:
            future_to_scan_type[executor.submit(run_php_scan, targets_list)] = "PHP Version Disclosure"

        for future in concurrent.futures.as_completed(future_to_scan_type):
            scan_type = future_to_scan_type[future]
            try:
                yield scan_type, future.result(), None
            except Exception as exc:
                yield scan_type, None, exc


def start_scanning_engine(targets_list, selected_scans, temp_file_path):
    """
    Menjalankan scanning paralel dan mengembalikan dictionary berdasarkan Scan Type.
    Format Return: { "SSL Certificate Check": [...data...], "HSTS...": ... }
    """

    scan_results = {}

    for scan_type, payload, err in iter_scanning_engine_results(
        targets_list,
        selected_scans,
        temp_file_path,
    ):
        if err is not None:
            scan_results[scan_type] = None
            print(f"[Error] {scan_type} failed: {err}")
            import traceback
            traceback.print_exc()
            continue
        scan_results[scan_type] = payload

    return scan_results
