import concurrent.futures

# Import service modules
from backend.services.certifExpired import run_ssl_scan
from backend.services.hstsChecker import run_hsts_scan
from backend.services.headerCheck import check_security_headers
from backend.services.ipCountry import run_ip_country_scan
from backend.services.laravelCheck import run_laravel_scan
from backend.services.nodeDebug import run_node_scan
from backend.services.tlsScanner import run_tls_scan
from backend.services.phpVersion import run_php_scan
from backend.services.cookieSecure import run_cookie_scan
from backend.services.cookieHttpOnly import run_cookie_httponly_scan
from backend.services.sslHostnameMismatch import run_ssl_hostname_mismatch_scan
from backend.services.responseCode import run_response_code_scan

_TLS_MODULE_NAMES = frozenset({"SSLv3 Detection", "TLS 1.0 Detection", "TLS 1.1 Detection"})
_TLS_COMBINED_KEY = "__TLS_COMBINED__"


def iter_scanning_engine_results(targets_list, selected_scans, timeout=None, parallelism=20):
    """
    Jalankan module scan paralel lalu yield hasil per module saat module tersebut selesai.
    Yield format: (scan_type, payload, error)

    If timeout (seconds) is set, modules still pending when the deadline is
    reached yield a TimeoutError and queued futures are cancelled. Threads
    already running a module cannot be force-killed and finish in the background.
    """

    executor = concurrent.futures.ThreadPoolExecutor()
    try:
        future_to_scan_type = {}

        if "SSL Certificate Check" in selected_scans:
            future_to_scan_type[executor.submit(run_ssl_scan, targets_list, parallelism)] = "SSL Certificate Check"

        if "SSL Certificate Hostname Mismatch" in selected_scans:
            future_to_scan_type[
                executor.submit(run_ssl_hostname_mismatch_scan, targets_list, parallelism)
            ] = "SSL Certificate Hostname Mismatch"

        tls_modules_requested = [m for m in ("SSLv3 Detection", "TLS 1.0 Detection", "TLS 1.1 Detection") if m in selected_scans]
        if tls_modules_requested:
            future_to_scan_type[
                executor.submit(run_tls_scan, targets_list, parallelism)
            ] = _TLS_COMBINED_KEY

        if "HSTS Security Check" in selected_scans:
            future_to_scan_type[executor.submit(run_hsts_scan, targets_list, parallelism)] = "HSTS Security Check"

        if "Security Headers Check" in selected_scans:
            future_to_scan_type[
                executor.submit(check_security_headers, targets_list, parallelism)
            ] = "Security Headers Check"

        if "Cookie Secure Flag" in selected_scans:
            future_to_scan_type[executor.submit(run_cookie_scan, targets_list, parallelism)] = "Cookie Secure Flag"

        if "Cookie HttpOnly Flag" in selected_scans:
            future_to_scan_type[
                executor.submit(run_cookie_httponly_scan, targets_list, parallelism)
            ] = "Cookie HttpOnly Flag"

        if "Response Code Check" in selected_scans:
            future_to_scan_type[
                executor.submit(run_response_code_scan, targets_list, parallelism)
            ] = "Response Code Check"

        if "Laravel Debug Mode" in selected_scans:
            future_to_scan_type[executor.submit(run_laravel_scan, targets_list, parallelism)] = "Laravel Debug Mode"

        if "Node.js Debug Mode" in selected_scans:
            future_to_scan_type[executor.submit(run_node_scan, targets_list, parallelism)] = "Node.js Debug Mode"

        if "PHP Version Disclosure" in selected_scans:
            future_to_scan_type[executor.submit(run_php_scan, targets_list, parallelism)] = "PHP Version Disclosure"

        if "IP Country Lookup" in selected_scans:
            future_to_scan_type[executor.submit(run_ip_country_scan, targets_list, parallelism)] = "IP Country Lookup"

        try:
            for future in concurrent.futures.as_completed(future_to_scan_type, timeout=timeout):
                scan_type = future_to_scan_type[future]
                try:
                    result = future.result()
                    if scan_type == _TLS_COMBINED_KEY:
                        for module_name, payload in result.items():
                            if module_name in tls_modules_requested:
                                yield module_name, payload, None
                    else:
                        yield scan_type, result, None
                except Exception as exc:
                    if scan_type == _TLS_COMBINED_KEY:
                        for module_name in tls_modules_requested:
                            yield module_name, None, exc
                    else:
                        yield scan_type, None, exc
        except concurrent.futures.TimeoutError:
            for future, scan_type in future_to_scan_type.items():
                modules = tls_modules_requested if scan_type == _TLS_COMBINED_KEY else [scan_type]
                if future.cancelled():
                    for m in modules:
                        yield m, None, TimeoutError("module cancelled after job timeout")
                elif future.done():
                    try:
                        result = future.result()
                        if scan_type == _TLS_COMBINED_KEY:
                            for module_name, payload in result.items():
                                if module_name in modules:
                                    yield module_name, payload, None
                        else:
                            yield scan_type, result, None
                    except Exception as exc:
                        for m in modules:
                            yield m, None, exc
                else:
                    for m in modules:
                        yield m, None, TimeoutError(f"job timeout of {timeout}s exceeded")
    finally:
        executor.shutdown(wait=False, cancel_futures=True)
