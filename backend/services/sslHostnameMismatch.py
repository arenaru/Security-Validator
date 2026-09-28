import socket
import ssl
import concurrent.futures
from urllib.parse import urlparse


VULN_NAME_HOSTNAME_MISMATCH = "SSL Certificate Name Hostname Mismatch"


def sanitize(domain):
    domain = domain.strip()
    if domain.startswith("http://") or domain.startswith("https://"):
        domain = urlparse(domain).netloc

    # Remove path and optional port if present in input file.
    domain = domain.split("/")[0]
    if ":" in domain:
        domain = domain.split(":")[0]

    return domain


def check_ssl_hostname_mismatch(domain, port=443):
    context = ssl.create_default_context()
    result = {
        "URL": f"https://{domain}",
        "Status": "Error",
        "Detail": "-",
        "vuln_name": None,
    }

    try:
        with socket.create_connection((domain, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain):
                result["Status"] = "VALID"
                result["Detail"] = "Hostname matches certificate"
                result["vuln_name"] = None

    except ssl.CertificateError:
        result["Status"] = "WARNING"
        result["Detail"] = "Hostname Mismatch"
        result["vuln_name"] = VULN_NAME_HOSTNAME_MISMATCH

    except ssl.SSLCertVerificationError as e:
        # Different Python/OpenSSL versions may format mismatch text differently.
        err = str(e).lower()
        if "hostname" in err and ("mismatch" in err or "match" in err):
            result["Status"] = "WARNING"
            result["Detail"] = "Hostname Mismatch"
            result["vuln_name"] = VULN_NAME_HOSTNAME_MISMATCH
        else:
            result["Status"] = "WARNING"
            result["Detail"] = f"Certificate verification failed: {str(e)}"
            result["vuln_name"] = None

    except ssl.SSLError as e:
        result["Status"] = "WARNING"
        result["Detail"] = f"SSL error: {str(e)}"
        result["vuln_name"] = None

    except socket.timeout:
        result["Status"] = "Error"
        result["Detail"] = "Connection Timeout (Web Down)"
        result["vuln_name"] = None

    except socket.gaierror:
        result["Status"] = "Error"
        result["Detail"] = "DNS Error (Domain not found)"
        result["vuln_name"] = None

    except Exception as e:
        result["Status"] = "Error"
        result["Detail"] = str(e)
        result["vuln_name"] = None

    return result


def run_ssl_hostname_mismatch_scan(targets: list[str], max_threads: int = 20) -> list[dict]:
    valid = [sanitize(t) for t in targets if t and t.strip()]
    results = [None] * len(valid)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_ssl_hostname_mismatch, domain): index
            for index, domain in enumerate(valid)
        }
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()

    return [r for r in results if r is not None]
