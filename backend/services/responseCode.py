import concurrent.futures
import time

import requests
import urllib3

from backend.utils.target_resolver import build_target_candidates

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# (connect, read) so a slow connect cannot eat the whole read budget.
TIMEOUT = (5, 10)
TIMEOUT_RETRIES = 1
RETRY_BACKOFF_SECONDS = 1.0
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"

# Category -> ResultStatus string consumed by normalize_result_status().
# Reachable-and-answering is informational; only genuine faults are findings.
_CATEGORY_STATUS = {
    "SUCCESS": "INFO",
    "REDIRECT": "INFO",
    "CLIENT_ERROR": "WARNING",
    "SERVER_ERROR": "WARNING",
    "OTHER": "INFO",
    "TLS_ERROR": "WARNING",
    "ERROR": "ERROR",
}


def _classify_status(status_code):
    if 200 <= status_code < 300:
        return "SUCCESS"
    if 300 <= status_code < 400:
        return "REDIRECT"
    if 400 <= status_code < 500:
        return "CLIENT_ERROR"
    if 500 <= status_code < 600:
        return "SERVER_ERROR"
    return "OTHER"


def _status_for(category):
    return _CATEGORY_STATUS.get(category, "INFO")


def _get_with_retry(candidate, headers):
    """
    GET a candidate, retrying only on timeout (transient). Connection and TLS
    errors are deterministic for a given host/port, so retrying them just
    doubles scan time.
    """
    last_timeout = None
    for attempt in range(TIMEOUT_RETRIES + 1):
        try:
            return requests.get(
                candidate,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )
        except requests.exceptions.Timeout as exc:
            last_timeout = exc
            if attempt < TIMEOUT_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS)
    raise last_timeout


def check_response_code(target):
    candidates = build_target_candidates(target)
    headers = {'User-Agent': USER_AGENT}
    candidate_errors = []

    for candidate in candidates:
        try:
            response = _get_with_retry(candidate, headers)

            status_code = response.status_code
            reason = response.reason or ""
            message = f"HTTP {status_code} {reason}".strip()
            category = _classify_status(status_code)

            result = {
                "URL": candidate,
                "Status Code": status_code,
                "Reason": reason,
                "Category": category,
                "Message": message,
                "Fallback Used": False,
                "Status": _status_for(category),
            }

            if candidate_errors:
                failed = candidate_errors[-1]
                note = (
                    f"{failed['url']} unreachable ({failed['message']}) "
                    f"before falling back to {candidate}"
                )
                result["Fallback Used"] = True
                result["Fallback Note"] = note
                result["Message"] = f"{message} (fallback — {note})"

            return result

        # SSLError must precede ConnectionError: it is a subclass of it.
        # Port 443 answered, so HTTPS exists but its TLS layer is broken — that
        # is the finding. Downgrading to HTTP here would report the target as a
        # healthy 200 and silently drop a real TLS defect (false negative).
        except requests.exceptions.SSLError as e:
            return {
                "URL": candidate,
                "Status Code": "N/A",
                "Reason": "TLS_ERROR",
                "Category": "TLS_ERROR",
                "Message": f"TLS handshake failed: {str(e)[:150]}",
                "Fallback Used": False,
                "Status": _status_for("TLS_ERROR"),
            }
        except requests.exceptions.Timeout:
            candidate_errors.append({
                "url": candidate,
                "error_type": "TIMEOUT",
                "message": f"Connection timed out after {TIMEOUT_RETRIES + 1} attempt(s)",
            })
            continue
        except requests.exceptions.ConnectionError:
            candidate_errors.append({
                "url": candidate,
                "error_type": "CONNECTION_ERROR",
                "message": "Connection refused or host unreachable",
            })
            continue
        except Exception as e:
            candidate_errors.append({
                "url": candidate,
                "error_type": "ERROR",
                "message": f"Error: {str(e)[:100]}",
            })
            continue

    if candidate_errors:
        last_error = candidate_errors[-1]
        return {
            "URL": last_error["url"],
            "Status Code": "N/A",
            "Reason": last_error["error_type"],
            "Category": "ERROR",
            "Message": last_error["message"],
            "Fallback Used": False,
            "Status": _status_for("ERROR"),
        }

    return {
        "URL": target.strip(),
        "Status Code": "N/A",
        "Reason": "UNKNOWN",
        "Category": "ERROR",
        "Message": "Unknown Error",
        "Fallback Used": False,
        "Status": _status_for("ERROR"),
    }


def run_response_code_scan(targets_list, max_threads=20):
    """
    Run HTTP response code scan for multiple targets in parallel.
    Returns: list of results in original target order.
    """
    valid_targets = [target for target in targets_list if target.strip()]
    results = [None] * len(valid_targets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_response_code, target): index
            for index, target in enumerate(valid_targets)
        }
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()

    return results
