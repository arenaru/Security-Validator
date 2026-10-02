import requests
import urllib3
import concurrent.futures

from backend.utils.target_resolver import build_target_candidates

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"


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


def check_response_code(target):
    candidates = build_target_candidates(target)
    headers = {'User-Agent': USER_AGENT}
    candidate_errors = []

    for candidate in candidates:
        try:
            response = requests.get(
                candidate,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=False,
            )

            status_code = response.status_code
            reason = response.reason or ""
            message = f"HTTP {status_code} {reason}".strip()

            result = {
                "URL": candidate,
                "Status Code": status_code,
                "Reason": reason,
                "Category": _classify_status(status_code),
                "Message": message,
                "Fallback Used": False,
                # Forced to WARNING (not SECURE/INFO) so this result survives the
                # true-positive filter in scan_service._normalize_module_output and
                # always appears in the report — Response Code Check is informational
                # and every scanned target should be visible, not just vulnerabilities.
                "Status": "WARNING",
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

        except requests.exceptions.Timeout:
            candidate_errors.append({
                "url": candidate,
                "error_type": "TIMEOUT",
                "message": "Connection Timeout",
            })
            continue
        except requests.exceptions.ConnectionError:
            candidate_errors.append({
                "url": candidate,
                "error_type": "CONNECTION_ERROR",
                "message": "Connection Refused",
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
            "Status": "WARNING",
        }

    return {
        "URL": target.strip(),
        "Status Code": "N/A",
        "Reason": "UNKNOWN",
        "Category": "ERROR",
        "Message": "Unknown Error",
        "Fallback Used": False,
        "Status": "WARNING",
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
