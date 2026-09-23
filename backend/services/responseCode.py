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
    last_error = None

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

            return {
                "URL": candidate,
                "Status Code": status_code,
                "Reason": reason,
                "Category": _classify_status(status_code),
                "Message": f"HTTP {status_code} {reason}".strip(),
            }

        except requests.exceptions.Timeout:
            last_error = (candidate, "TIMEOUT", "Connection Timeout")
            continue
        except requests.exceptions.ConnectionError:
            last_error = (candidate, "CONNECTION_ERROR", "Connection Refused")
            continue
        except Exception as e:
            last_error = (candidate, "ERROR", f"Error: {str(e)[:100]}")
            continue

    if last_error:
        return {
            "URL": last_error[0],
            "Status Code": "N/A",
            "Reason": last_error[1],
            "Category": "ERROR",
            "Message": last_error[2],
        }

    return {
        "URL": target.strip(),
        "Status Code": "N/A",
        "Reason": "UNKNOWN",
        "Category": "ERROR",
        "Message": "Unknown Error",
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
