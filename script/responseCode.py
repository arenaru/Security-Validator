import requests
import urllib3
from urllib.parse import urlparse

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

TIMEOUT = 10
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/115.0.0.0 Safari/537.36"


def build_target_candidates(target):
    """
    Return request candidates in priority order: HTTPS first, then HTTP.
    """
    target = target.strip().rstrip('/')
    if target.startswith(('http://', 'https://')):
        parsed = urlparse(target)
        host = parsed.netloc or parsed.path
        path = parsed.path if parsed.netloc else ""
        if parsed.query:
            path = f"{path}?{parsed.query}"
        candidates = [f"https://{host}{path}", f"http://{host}{path}"]
        return list(dict.fromkeys(candidates))
    return [f"https://{target}", f"http://{target}"]


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


def run_response_code_scan(targets_list):
    """
    Run HTTP response code scan for multiple targets.
    Returns: list of results.
    """
    results = []
    for target in targets_list:
        if target.strip():
            results.append(check_response_code(target))
    return results
