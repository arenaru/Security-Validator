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

# Browser-like headers. A bare User-Agent is enough of an outlier that some WAFs
# answer 403 to it, which would be reported as the target's real response code.
HEADERS = {
    "User-Agent": USER_AGENT,
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}


def _get_with_retry(candidate, headers):
    """
    GET a candidate, retrying only on timeout (transient). Connection and TLS
    errors are deterministic for a given host/port, so retrying them just
    doubles scan time.

    Redirects are followed so the reported code matches what a browser, curl -L,
    or any other response-code tool reports. Stopping at the first hop would
    report 308 for a host that actually answers 200, and would hide a redirect
    to a 403 login/WAF page behind a harmless 302.
    """
    last_timeout = None
    for attempt in range(TIMEOUT_RETRIES + 1):
        try:
            return requests.get(
                candidate,
                headers=headers,
                timeout=TIMEOUT,
                verify=False,
                allow_redirects=True,
            )
        except requests.exceptions.Timeout as exc:
            last_timeout = exc
            if attempt < TIMEOUT_RETRIES:
                time.sleep(RETRY_BACKOFF_SECONDS)
    raise last_timeout


def check_response_code(target):
    """
    Report the HTTP response code for a target. This is reconnaissance, not a
    vulnerability check: it carries no status/severity, because an answered
    request is a fact about the host, not a finding. A 401 on an auth-gated API
    and a 404 on an unused path are both normal.

    "Status Code" is the first hop, "Final Code" is where the request landed.
    They differ only when the target redirects.
    """
    candidates = build_target_candidates(target)
    headers = dict(HEADERS)
    candidate_errors = []

    for candidate in candidates:
        try:
            response = _get_with_retry(candidate, headers)

            first_code = response.history[0].status_code if response.history else response.status_code
            final_code = response.status_code
            reason = response.reason or ""

            if response.history:
                message = f"HTTP {first_code} -> {final_code} {reason}".strip()
            else:
                message = f"HTTP {final_code} {reason}".strip()

            result = {
                "URL": candidate,
                "Status Code": first_code,
                "Final Code": final_code,
                "Final URL": response.url,
                "Reason": reason,
                "Redirects": len(response.history),
                "Message": message,
            }

            if candidate_errors:
                failed = candidate_errors[-1]
                result["Message"] = (
                    f"{message} (measured over {candidate}: "
                    f"{failed['url']} unreachable — {failed['message']})"
                )

            return result

        # SSLError must precede ConnectionError: it is a subclass of it.
        # Port 443 answered, so HTTPS exists but its TLS layer is broken. There
        # is no response code to report, and downgrading to HTTP would report a
        # different service's code as this target's.
        except requests.exceptions.SSLError as e:
            return {
                "URL": candidate,
                "Status Code": "N/A",
                "Final Code": "N/A",
                "Final URL": candidate,
                "Reason": "TLS_ERROR",
                "Redirects": 0,
                "Message": f"TLS handshake failed: {str(e)[:150]}",
            }
        except requests.exceptions.TooManyRedirects as e:
            return {
                "URL": candidate,
                "Status Code": "N/A",
                "Final Code": "N/A",
                "Final URL": candidate,
                "Reason": "REDIRECT_LOOP",
                "Redirects": 0,
                "Message": f"Redirect loop: {str(e)[:120]}",
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
            "Final Code": "N/A",
            "Final URL": last_error["url"],
            "Reason": last_error["error_type"],
            "Redirects": 0,
            "Message": last_error["message"],
        }

    return {
        "URL": str(target).strip(),
        "Status Code": "N/A",
        "Final Code": "N/A",
        "Final URL": str(target).strip(),
        "Reason": "UNKNOWN",
        "Redirects": 0,
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
