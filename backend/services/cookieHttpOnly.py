import requests
import urllib3
import concurrent.futures

from backend.utils.target_resolver import build_target_candidates

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# Cookies that are commonly designed to be readable by browser JS (e.g., CSRF token cookies).
EXCLUDED_COOKIE_NAMES = {
    'xsrf-token',
    'csrf-token',
    '_csrf',
    '__requestverificationtoken',
}

EXCLUDED_COOKIE_KEYWORDS = (
    'xsrf',
    'csrf',
)


def is_cookie_excluded(cookie_name):
    """
    Return True for cookie names intentionally excluded from HttpOnly checks.
    """
    if not cookie_name:
        return False

    name = cookie_name.strip().lower()
    if name in EXCLUDED_COOKIE_NAMES:
        return True

    return any(keyword in name for keyword in EXCLUDED_COOKIE_KEYWORDS)


def parse_set_cookie_header(response_obj, cookies_dict):
    """
    Parse all Set-Cookie headers to extract cookie names and security attributes.
    """
    try:
        # Preserve repeated Set-Cookie headers if available.
        if hasattr(response_obj, 'raw') and hasattr(response_obj.raw, '_original_response'):
            headers = response_obj.raw._original_response.msg.items()
            for header_name, header_value in headers:
                if header_name.lower() == 'set-cookie':
                    parse_single_cookie(header_value, cookies_dict)
    except Exception:
        # Fallback for cases where raw/original headers are unavailable.
        set_cookie = response_obj.headers.get('Set-Cookie', '')
        if set_cookie:
            parse_single_cookie(set_cookie, cookies_dict)


def parse_single_cookie(cookie_str, cookies_dict):
    """
    Parse a single Set-Cookie header value.
    """
    parts = cookie_str.split(';')
    if not parts:
        return

    name_value = parts[0].strip()
    if '=' not in name_value:
        return

    cookie_name = name_value.split('=', 1)[0].strip()
    httponly_flag = False

    for part in parts[1:]:
        part = part.strip().lower()
        if part == 'httponly':
            httponly_flag = True

    if cookie_name:
        # Preserve True if this cookie already appeared in another Set-Cookie header.
        previous_flag = cookies_dict.get(cookie_name, {}).get('httponly', False)
        cookies_dict[cookie_name] = {
            'httponly': bool(previous_flag or httponly_flag)
        }


def check_cookie_httponly(target):
    """
    Check whether cookies are marked with HttpOnly flag.
    Returns: dict with url, status, message.
    """
    candidates = build_target_candidates(target)
    last_error = None

    for candidate in candidates:
        try:
            session = requests.Session()
            response = session.get(
                candidate,
                timeout=(3, 5),
                verify=False,
                allow_redirects=True,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            all_cookies = {}

            for hist_response in response.history:
                parse_set_cookie_header(hist_response, all_cookies)

            parse_set_cookie_header(response, all_cookies)

            # Fill missing cookies from cookie jar (best effort for HttpOnly attribute).
            for cookie in session.cookies:
                cookie_name = cookie.name
                jar_httponly = hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr('HttpOnly')
                # Do not overwrite a positive header-based result with False from cookie jar.
                previous_flag = all_cookies.get(cookie_name, {}).get('httponly', False)
                all_cookies[cookie_name] = {
                    'httponly': bool(previous_flag or jar_httponly)
                }

            if not all_cookies:
                return {
                    "url": candidate,
                    "status": "INFO",
                    "message": "No Cookies Found"
                }

            missing_httponly = []
            excluded_cookies = []

            for cookie_name, cookie_attrs in all_cookies.items():
                if is_cookie_excluded(cookie_name):
                    excluded_cookies.append(cookie_name)
                    continue

                if cookie_attrs.get('httponly', False):
                    continue
                else:
                    missing_httponly.append(cookie_name)

            if missing_httponly:
                cookie_names = ", ".join(missing_httponly)
                excluded_note = ""
                if excluded_cookies:
                    excluded_note = f" (excluded: {', '.join(excluded_cookies)})"
                return {
                    "url": candidate,
                    "status": "VULNERABLE",
                    "message": f"Cookies without HttpOnly: {cookie_names}{excluded_note}"
                }

            if excluded_cookies:
                return {
                    "url": candidate,
                    "status": "SAFE",
                    "message": f"All applicable cookies are HttpOnly (excluded: {', '.join(excluded_cookies)})"
                }

            return {
                "url": candidate,
                "status": "SAFE",
                "message": "All Cookies are HttpOnly"
            }

        except requests.exceptions.Timeout:
            last_error = ("timeout", candidate)
            continue
        except requests.exceptions.ConnectionError:
            last_error = ("connection", candidate)
            continue
        except Exception as e:
            last_error = ("other", candidate, str(e))
            continue

    if last_error and last_error[0] == "timeout":
        return {
            "url": last_error[1],
            "status": "ERROR",
            "message": "Connection Timeout"
        }
    if last_error and last_error[0] == "connection":
        return {
            "url": last_error[1],
            "status": "ERROR",
            "message": "Connection Refused"
        }
    if last_error and last_error[0] == "other":
        return {
            "url": last_error[1],
            "status": "ERROR",
            "message": f"Error: {last_error[2][:50]}"
        }

    return {
        "url": target.strip(),
        "status": "ERROR",
        "message": "Unknown Error"
    }


def run_cookie_httponly_scan(targets_list, max_threads=20):
    """
    Run HttpOnly cookie scan for multiple targets in parallel.
    Returns: list of results in original target order.
    """
    valid_targets = [target for target in targets_list if target.strip()]
    results = [None] * len(valid_targets)

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {
            executor.submit(check_cookie_httponly, target): index
            for index, target in enumerate(valid_targets)
        }
        for future in concurrent.futures.as_completed(futures):
            results[futures[future]] = future.result()

    return results
