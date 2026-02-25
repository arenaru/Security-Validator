import requests
import urllib3
from urllib.parse import urlparse

# Suppress SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def parse_set_cookie_header(response_obj, cookies_dict):
    """
    Parse all Set-Cookie headers to extract cookie names and security attributes
    """
    try:
        # Try to get all Set-Cookie headers (there can be multiple)
        if hasattr(response_obj, 'raw') and hasattr(response_obj.raw, '_original_response'):
            # Get original headers which preserve multiple Set-Cookie headers
            headers = response_obj.raw._original_response.msg.items()
            
            for header_name, header_value in headers:
                if header_name.lower() == 'set-cookie':
                    parse_single_cookie(header_value, cookies_dict)
    except:
        # Fallback: use regular headers (may miss some cookies if multiple Set-Cookie headers)
        set_cookie = response_obj.headers.get('Set-Cookie', '')
        if set_cookie:
            parse_single_cookie(set_cookie, cookies_dict)

def parse_single_cookie(cookie_str, cookies_dict):
    """
    Parse a single Set-Cookie header value
    """
    parts = cookie_str.split(';')
    if not parts:
        return
    
    # First part is name=value
    name_value = parts[0].strip()
    if '=' not in name_value:
        return
    
    cookie_name = name_value.split('=', 1)[0].strip()
    
    # Check for Secure and HttpOnly flags
    secure_flag = False
    httponly_flag = False
    
    for part in parts[1:]:
        part = part.strip().lower()
        if part == 'secure':
            secure_flag = True
        elif part == 'httponly':
            httponly_flag = True
    
    # Store in dict
    if cookie_name:
        cookies_dict[cookie_name] = {
            'secure': secure_flag,
            'httponly': httponly_flag
        }

def check_cookie_security(target):
    """
    Check if cookies are marked with Secure flag
    Returns: dict with url, status, message
    """
    # Clean and normalize target
    target = target.strip()
    
    # Add https:// if no scheme
    if not target.startswith(('http://', 'https://')):
        target = f"https://{target}"
    
    # Remove trailing slash
    target = target.rstrip('/')
    
    try:
        # Create session to capture all cookies across redirects
        session = requests.Session()
        
        # Make request with timeout
        response = session.get(
            target,
            timeout=(3, 5),  # connect timeout 3s, read timeout 5s
            verify=False,
            allow_redirects=True,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        
        # Parse Set-Cookie headers from response and all redirects
        all_cookies = {}
        
        # Check history (redirects)
        for hist_response in response.history:
            parse_set_cookie_header(hist_response, all_cookies)
        
        # Check final response
        parse_set_cookie_header(response, all_cookies)
        
        # Also get cookies from session jar (as fallback and to update attributes)
        for cookie in session.cookies:
            cookie_name = cookie.name
            # Update or add cookie info from session jar
            all_cookies[cookie_name] = {
                'secure': cookie.secure,
                'httponly': hasattr(cookie, 'has_nonstandard_attr') and cookie.has_nonstandard_attr('HttpOnly')
            }
        
        if not all_cookies:
            return {
                "url": target,
                "status": "INFO",
                "message": "No Cookies Found"
            }
        
        # Check if all cookies have Secure flag
        insecure_cookies = []
        secure_cookies = []
        
        for cookie_name, cookie_attrs in all_cookies.items():
            if cookie_attrs.get('secure', False):
                secure_cookies.append(cookie_name)
            else:
                insecure_cookies.append(cookie_name)
        
        if insecure_cookies:
            cookie_names = ", ".join(insecure_cookies)
            return {
                "url": target,
                "status": "VULNERABLE",
                "message": f"Insecure Cookies: {cookie_names}"
            }
        else:
            return {
                "url": target,
                "status": "SAFE",
                "message": "All Cookies are Secure"
            }
            
    except requests.exceptions.Timeout:
        return {
            "url": target,
            "status": "ERROR",
            "message": "Connection Timeout"
        }
    except requests.exceptions.ConnectionError:
        return {
            "url": target,
            "status": "ERROR",
            "message": "Connection Refused"
        }
    except Exception as e:
        return {
            "url": target,
            "status": "ERROR",
            "message": f"Error: {str(e)[:50]}"
        }

def run_cookie_scan(targets_list):
    """
    Run cookie security scan for multiple targets
    Returns: list of results
    """
    results = []
    for target in targets_list:
        if target.strip():
            result = check_cookie_security(target)
            results.append(result)
    return results
