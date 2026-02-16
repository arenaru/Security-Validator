import json
import re
import socket
import ssl
import os
import uuid
from urllib.parse import urlparse, urljoin, urlencode, parse_qsl

import requests
import urllib3
from bs4 import BeautifulSoup


class BurpScanner:
    def __init__(
        self,
        burp_json_path=None,
        timeout=8,
        aggressive=True,
        crawl=True,
        max_pages=12,
        max_requests_per_detector=20,
        verify_tls=True,
    ):
        self.timeout = timeout
        self.aggressive = aggressive
        self.crawl = crawl
        self.max_pages = max_pages
        self.max_requests_per_detector = max_requests_per_detector
        self.verify_tls = verify_tls

        self._scan_context = None

        # Resolve JSON path relative to this module if not provided
        if not burp_json_path:
            base_dir = os.path.dirname(__file__)
            burp_json_path = os.path.join(base_dir, 'burp_vulnerabilities.json')

        with open(burp_json_path, encoding="utf-8") as f:
            self.vulns = json.load(f)

        # Registry: detector_key -> method
        self.detector_registry = {
            "xss_reflected": self._detect_xss_reflected,
            "xss_active": self._detect_xss_active,
            "csp": self._detect_csp,
            "hsts": self._detect_hsts,
            "cookie_flags": self._detect_cookie_flags,
            "http_methods": self._detect_http_methods,
            "directory_listing": self._detect_directory_listing,
            "robots": self._detect_robots_txt,
            "tls_cert": self._detect_tls_certificate,
            "ssti": self._detect_ssti,
            "code_injection": self._detect_code_injection_active,
            "sql_injection": self._detect_sql_injection,
            "open_redirect": self._detect_open_redirect_active,
            "path_traversal": self._detect_path_traversal_active,
            "cors": self._detect_cors,
            "security_headers": self._detect_security_headers,
            "clickjacking": self._detect_clickjacking,
            "server_banner": self._detect_server_banner_disclosure,
            "debug_errors": self._detect_debug_and_error_disclosure,
            "csrf": self._detect_csrf_heuristic,
            "sensitive_files": self._detect_sensitive_file_exposure,
            "cmd_injection": self._detect_os_command_injection_marker,
            "ldap_injection": self._detect_ldap_injection_heuristic,
            "xpath_injection": self._detect_xpath_injection_heuristic,
            "ssi_injection": self._detect_ssi_injection_heuristic,
            "mixed_content": self._detect_mixed_content,
            "client_side_js": self._detect_client_side_injection_patterns,
            "cross_domain_policy": self._detect_cross_domain_policy,
            "user_agent_variation": self._detect_user_agent_dependent_response,
            "sensitive_url_params": self._detect_sensitive_data_in_url,
            "password_get_form": self._detect_password_submitted_using_get,
        }

        # Name-based routing (substring match on Burp issue title)
        self.name_routes = [
            (("cross-site scripting", "xss"), "xss_active"),
            (("content security policy", "csp"), "csp"),
            (("strict transport security", "hsts"), "hsts"),
            (("cookie",), "cookie_flags"),
            (("http put method", "http trace method", "http delete method", "http patch", "http options"), "http_methods"),
            (("directory listing", "index of"), "directory_listing"),
            (("robots.txt", "robots"), "robots"),
            (("tls", "ssl", "certificate"), "tls_cert"),
            (("server-side template injection", "template injection"), "ssti"),
            (("code injection", "expression language injection"), "code_injection"),
            (("sql injection", "sql statement"), "sql_injection"),
            (("open redirection", "open redirect"), "open_redirect"),
            (("file path traversal", "path traversal", "directory traversal", "file path manipulation", "file path manipulation"), "path_traversal"),
            (("cors", "cross-origin resource sharing"), "cors"),
            (("clickjacking", "x-frame-options", "frameable response"), "clickjacking"),
            (("server header", "x-powered-by", "version disclosure", "information disclosure"), "server_banner"),
            (("debug", "stack trace", "verbose error", "error message"), "debug_errors"),
            (("csrf", "cross-site request forgery"), "csrf"),
            (("mixed content",), "mixed_content"),
            (("user agent-dependent response", "user-agent"), "user_agent_variation"),
            (("password submitted using get",), "password_get_form"),
            (("password returned in url query string", "password in url", "sensitive data in url"), "sensitive_url_params"),
            (("flash cross-domain policy", "silverlight cross-domain policy", "cross-domain policy"), "cross_domain_policy"),
            ((
                "dom-based",
                "client-side",
                "prototype pollution",
                "websocket url poisoning",
                "client-side template injection",
                "javascript injection",
                "client-side sql injection",
                "client-side xpath injection",
                "client-side json injection",
                "path-relative style sheet import",
                "local file path manipulation (dom-based)",
            ), "client_side_js"),
            (("content security policy:",), "csp"),
            (("os command injection", "command injection"), "cmd_injection"),
            (("ldap injection",), "ldap_injection"),
            (("xpath injection",), "xpath_injection"),
            (("ssi injection", "server-side includes"), "ssi_injection"),
            (("exposed", "backup", "sensitive file", "known file"), "sensitive_files"),
            (("missing", "security header", "insecure", "misconfiguration"), "security_headers"),
        ]

        # CWE-based routing (coverage for many Burp items without exact name match)
        self.cwe_routes = {
            "CWE-79": ["xss_active"],
            "CWE-89": ["sql_injection"],
            "CWE-22": ["path_traversal"],
            "CWE-23": ["path_traversal"],
            "CWE-35": ["path_traversal"],
            "CWE-36": ["path_traversal"],
            "CWE-77": ["cmd_injection"],
            "CWE-78": ["cmd_injection"],
            "CWE-90": ["ldap_injection"],
            "CWE-643": ["xpath_injection"],
            "CWE-96": ["ssi_injection"],
            "CWE-352": ["csrf"],
            "CWE-598": ["sensitive_url_params"],
            "CWE-200": ["server_banner", "debug_errors", "sensitive_files"],
            "CWE-204": ["debug_errors"],
            "CWE-16": ["security_headers", "server_banner"],
            "CWE-942": ["cross_domain_policy"],
        }

    def scan_target(self, target_url):
        results = []
        target = target_url.strip()
        if not target.startswith("http"):
            target = "http://" + target

        parsed = urlparse(target)
        base = f"{parsed.scheme}://{parsed.netloc}"

        session = requests.Session()
        session.headers.update({"User-Agent": "BurpLikeScanner/1.1"})

        # prefetch main response
        try:
            resp = session.get(target, timeout=self.timeout, allow_redirects=True, verify=self.verify_tls)
        except requests.exceptions.SSLError as e:
            # Fallback for environments without a working CA bundle
            try:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                session.verify = False
                resp = session.get(target, timeout=self.timeout, allow_redirects=True, verify=False)
            except Exception as e2:
                return [{"name": "connection", "status": "ERROR", "details": f"TLS verify failed; retry without verify also failed: {e2}"}]
        except Exception as e:
            return [{"name": "connection", "status": "ERROR", "details": str(e)}]

        self._scan_context = self._build_scan_context(session=session, base=base, target=target, resp=resp)
        detector_cache = {}

        def run_detector(detector_key: str):
            if detector_key in detector_cache:
                return detector_cache[detector_key]
            func = self.detector_registry.get(detector_key)
            if not func:
                detector_cache[detector_key] = {"status": "NOT_IMPLEMENTED", "details": f"Detector '{detector_key}' not registered"}
                return detector_cache[detector_key]
            try:
                detector_cache[detector_key] = func(session, base, target, resp)
            except Exception as e:
                detector_cache[detector_key] = {"status": "ERROR", "details": str(e)}
            return detector_cache[detector_key]

        # run detectors for each vulnerability entry (cached per detector to avoid hammering the target)
        for v in self.vulns:
            name = (v.get("name") or "").strip() or "(unnamed)"
            lname = name.lower()
            cwes = v.get("classifications") or []

            detector_keys = []
            # name routes
            for patterns, detector_key in self.name_routes:
                if any(p in lname for p in patterns):
                    detector_keys.append(detector_key)
            # cwe routes
            for cwe in cwes:
                for detector_key in self.cwe_routes.get(cwe, []):
                    detector_keys.append(detector_key)

            # always run basic header/misconfig checks for broad coverage
            if any(s in lname for s in ("header", "policy", "clickjacking", "cache", "security")):
                detector_keys.append("security_headers")

            # de-dup preserving order
            seen = set()
            detector_keys = [k for k in detector_keys if not (k in seen or seen.add(k))]

            if not detector_keys:
                results.append({
                    "name": name,
                    "severity": v.get("severity"),
                    "classifications": cwes,
                    "status": "NOT_IMPLEMENTED",
                    "details": "No detector mapped for this Burp issue (yet)",
                })
                continue

            # pick the strongest signal among mapped detectors
            detector_results = []
            for k in detector_keys:
                detector_results.append((k, run_detector(k)))

            best_key, best = self._pick_best_result(detector_results)
            out = {
                "name": name,
                "severity": v.get("severity"),
                "classifications": cwes,
                "detector": best_key,
            }
            out.update(best)
            results.append(out)

        return results

    def _pick_best_result(self, detector_results):
        """Choose the most actionable result from a list of (key, result)."""
        priority = {
            "ERROR": 90,
            "VULNERABLE": 80,
            "FOUND": 75,
            "RISKY": 70,
            "WEAK": 65,
            "MISSING": 60,
            "POTENTIAL": 55,
            "NOT_CONFIGURED": 40,
            "UNKNOWN": 35,
            "NOT_TESTED": 30,
            "NOT_VULNERABLE": 20,
            "NOT_FOUND": 15,
            "OK": 10,
            "NO_COOKIES": 8,
        }

        best_key = detector_results[0][0]
        best_res = detector_results[0][1]
        best_score = priority.get((best_res or {}).get("status"), 0)

        for key, res in detector_results[1:]:
            score = priority.get((res or {}).get("status"), 0)
            if score > best_score:
                best_key, best_res, best_score = key, res, score
        return best_key, best_res

    def _build_scan_context(self, session, base, target, resp):
        urls = [target]
        try:
            urls.append(base + "/")
        except Exception:
            pass

        if self.crawl and resp is not None and getattr(resp, "text", None):
            ctype = (resp.headers.get("Content-Type") or "").lower()
            if "html" in ctype or (resp.text.lstrip().startswith("<") and "<html" in resp.text.lower()[:500]):
                discovered = self._extract_same_origin_urls(base, target, resp.text)
                for u in discovered:
                    if u not in urls:
                        urls.append(u)

        # clamp
        urls = urls[: max(1, int(self.max_pages))]
        return {
            "base": base,
            "target": target,
            "urls": urls,
        }

    def _extract_same_origin_urls(self, base, page_url, html):
        out = []
        try:
            soup = BeautifulSoup(html, "html.parser")
            base_parsed = urlparse(base)
            base_host = base_parsed.netloc

            # links
            for a in soup.find_all("a", href=True):
                href = a.get("href")
                if not href:
                    continue
                u = urljoin(page_url, href)
                pu = urlparse(u)
                if pu.scheme in ("http", "https") and pu.netloc == base_host:
                    out.append(u)

            # forms
            for f in soup.find_all("form"):
                action = f.get("action") or page_url
                u = urljoin(page_url, action)
                pu = urlparse(u)
                if pu.scheme in ("http", "https") and pu.netloc == base_host:
                    out.append(u)
        except Exception:
            return []

        # de-dup
        seen = set()
        deduped = []
        for u in out:
            if u in seen:
                continue
            seen.add(u)
            deduped.append(u)
        return deduped

    # ---------- Detectors (passive / low-risk) ----------
    def _detect_xss_reflected(self, session, base, target, resp):
        # Simple reflected check: inject unique token in query param 'q'
        token = "burp_scan_xss_test_12345"
        parsed = urlparse(target)
        test_url = parsed._replace(query=f"q={token}").geturl()
        try:
            r = session.get(test_url, timeout=self.timeout)
            if token in r.text:
                return {"status": "POTENTIAL", "details": "Reflected input found in response", "evidence": token}
            else:
                return {"status": "NOT_FOUND", "details": "No reflected input detected"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_csp(self, session, base, target, resp):
        csp = resp.headers.get("Content-Security-Policy")
        if not csp:
            return {"status": "MISSING", "details": "No Content-Security-Policy header"}
        csp_l = csp.lower()

        findings = []
        if "unsafe-inline" in csp_l:
            findings.append("unsafe-inline")
        if "unsafe-eval" in csp_l:
            findings.append("unsafe-eval")
        if re.search(r"\bscript-src\b[^;]*\*", csp_l):
            findings.append("script-src allows *")
        if re.search(r"\bscript-src\b[^;]*\bhttp:\/\/", csp_l):
            findings.append("script-src allows http://")
        if re.search(r"\bscript-src\b[^;]*\bdata:", csp_l):
            findings.append("script-src allows data:")
        if "report-only" in csp_l:
            findings.append("CSP appears report-only")

        # Basic syntax sanity check (very light)
        if ":" in csp and " " not in csp.strip():
            # unlikely real CSP, but keep as weak signal
            findings.append("CSP syntax looks unusual")

        if findings:
            return {"status": "WEAK", "details": "CSP present but potentially weak: " + ", ".join(findings), "evidence": csp}
        return {"status": "OK", "details": "CSP present", "evidence": csp}

    def _detect_hsts(self, session, base, target, resp):
        sts = resp.headers.get("Strict-Transport-Security")
        if not sts:
            return {"status": "MISSING", "details": "HSTS header not present"}
        return {"status": "OK", "details": sts}

    def _detect_cookie_flags(self, session, base, target, resp):
        cookies = resp.headers.get("Set-Cookie")
        if not cookies:
            return {"status": "NO_COOKIES", "details": "No Set-Cookie header"}
        issues = []
        # multiple cookies may exist; check each for Secure and HttpOnly
        for part in cookies.split('\n'):
            if "httponly" not in part.lower():
                issues.append("Missing HttpOnly on cookie: %s" % part.split('=')[0])
            if "secure" not in part.lower():
                issues.append("Missing Secure on cookie: %s" % part.split('=')[0])
        if issues:
            return {"status": "WEAK", "details": "; ".join(issues), "evidence": cookies}
        return {"status": "OK", "details": "Cookies have Secure and HttpOnly flags"}

    def _detect_http_methods(self, session, base, target, resp):
        try:
            r = session.options(target, timeout=self.timeout)
            allow = r.headers.get("Allow") or r.headers.get("allow")
            if allow:
                forbidden = [m for m in ["PUT", "DELETE", "TRACE", "PATCH"] if m in allow]
                if forbidden:
                    return {"status": "RISKY", "details": "Allowed methods: " + allow}
                return {"status": "OK", "details": "Allowed methods: " + allow}
            return {"status": "UNKNOWN", "details": "No Allow header returned"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_directory_listing(self, session, base, target, resp):
        try:
            r = session.get(base + '/', timeout=self.timeout)
            if re.search(r"Index of /", r.text, re.IGNORECASE):
                return {"status": "FOUND", "details": "Directory listing appears enabled", "evidence": "Index of"}
            return {"status": "NOT_FOUND", "details": "No directory listing detected"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_robots_txt(self, session, base, target, resp):
        try:
            r = session.get(urljoin(base, '/robots.txt'), timeout=self.timeout)
            if r.status_code == 200 and r.text.strip():
                return {"status": "FOUND", "details": "robots.txt present", "evidence": r.text[:400]}
            return {"status": "NOT_FOUND", "details": "robots.txt not present"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_tls_certificate(self, session, base, target, resp):
        parsed = urlparse(base)
        host = parsed.hostname
        port = 443
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=host) as s:
                s.settimeout(self.timeout)
                s.connect((host, port))
                cert = s.getpeercert()
            # check expiry
            notAfter = cert.get('notAfter')
            notBefore = cert.get('notBefore')
            return {"status": "OK", "details": f"Valid cert from {notBefore} to {notAfter}", "evidence": cert}
        except Exception as e:
            return {"status": "ERROR", "details": f"TLS connection failed: {e}"}

    def _detect_ssti(self, session, base, target, resp):
        # Passive: look for typical template markers in responses
        markers = ['${', '{{', '{%']
        for m in markers:
            if m in resp.text:
                return {"status": "POTENTIAL", "details": "Template markers found in response", "evidence": m}
        return {"status": "NOT_FOUND", "details": "No template markers detected"}

    def _detect_open_redirect(self, session, base, target, resp):
        # Look for common redirect parameter names and test harmless redirect
        params = ['next', 'url', 'redirect', 'return']
        parsed = urlparse(target)
        for p in params:
            if p + '=' in parsed.query:
                return {"status": "POTENTIAL", "details": f"Found redirect param '{p}' in URL"}
        return {"status": "NOT_FOUND", "details": "No redirect params in URL"}

    def _detect_open_redirect_active(self, session, base, target, resp):
        # Actively test redirect params by setting to a harmless external URL
        params = ['next', 'url', 'redirect', 'return']
        parsed = urlparse(target)
        q = parsed.query
        if not q:
            return {"status": "NOT_TESTED", "details": "No query string to test"}
        # naive parse of query
        for seg in q.split('&'):
            if '=' not in seg:
                continue
            k, v = seg.split('=', 1)
            if k.lower() in params:
                test_url = parsed._replace(query=f"{k}=https://example.com/redirect-test").geturl()
                try:
                    r = session.get(test_url, timeout=self.timeout, allow_redirects=True)
                    # if final url contains example.com, redirect occurred
                    if 'example.com' in r.url:
                        return {"status": "VULNERABLE", "details": f"Parameter {k} allows open redirect", "evidence": r.url}
                    return {"status": "NOT_VULNERABLE", "details": f"Parameter {k} did not redirect externally"}
                except Exception as e:
                    return {"status": "ERROR", "details": str(e)}
        return {"status": "NOT_FOUND", "details": "No redirect params in URL"}

    def _detect_sql_injection(self, session, base, target, resp):
        # Active SQLi check using simple payloads on query param 'q' or first param
        parsed = urlparse(target)
        qs = parsed.query
        payloads = ["' OR '1'='1", '" OR "1"="1', "' OR '1'='1' -- "]
        if not qs:
            # try adding a query param
            for p in payloads:
                test = parsed._replace(query=f"q={p}").geturl()
                try:
                    r = session.get(test, timeout=self.timeout)
                    if self._looks_like_sqli(r.text):
                        return {"status": "POTENTIAL", "details": "SQLi payload triggered differences", "evidence": p}
                except Exception as e:
                    return {"status": "ERROR", "details": str(e)}
            return {"status": "NOT_FOUND", "details": "No query parameters to test; tried q parameter"}

        # choose first param to replace
        first = qs.split('&')[0]
        if '=' not in first:
            return {"status": "NOT_TESTED", "details": "Can't parse query params"}
        k, v = first.split('=', 1)
        # baseline
        try:
            base_resp = session.get(target, timeout=self.timeout)
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}
        base_len = len(base_resp.text or "")
        for p in payloads:
            test_q = '&'.join([f"{k}={p}"] + qs.split('&')[1:])
            test_url = parsed._replace(query=test_q).geturl()
            try:
                r = session.get(test_url, timeout=self.timeout)
                if self._looks_like_sqli(r.text) or abs(len(r.text or "") - base_len) > 200:
                    return {"status": "POTENTIAL", "details": "Response changed significantly for SQLi payload", "evidence": p}
            except Exception as e:
                return {"status": "ERROR", "details": str(e)}
        return {"status": "NOT_FOUND", "details": "No SQLi indications detected"}

    def _looks_like_sqli(self, text):
        if not text:
            return False
        errors = ['sql syntax error', 'mysql', 'syntax error', 'unclosed quotation mark', 'pg_query']
        lower = text.lower()
        return any(e in lower for e in errors)

    def _detect_xss_active(self, session, base, target, resp):
        parsed = urlparse(target)
        qs = parsed.query
        payload = '<script>window.__xss=12345</script>'
        if not qs:
            test = parsed._replace(query=f"q={payload}").geturl()
            try:
                r = session.get(test, timeout=self.timeout)
                if payload in r.text:
                    return {"status": "VULNERABLE", "details": "Reflected XSS payload found in response", "evidence": payload}
                return {"status": "NOT_FOUND", "details": "Payload not reflected"}
            except Exception as e:
                return {"status": "ERROR", "details": str(e)}
        # replace first param
        first = qs.split('&')[0]
        if '=' not in first:
            return {"status": "NOT_TESTED", "details": "Can't parse query params"}
        k, v = first.split('=', 1)
        test_q = '&'.join([f"{k}={payload}"] + qs.split('&')[1:])
        test_url = parsed._replace(query=test_q).geturl()
        try:
            r = session.get(test_url, timeout=self.timeout)
            if payload in r.text:
                return {"status": "VULNERABLE", "details": "Reflected XSS payload found in response", "evidence": payload}
            return {"status": "NOT_FOUND", "details": "Payload not reflected"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_path_traversal_active(self, session, base, target, resp):
        # Try common traversal patterns against the root path
        parsed = urlparse(target)
        paths = ["/../../../../../../etc/passwd", "/..%2f..%2f..%2f..%2fetc/passwd", "/../../../../windows/win.ini"]
        for p in paths:
            try:
                r = session.get(base + p, timeout=self.timeout)
                text = r.text or ""
                if 'root:' in text or '[extensions]' in text or 'Windows' in text:
                    return {"status": "POTENTIAL", "details": "Traversal may be possible", "evidence": p}
            except Exception:
                continue
        return {"status": "NOT_FOUND", "details": "No traversal evidence"}

    def _detect_code_injection_active(self, session, base, target, resp):
        """Attempt harmless expression-based payloads to detect server-side code evaluation.

        This only injects payloads that, if evaluated, would output a unique marker string or number.
        Do NOT use system/OS command payloads here.
        """
        parsed = urlparse(target)
        qs = parsed.query

        # Use a per-request arithmetic marker to avoid accidental matches (e.g. timestamps).
        # We also compare against a "control" request where the param value is benign.
        run_id = uuid.uuid4().hex[:8]
        a = (int(run_id[:4], 16) % 90) + 10
        b = (int(run_id[4:], 16) % 90) + 10
        marker = str(a * b + 1)
        control_value = f"CTL_{run_id}"

        # payload -> expected marker
        payloads = [
            (f"{{{{{a}*{b}+1}}}}", marker),
            (f"${{{a}*{b}+1}}", marker),
            (f"<%= {a}*{b}+1 %>", marker),
            (f"<?= {a}*{b}+1 ?>", marker),
        ]

        test_params = []
        if qs:
            # identify first parameter name
            first = qs.split('&')[0]
            if '=' in first:
                k = first.split('=', 1)[0]
                test_params.append(k)
        # common parameter names to try
        test_params += ['q', 'input', 'search', 'id', 'name']

        baseline_text = resp.text if (resp is not None and getattr(resp, 'text', None)) else ""

        for k in test_params:
            for payload, expected in payloads:
                try:
                    encoded = requests.utils.quote(payload, safe='')
                    test_q = f"{k}={encoded}"
                    # if there are other params, preserve them (replace first occurrence)
                    if qs and '=' in qs:
                        rest = '&'.join(qs.split('&')[1:])
                        full_q = test_q if not rest else test_q + '&' + rest
                    else:
                        full_q = test_q
                    test_url = parsed._replace(query=full_q).geturl()

                    # Build a control URL for the same param
                    encoded_ctl = requests.utils.quote(control_value, safe='')
                    ctl_q = f"{k}={encoded_ctl}"
                    if qs and '=' in qs:
                        rest_ctl = '&'.join(qs.split('&')[1:])
                        full_q_ctl = ctl_q if not rest_ctl else ctl_q + '&' + rest_ctl
                    else:
                        full_q_ctl = ctl_q
                    control_url = parsed._replace(query=full_q_ctl).geturl()

                    r = session.get(test_url, timeout=self.timeout, allow_redirects=True)
                    rc = session.get(control_url, timeout=self.timeout, allow_redirects=True)
                    if not r or not getattr(r, 'text', None):
                        continue
                    text_payload = r.text
                    text_control = rc.text if (rc is not None and getattr(rc, 'text', None)) else ""

                    # Strong signal: marker appears in payload response, but not in baseline and not in control.
                    if expected in text_payload and expected not in baseline_text and expected not in text_control:
                        idx = text_payload.find(expected)
                        snippet = text_payload[max(0, idx-60):idx+len(expected)+60]

                        # If the raw payload is reflected verbatim, this is weaker evidence (likely reflection).
                        if payload in text_payload:
                            return {
                                "status": "POTENTIAL",
                                "details": f"Marker appeared, but payload was also reflected for param '{k}' (possible reflection, not proven evaluation)",
                                "evidence": {
                                    "payload": payload,
                                    "marker": expected,
                                    "control_value": control_value,
                                    "response_snippet": snippet,
                                },
                            }

                        idx_ctl = text_control.find(expected)
                        ctl_snippet = "" if idx_ctl < 0 else text_control[max(0, idx_ctl-60):idx_ctl+len(expected)+60]
                        return {
                            "status": "VULNERABLE",
                            "details": f"Expression result '{expected}' only appears for the payload (not baseline/control) for param '{k}'",
                            "evidence": {
                                "payload": payload,
                                "marker": expected,
                                "control_value": control_value,
                                "response_snippet": snippet,
                                "control_snippet": ctl_snippet,
                            },
                        }
                except Exception as e:
                    return {"status": "ERROR", "details": str(e)}

        # Header-based injection check (User-Agent)
        # Some apps reflect or (mis)use header values; we treat this as a secondary signal.
        for payload, expected in payloads:
            try:
                headers_payload = {"User-Agent": payload}
                headers_control = {"User-Agent": control_value}
                r = session.get(target, timeout=self.timeout, allow_redirects=True, headers=headers_payload)
                rc = session.get(target, timeout=self.timeout, allow_redirects=True, headers=headers_control)
                if not r or not getattr(r, 'text', None):
                    continue

                text_payload = r.text
                text_control = rc.text if (rc is not None and getattr(rc, 'text', None)) else ""

                if expected in text_payload and expected not in baseline_text and expected not in text_control:
                    idx = text_payload.find(expected)
                    snippet = text_payload[max(0, idx-60):idx+len(expected)+60]
                    if payload in text_payload:
                        return {
                            "status": "POTENTIAL",
                            "details": "Marker appeared for User-Agent, but payload was also reflected (possible reflection, not proven evaluation)",
                            "evidence": {
                                "location": "header",
                                "header": "User-Agent",
                                "payload": payload,
                                "marker": expected,
                                "control_value": control_value,
                                "response_snippet": snippet,
                            },
                        }

                    idx_ctl = text_control.find(expected)
                    ctl_snippet = "" if idx_ctl < 0 else text_control[max(0, idx_ctl-60):idx_ctl+len(expected)+60]
                    return {
                        "status": "VULNERABLE",
                        "details": "Expression result appears only for User-Agent payload (not baseline/control)",
                        "evidence": {
                            "location": "header",
                            "header": "User-Agent",
                            "payload": payload,
                            "marker": expected,
                            "control_value": control_value,
                            "response_snippet": snippet,
                            "control_snippet": ctl_snippet,
                        },
                    }
            except Exception as e:
                return {"status": "ERROR", "details": str(e)}

        return {"status": "NOT_FOUND", "details": "No evidence of code-evaluation from tested payloads"}

    def _detect_cors(self, session, base, target, resp):
        acao = resp.headers.get('Access-Control-Allow-Origin')
        if not acao:
            return {"status": "NOT_CONFIGURED", "details": "No CORS headers"}
        if acao == '*':
            return {"status": "RISKY", "details": "CORS allows any origin (*)"}
        return {"status": "OK", "details": f"ACAO: {acao}"}

    # ---------- Additional detectors (broader Burp coverage) ----------
    def _detect_security_headers(self, session, base, target, resp):
        headers = resp.headers if resp is not None else {}
        missing = []
        weak = []

        # Common security headers
        if not headers.get("X-Content-Type-Options"):
            missing.append("X-Content-Type-Options")
        if not headers.get("X-Frame-Options") and not (headers.get("Content-Security-Policy") and "frame-ancestors" in headers.get("Content-Security-Policy", "")):
            missing.append("X-Frame-Options/frame-ancestors")
        if not headers.get("Referrer-Policy"):
            missing.append("Referrer-Policy")
        if not headers.get("Permissions-Policy"):
            missing.append("Permissions-Policy")

        # COOP/CORP/COEP are modern hardening; treat as "weak" if absent
        if not headers.get("Cross-Origin-Opener-Policy"):
            weak.append("Cross-Origin-Opener-Policy")
        if not headers.get("Cross-Origin-Resource-Policy"):
            weak.append("Cross-Origin-Resource-Policy")
        if not headers.get("Cross-Origin-Embedder-Policy"):
            weak.append("Cross-Origin-Embedder-Policy")

        if missing:
            return {"status": "MISSING", "details": "Missing security headers: " + ", ".join(missing), "evidence": {"missing": missing, "weak": weak}}
        if weak:
            return {"status": "WEAK", "details": "Hardening headers not set: " + ", ".join(weak), "evidence": {"weak": weak}}
        return {"status": "OK", "details": "Security headers look present"}

    def _detect_clickjacking(self, session, base, target, resp):
        headers = resp.headers if resp is not None else {}
        xfo = headers.get("X-Frame-Options")
        csp = headers.get("Content-Security-Policy", "")
        if xfo:
            return {"status": "OK", "details": f"X-Frame-Options present: {xfo}", "evidence": xfo}
        if "frame-ancestors" in csp:
            return {"status": "OK", "details": "CSP frame-ancestors present", "evidence": csp}
        return {"status": "RISKY", "details": "No X-Frame-Options or CSP frame-ancestors (potential clickjacking)"}

    def _detect_server_banner_disclosure(self, session, base, target, resp):
        headers = resp.headers if resp is not None else {}
        disclosed = {}
        for h in ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "Via"]:
            if headers.get(h):
                disclosed[h] = headers.get(h)
        if disclosed:
            return {"status": "FOUND", "details": "Version/banner disclosure in response headers", "evidence": disclosed}
        return {"status": "NOT_FOUND", "details": "No obvious version/banner disclosure headers"}

    def _detect_debug_and_error_disclosure(self, session, base, target, resp):
        text = (resp.text or "") if resp is not None else ""
        if not text:
            return {"status": "NOT_TESTED", "details": "No response body to inspect"}

        patterns = [
            r"Whoops! There was an error",
            r"Symfony\\\\Component\\\\Debug",
            r"Illuminate\\\\\\w+Exception",
            r"Stack trace:",
            r"Traceback \(most recent call last\):",
            r"System\.Web\.HttpException",
            r"Microsoft OLE DB Provider",
            r"You have an error in your SQL syntax",
        ]
        for pat in patterns:
            if re.search(pat, text, re.IGNORECASE):
                return {"status": "FOUND", "details": "Verbose error/debug content detected", "evidence": pat}
        return {"status": "NOT_FOUND", "details": "No obvious verbose error/debug markers"}

    def _detect_csrf_heuristic(self, session, base, target, resp):
        text = (resp.text or "") if resp is not None else ""
        ctype = (resp.headers.get("Content-Type") or "").lower() if resp is not None else ""
        if "html" not in ctype and "<form" not in text.lower():
            return {"status": "NOT_TESTED", "details": "No HTML forms detected on the landing page"}
        try:
            soup = BeautifulSoup(text, "html.parser")
            forms = soup.find_all("form")
            if not forms:
                return {"status": "NOT_TESTED", "details": "No forms found"}
            missing = 0
            total = 0
            for f in forms:
                total += 1
                hidden = f.find_all("input", {"type": "hidden"})
                has_token = False
                for i in hidden:
                    n = (i.get("name") or "").lower()
                    if n in ("csrf", "csrf_token", "_csrf", "_token", "authenticity_token", "__requestverificationtoken"):
                        has_token = True
                        break
                if not has_token:
                    missing += 1
            if missing == 0:
                return {"status": "OK", "details": f"CSRF tokens appear present in {total} form(s)"}
            return {"status": "POTENTIAL", "details": f"{missing}/{total} form(s) lack an obvious CSRF token field"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_sensitive_file_exposure(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}

        candidates = [
            "/.env",
            "/.git/config",
            "/phpinfo.php",
            "/server-status",
            "/debug",
            "/actuator/env",
            "/actuator/health",
            "/web.config",
            "/crossdomain.xml",
        ]
        evidence = []
        base_url = base.rstrip("/")
        checked = 0
        for path in candidates:
            if checked >= self.max_requests_per_detector:
                break
            checked += 1
            url = base_url + path
            try:
                r = session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code != 200:
                    continue
                body = (r.text or "")[:2000]
                # light content markers to reduce false positives
                if path == "/.env" and re.search(r"(?m)^(APP_KEY|DB_HOST|DB_PASSWORD|AWS_SECRET_ACCESS_KEY)=", body):
                    evidence.append({"url": url, "marker": "dotenv"})
                elif path == "/.git/config" and "[core]" in body:
                    evidence.append({"url": url, "marker": "git config"})
                elif path == "/phpinfo.php" and "php version" in body.lower():
                    evidence.append({"url": url, "marker": "phpinfo"})
                elif path == "/server-status" and "server status" in body.lower():
                    evidence.append({"url": url, "marker": "server-status"})
                elif path.startswith("/actuator/") and re.search(r"\bstatus\b", body, re.IGNORECASE):
                    evidence.append({"url": url, "marker": "actuator"})
                elif path in ("/web.config", "/crossdomain.xml"):
                    evidence.append({"url": url, "marker": "file present"})
                elif path == "/debug":
                    evidence.append({"url": url, "marker": "debug endpoint"})
            except Exception:
                continue

        if evidence:
            return {"status": "FOUND", "details": "Sensitive/common files appear accessible", "evidence": evidence}
        return {"status": "NOT_FOUND", "details": "No sensitive/common files found from the small probe list"}

    def _detect_os_command_injection_marker(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}

        parsed = urlparse(target)
        qs = parsed.query
        if not qs:
            return {"status": "NOT_TESTED", "details": "No query parameters available for a safe command-injection marker test"}

        # Choose a single parameter (first) and try a tiny marker-based echo payload.
        params = parse_qsl(qs, keep_blank_values=True)
        if not params:
            return {"status": "NOT_TESTED", "details": "Can't parse query string"}

        k, v = params[0]
        run_id = uuid.uuid4().hex[:8]
        marker = f"CMDINJ_{run_id}"
        control = f"CTL_{run_id}"

        payloads = [
            f"{control};echo {marker}",
            f"{control}|echo {marker}",
            f"{control}&echo {marker}",
        ]

        # Baseline for comparison
        try:
            baseline = session.get(target, timeout=self.timeout, allow_redirects=True)
            baseline_text = baseline.text or ""
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

        checked = 0
        for p in payloads:
            if checked >= self.max_requests_per_detector:
                break
            checked += 1
            new_params = params[:]
            new_params[0] = (k, p)
            test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
            try:
                r = session.get(test_url, timeout=self.timeout, allow_redirects=True)
                text = r.text or ""
                if marker in text and marker not in baseline_text:
                    # If the raw payload is reflected, treat as weaker
                    if p in text:
                        return {
                            "status": "POTENTIAL",
                            "details": f"Command-injection marker appeared, but payload was also reflected for param '{k}'",
                            "evidence": {"param": k, "marker": marker, "payload": p, "url": test_url},
                        }
                    return {
                        "status": "VULNERABLE",
                        "details": f"Command-injection marker '{marker}' appeared for param '{k}'",
                        "evidence": {"param": k, "marker": marker, "payload": p, "url": test_url},
                    }
            except Exception:
                continue

        return {"status": "NOT_FOUND", "details": "No command-injection marker evidence"}

    def _detect_ldap_injection_heuristic(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}
        return self._detect_error_based_injection(session, target, kind="LDAP")

    def _detect_xpath_injection_heuristic(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}
        return self._detect_error_based_injection(session, target, kind="XPath")

    def _detect_ssi_injection_heuristic(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}

        # SSI test: try a harmless echo of DATE_LOCAL and see if it is evaluated.
        parsed = urlparse(target)
        qs = parsed.query
        token = "<!--#echo var=\"DATE_LOCAL\" -->"
        ctl = "SSI_CTL"

        if not qs:
            test_url = parsed._replace(query=urlencode({"q": token})).geturl()
            control_url = parsed._replace(query=urlencode({"q": ctl})).geturl()
        else:
            params = parse_qsl(qs, keep_blank_values=True)
            if not params:
                return {"status": "NOT_TESTED", "details": "Can't parse query string"}
            k, v = params[0]
            params_test = params[:]
            params_ctl = params[:]
            params_test[0] = (k, token)
            params_ctl[0] = (k, ctl)
            test_url = parsed._replace(query=urlencode(params_test, doseq=True)).geturl()
            control_url = parsed._replace(query=urlencode(params_ctl, doseq=True)).geturl()

        try:
            r = session.get(test_url, timeout=self.timeout, allow_redirects=True)
            rc = session.get(control_url, timeout=self.timeout, allow_redirects=True)
            text = (r.text or "")
            text_ctl = (rc.text or "")

            # DATE_LOCAL typically expands to something like: "Wednesday, 16-Feb-2026 12:34:56 UTC"
            date_like = re.search(r"\b(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun),\s+\d{1,2}-[A-Za-z]{3}-\d{4}\b", text)
            if date_like and not re.search(r"\d{1,2}-[A-Za-z]{3}-\d{4}", text_ctl):
                if token in text:
                    return {"status": "POTENTIAL", "details": "SSI output-like marker present but payload also reflected", "evidence": {"url": test_url}}
                return {"status": "VULNERABLE", "details": "SSI directive appears evaluated", "evidence": {"url": test_url, "match": date_like.group(0)}}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

        return {"status": "NOT_FOUND", "details": "No SSI evaluation evidence"}

    def _detect_error_based_injection(self, session, target, kind):
        parsed = urlparse(target)
        qs = parsed.query
        params = parse_qsl(qs, keep_blank_values=True)
        if not params:
            return {"status": "NOT_TESTED", "details": "No query parameters available"}

        k, v = params[0]
        run_id = uuid.uuid4().hex[:6]
        payloads = []
        error_markers = []

        if kind == "LDAP":
            payloads = [
                f"{v}*)(|(uid=*))({run_id}",
                f"{v}*)({run_id}",
                f"*{run_id}*",
            ]
            error_markers = [
                "ldap",
                "javax.naming",
                "bad search filter",
                "invalid dn",
                "unbalanced parenthesis",
            ]
        elif kind == "XPath":
            payloads = [
                f"' or '1'='1{run_id}",
                f"\" or \"1\"=\"1{run_id}",
                f"') or true() or ('{run_id}",
            ]
            error_markers = [
                "xpath",
                "xpathexception",
                "org.jaxen",
                "xpst",
                "system.xml.xpath",
            ]
        else:
            return {"status": "NOT_TESTED", "details": "Unknown injection kind"}

        try:
            baseline = session.get(target, timeout=self.timeout, allow_redirects=True)
            baseline_text = (baseline.text or "").lower()
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

        checked = 0
        for p in payloads:
            if checked >= self.max_requests_per_detector:
                break
            checked += 1
            new_params = params[:]
            new_params[0] = (k, p)
            test_url = parsed._replace(query=urlencode(new_params, doseq=True)).geturl()
            try:
                r = session.get(test_url, timeout=self.timeout, allow_redirects=True)
                text = (r.text or "").lower()
                if any(m in text for m in error_markers) and not any(m in baseline_text for m in error_markers):
                    return {"status": "POTENTIAL", "details": f"{kind} error markers appeared after payload", "evidence": {"param": k, "payload": p, "url": test_url}}
            except Exception:
                continue

        return {"status": "NOT_FOUND", "details": f"No {kind} injection error markers detected"}

    def _detect_mixed_content(self, session, base, target, resp):
        parsed = urlparse(target)
        if parsed.scheme != "https":
            return {"status": "NOT_TESTED", "details": "Target is not HTTPS"}
        text = (resp.text or "") if resp is not None else ""
        if not text:
            return {"status": "NOT_TESTED", "details": "No response body to inspect"}
        # Look for explicit http:// resource loads
        if re.search(r"\bhttp://[^\s\"']+", text, re.IGNORECASE):
            return {"status": "FOUND", "details": "Page appears to include http:// resources (mixed content)", "evidence": "http://"}
        return {"status": "NOT_FOUND", "details": "No obvious mixed-content markers"}

    def _detect_cross_domain_policy(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}

        base_url = base.rstrip("/")
        candidates = [
            ("/crossdomain.xml", "flash"),
            ("/clientaccesspolicy.xml", "silverlight"),
        ]
        checked = 0
        found = []
        for path, kind in candidates:
            if checked >= self.max_requests_per_detector:
                break
            checked += 1
            url = base_url + path
            try:
                r = session.get(url, timeout=self.timeout, allow_redirects=True)
                if r.status_code != 200:
                    continue
                body = (r.text or "")[:4000].lower()
                if "allow-access-from" in body or "cross-domain-policy" in body or "site-control" in body:
                    risky = (
                        'domain="*"' in body
                        or "domain='*'" in body
                        or "to-ports=\"*\"" in body
                        or "toports=\"*\"" in body
                        or "\"*\"" in body and "domain" in body
                    )
                    found.append({"url": url, "type": kind, "risky": risky})
            except Exception:
                continue

        if any(x.get("risky") for x in found):
            return {"status": "RISKY", "details": "Cross-domain policy allows overly broad access", "evidence": found}
        if found:
            return {"status": "FOUND", "details": "Cross-domain policy file present", "evidence": found}
        return {"status": "NOT_FOUND", "details": "No Flash/Silverlight cross-domain policy files detected"}

    def _detect_user_agent_dependent_response(self, session, base, target, resp):
        if not self.aggressive:
            return {"status": "NOT_TESTED", "details": "Aggressive checks disabled"}

        ua_a = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0"
        ua_b = "curl/8.0"
        try:
            ra = session.get(target, timeout=self.timeout, allow_redirects=True, headers={"User-Agent": ua_a})
            rb = session.get(target, timeout=self.timeout, allow_redirects=True, headers={"User-Agent": ua_b})
            la = len(ra.text or "")
            lb = len(rb.text or "")
            if ra.status_code != rb.status_code:
                return {
                    "status": "FOUND",
                    "details": "Different status codes for different User-Agent values",
                    "evidence": {"status_a": ra.status_code, "status_b": rb.status_code, "len_a": la, "len_b": lb},
                }
            if la == 0 and lb == 0:
                return {"status": "NOT_TESTED", "details": "Empty bodies returned"}
            # flag significant length differences
            if la and lb and (max(la, lb) / max(1, min(la, lb))) >= 1.5:
                return {
                    "status": "FOUND",
                    "details": "Response body length differs significantly by User-Agent",
                    "evidence": {"len_a": la, "len_b": lb},
                }
            return {"status": "NOT_FOUND", "details": "No significant User-Agent dependent response observed"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_sensitive_data_in_url(self, session, base, target, resp):
        parsed = urlparse(target)
        qs = parsed.query
        if not qs:
            return {"status": "NOT_FOUND", "details": "No query string present"}
        params = parse_qsl(qs, keep_blank_values=True)
        if not params:
            return {"status": "NOT_FOUND", "details": "No query parameters parsed"}

        sensitive_keys = {
            "password",
            "pass",
            "pwd",
            "secret",
            "token",
            "access_token",
            "id_token",
            "apikey",
            "api_key",
            "session",
            "sessionid",
            "sid",
        }
        hits = []
        for k, v in params:
            if (k or "").lower() in sensitive_keys and (v or ""):
                hits.append({"param": k, "value_preview": (v[:6] + "…") if len(v) > 6 else v})
        if hits:
            return {"status": "FOUND", "details": "Sensitive-looking data present in URL query string", "evidence": hits}
        return {"status": "NOT_FOUND", "details": "No obvious sensitive parameters in URL query string"}

    def _detect_password_submitted_using_get(self, session, base, target, resp):
        text = (resp.text or "") if resp is not None else ""
        if not text:
            return {"status": "NOT_TESTED", "details": "No response body to inspect"}
        try:
            soup = BeautifulSoup(text, "html.parser")
            for form in soup.find_all("form"):
                method = (form.get("method") or "get").lower()
                if method != "get":
                    continue
                # look for password field
                if form.find("input", {"type": "password"}):
                    action = form.get("action")
                    return {
                        "status": "FOUND",
                        "details": "A form containing a password input uses GET method",
                        "evidence": {"action": action or "(no action)"},
                    }
            return {"status": "NOT_FOUND", "details": "No password forms using GET were detected on landing page"}
        except Exception as e:
            return {"status": "ERROR", "details": str(e)}

    def _detect_client_side_injection_patterns(self, session, base, target, resp):
        # Heuristic: look for common DOM XSS / client-side injection sources+sinks in JS.
        base_host = urlparse(base).netloc
        js_blobs = []
        fetched = 0

        def add_blob(label, content):
            if content:
                js_blobs.append({"label": label, "content": content})

        if resp is None:
            return {"status": "NOT_TESTED", "details": "No response"}

        ctype = (resp.headers.get("Content-Type") or "").lower()
        body = resp.text or ""

        if "javascript" in ctype or urlparse(target).path.lower().endswith(".js"):
            add_blob("response", body)
        else:
            # parse HTML for scripts
            try:
                soup = BeautifulSoup(body, "html.parser")
                # inline scripts
                for s in soup.find_all("script"):
                    if s.get("src"):
                        continue
                    code = s.string or ""
                    if code.strip():
                        add_blob("inline_script", code)

                # external scripts (same-origin only, limited)
                if self.aggressive:
                    for s in soup.find_all("script", src=True):
                        if fetched >= 3:
                            break
                        src = s.get("src")
                        if not src:
                            continue
                        u = urljoin(target, src)
                        pu = urlparse(u)
                        if pu.scheme not in ("http", "https") or pu.netloc != base_host:
                            continue
                        try:
                            r = session.get(u, timeout=self.timeout, allow_redirects=True)
                            if r.status_code == 200 and (r.text or ""):
                                add_blob(f"script:{pu.path}", r.text)
                                fetched += 1
                        except Exception:
                            continue
            except Exception:
                pass

        if not js_blobs:
            return {"status": "NOT_TESTED", "details": "No JavaScript content available to analyze"}

        sources = [
            r"\blocation\.(hash|search|href)\b",
            r"\bdocument\.(url|documenturi|baseuri|cookie|referrer)\b",
            r"\bwindow\.name\b",
            r"\bpostMessage\b",
        ]
        sinks = [
            r"\binnerHTML\b",
            r"\bouterHTML\b",
            r"\binsertAdjacentHTML\b",
            r"\bdocument\.write\b",
            r"\beval\s*\(",
            r"\bnew\s+Function\b",
            r"\bsetTimeout\s*\(\s*['\"]",
            r"\bsetInterval\s*\(\s*['\"]",
        ]
        proto_pollution = [r"__proto__", r"constructor\.prototype"]
        websocket = [r"new\s+WebSocket\s*\("]
        client_sql = [r"openDatabase\s*\(", r"executeSql\s*\("]

        evidence = []
        for blob in js_blobs:
            txt = blob["content"]
            txt_l = txt.lower()
            found_sources = [p for p in sources if re.search(p, txt_l, re.IGNORECASE)]
            found_sinks = [p for p in sinks if re.search(p, txt, re.IGNORECASE)]
            found_proto = [p for p in proto_pollution if p.lower() in txt_l]
            found_ws = [p for p in websocket if re.search(p, txt, re.IGNORECASE)]
            found_sql = [p for p in client_sql if re.search(p, txt, re.IGNORECASE)]
            if found_sources or found_sinks or found_proto or found_ws or found_sql:
                evidence.append({
                    "where": blob["label"],
                    "sources": found_sources[:6],
                    "sinks": found_sinks[:6],
                    "prototype_pollution": found_proto[:4],
                    "websocket": bool(found_ws),
                    "client_sql": bool(found_sql),
                })

        if not evidence:
            return {"status": "NOT_FOUND", "details": "No obvious client-side injection patterns found"}

        # If we have both a source and a sink somewhere, treat as higher confidence potential.
        has_source = any(e.get("sources") for e in evidence)
        has_sink = any(e.get("sinks") for e in evidence)
        if has_source and has_sink:
            return {"status": "POTENTIAL", "details": "Client-side source+sinks detected (possible DOM XSS/client-side injection)", "evidence": evidence}

        if any(e.get("prototype_pollution") for e in evidence):
            return {"status": "POTENTIAL", "details": "Prototype-pollution related keywords found in client-side code", "evidence": evidence}

        return {"status": "POTENTIAL", "details": "Client-side risky patterns found", "evidence": evidence}


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description='Run passive Burp-like checks against a target')
    parser.add_argument('target', help='Target URL or host')
    args = parser.parse_args()
    scanner = BurpScanner()
    res = scanner.scan_target(args.target)
    print(json.dumps(res, indent=2, ensure_ascii=False))
