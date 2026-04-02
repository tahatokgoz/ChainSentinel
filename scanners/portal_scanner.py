import base64
import logging
import random
import requests
from scanners.base import BaseScanner
from scanners.web_crawler import WebCrawler

logger = logging.getLogger(__name__)


class PortalScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting Portal scan on {self.base_url}")
        self.crawler = WebCrawler(self.base_url)
        self.crawl_results = self.crawler.crawl()

        self._check_sqli_login()
        self._check_brute_force()
        self._check_session_weakness()
        self._check_session_fixation()
        self._check_debug_mode()
        self._check_backup_files()
        self._check_xss()
        self._check_csrf()
        self._check_security_headers()
        self._check_cookie_security()
        self._check_directory_traversal()
        self._check_file_upload()
        # Double check: retry checks that found nothing
        existing_count = len(self.findings)
        found_titles = [f["title"] for f in self.findings]

        if not any("SQL Injection" in t for t in found_titles):
            logger.info("Double check: retrying SQLi...")
            self._check_sqli_login()
            if len(self.findings) > existing_count:
                existing_count = len(self.findings)

        if not any("Debug" in t or "Backup" in t or "Exposed" in t for t in found_titles):
            logger.info("Double check: retrying info disclosure...")
            self._check_debug_mode()
            self._check_backup_files()

        logger.info(f"Portal scan complete. {len(self.findings)} findings.")
        return self.findings

    def _find_login_form(self):
        """Find a login form on the target."""
        login_forms = self.crawler.get_login_forms()
        if login_forms:
            return login_forms[0]

        # Try common login paths manually
        for path in ["/login", "/signin", "/auth", "/admin", "/user/login", "/account/login", "/"]:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code == 200 and 'type="password"' in resp.text.lower():
                    forms = self.crawler._parse_forms(resp.text, path)
                    login_forms_found = [f for f in forms if f.get("has_password")]
                    if login_forms_found:
                        return login_forms_found[0]
            except requests.RequestException:
                continue
        return None

    def _check_sqli_login(self):
        """Test SQL injection on login forms."""
        form = self._find_login_form()
        if not form:
            return

        username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
        password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not username_field or not password_field:
            return

        action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

        payloads = [
            ("' OR '1'='1' --", "anything"),
            ("admin' --", "anything"),
            ("' OR 1=1 --", "x"),
            ("\" OR \"1\"=\"1\" --", "x"),
            ("' OR ''='", "' OR ''='"),
        ]

        for username, password in payloads:
            try:
                resp = requests.post(
                    action_url,
                    data={username_field: username, password_field: password},
                    allow_redirects=False, timeout=10, verify=False
                )
                if resp.status_code in (301, 302, 303):
                    location = resp.headers.get("Location", "").lower()
                    if any(w in location for w in ["dashboard", "home", "panel", "admin", "index", "welcome"]):
                        self.add_finding(
                            title="SQL Injection - Authentication Bypass",
                            severity="critical",
                            category="injection",
                            description=f"Login form at {form['page']} is vulnerable to SQL injection, allowing authentication bypass.",
                            evidence=f"Payload: {username_field}='{username}', {password_field}='{password}'\nResponse: {resp.status_code} redirect to {resp.headers.get('Location')}",
                            remediation="Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
                            cvss_score=9.8,
                        )
                        return
                if resp.status_code == 200:
                    text = resp.text.lower()
                    if any(w in text for w in ["welcome", "dashboard", "logout", "sign out"]):
                        if not any(w in text for w in ["invalid", "error", "failed"]):
                            self.add_finding(
                                title="SQL Injection - Authentication Bypass",
                                severity="critical",
                                category="injection",
                                description=f"Login form at {form['page']} is vulnerable to SQL injection.",
                                evidence=f"Payload: {username_field}='{username}'\nResponse indicates successful login.",
                                remediation="Use parameterized queries. Never concatenate user input into SQL.",
                                cvss_score=9.8,
                            )
                            return
            except requests.RequestException:
                continue

    def _check_brute_force(self):
        """Check if brute force protection exists."""
        form = self._find_login_form()
        if not form:
            return

        username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
        password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not username_field or not password_field:
            return

        action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

        blocked = False
        attempts = 20
        for i in range(attempts):
            try:
                resp = requests.post(
                    action_url,
                    data={username_field: "nonexistent_user", password_field: f"wrong{i}"},
                    allow_redirects=False, timeout=5, verify=False
                )
                if resp.status_code == 429:
                    blocked = True
                    break
            except requests.RequestException:
                break

        if not blocked:
            self.add_finding(
                title="No Brute Force Protection",
                severity="medium",
                category="authentication",
                description=f"No rate limiting detected after {attempts} failed login attempts on {form['page']}.",
                evidence=f"Sent {attempts} failed login requests to {action_url}. No 429 response received.",
                remediation="Implement rate limiting. Add CAPTCHA after failed attempts. Use account lockout.",
                cvss_score=5.3,
            )

    def _check_session_weakness(self):
        """Check session token strength."""
        form = self._find_login_form()
        if not form:
            return

        username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
        password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not username_field or not password_field:
            return

        action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

        # Try SQLi to get a session
        try:
            resp = requests.post(
                action_url,
                data={username_field: "' OR '1'='1' --", password_field: "x"},
                allow_redirects=False, timeout=10, verify=False
            )

            # Check all cookies
            for cookie_name, cookie_value in resp.cookies.items():
                # Check if base64 encoded
                try:
                    decoded = base64.b64decode(cookie_value).decode()
                    if ":" in decoded or "@" in decoded:
                        self.add_finding(
                            title="Weak Session Token (Predictable)",
                            severity="high",
                            category="session_management",
                            description=f"Session token '{cookie_name}' is base64-encoded and contains readable data. No cryptographic signing.",
                            evidence=f"Cookie: {cookie_name}={cookie_value}\nDecoded: {decoded}",
                            remediation="Use cryptographically signed session tokens (e.g., JWT with HMAC, secure server-side sessions).",
                            cvss_score=7.5,
                        )
                        return
                except Exception:
                    pass

                # Check if token is too short or sequential
                if len(cookie_value) < 16:
                    self.add_finding(
                        title="Weak Session Token (Too Short)",
                        severity="high",
                        category="session_management",
                        description=f"Session token '{cookie_name}' is only {len(cookie_value)} characters long, making it vulnerable to brute force.",
                        evidence=f"Cookie: {cookie_name}={cookie_value} (length: {len(cookie_value)})",
                        remediation="Use session tokens of at least 128 bits (32 hex characters) generated by a CSPRNG.",
                        cvss_score=7.5,
                    )
                    return
        except requests.RequestException:
            pass

    def _check_session_fixation(self):
        """Check for session fixation vulnerability."""
        form = self._find_login_form()
        if not form:
            return

        username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
        password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not username_field or not password_field:
            return

        action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

        try:
            fixed_session = base64.b64encode(b"attacker:9999999999").decode()
            resp = requests.post(
                f"{action_url}?session_id={fixed_session}",
                data={username_field: "' OR '1'='1' --", password_field: "x"},
                allow_redirects=False, timeout=10, verify=False
            )
            set_cookie = resp.headers.get("Set-Cookie", "")
            if fixed_session in set_cookie:
                self.add_finding(
                    title="Session Fixation Vulnerability",
                    severity="high",
                    category="session_management",
                    description="The application accepts session IDs from URL parameters, enabling session fixation attacks.",
                    evidence=f"Sent session_id={fixed_session} in URL.\nSet-Cookie contains the fixed session value.",
                    remediation="Always generate new session IDs on login. Never accept session IDs from URL parameters.",
                    cvss_score=7.5,
                )
        except requests.RequestException:
            pass

    def _check_debug_mode(self):
        """Check for debug mode and information disclosure."""
        test_cases = [
            ("GET", f"{self.base_url}/nonexistent_page_{random.randint(1000,9999)}", None),
            ("GET", f"{self.base_url}/../../../../etc/passwd", None),
        ]

        # Add login form with bad data
        form = self._find_login_form()
        if form:
            username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
            password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)
            if username_field and password_field:
                action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"
                test_cases.append(("POST", action_url, {username_field: "' invalid sql", password_field: "x"}))

        for method, url, data in test_cases:
            try:
                if method == "GET":
                    resp = requests.get(url, timeout=10, verify=False)
                else:
                    resp = requests.post(url, data=data, allow_redirects=False, timeout=10, verify=False)

                text = resp.text.lower()
                if any(indicator in text for indicator in ["traceback", "debugger", "werkzeug", "stack trace", "exception", "error in", "syntax error", "operationalerror", "mysql", "postgresql", "sqlite3", "internal server error"]):
                    self.add_finding(
                        title="Debug Mode Enabled - Information Disclosure",
                        severity="medium",
                        category="information_disclosure",
                        description="The application exposes detailed error messages or stack traces, revealing internal implementation details.",
                        evidence=f"{method} {url}\nResponse snippet: {resp.text[:500]}",
                        remediation="Disable debug mode in production. Use custom error pages. Never expose raw error messages.",
                        cvss_score=5.3,
                    )
                    return
            except requests.RequestException:
                continue

    def _check_backup_files(self):
        """Check for exposed backup files and sensitive paths."""
        paths = [
            "/backup", "/backup.zip", "/backup.sql", "/dump.sql",
            "/db.sql", "/database.sql", "/.git/config", "/.svn/entries",
            "/.htaccess", "/web.config", "/.DS_Store",
            "/config.php.bak", "/config.old", "/.env.backup",
            "/admin.bak", "/login.bak",
        ]

        for path in paths:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code == 200 and len(resp.content) > 0:
                    content_type = resp.headers.get("Content-Type", "")
                    if "html" not in content_type.lower() or len(resp.content) < 1000:
                        self.add_finding(
                            title=f"Exposed Sensitive File: {path}",
                            severity="high",
                            category="information_disclosure",
                            description=f"The file {path} is publicly accessible and may contain sensitive information.",
                            evidence=f"GET {path} returned {resp.status_code}.\nContent-Type: {content_type}\nSize: {len(resp.content)} bytes\nSnippet: {resp.text[:200]}",
                            remediation="Remove backup and sensitive files from web-accessible directories. Block access via server configuration.",
                            cvss_score=7.2,
                        )
                        return
            except requests.RequestException:
                continue

    def _check_xss(self):
        """Check for reflected XSS vulnerabilities."""
        test_targets = []

        for form in self.crawl_results.get("forms", []):
            text_inputs = [i for i in form["inputs"] if i["type"] in ("text", "search")]
            for inp in text_inputs:
                test_targets.append({
                    "url": form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}",
                    "param": inp["name"],
                    "method": form["method"]
                })

        for path in ["/search", "/find", "/query", "/lookup"]:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code == 200 and "<form" in resp.text.lower():
                    for param in ["q", "search", "query", "keyword", "term"]:
                        test_targets.append({"url": f"{self.base_url}{path}", "param": param, "method": "GET"})
            except requests.RequestException:
                continue

        xss_payloads = [
            '<script>alert("XSS")</script>',
            '"><img src=x onerror=alert(1)>',
            "'-alert(1)-'",
        ]

        for target in test_targets:
            for payload in xss_payloads:
                try:
                    if target["method"] == "GET":
                        resp = requests.get(target["url"], params={target["param"]: payload}, timeout=10, verify=False)
                    else:
                        resp = requests.post(target["url"], data={target["param"]: payload}, timeout=10, verify=False)

                    if payload in resp.text:
                        self.add_finding(
                            title="Reflected Cross-Site Scripting (XSS)",
                            severity="high",
                            category="injection",
                            description=f"The parameter '{target['param']}' reflects user input without sanitization, enabling XSS attacks.",
                            evidence=f"{target['method']} {target['url']}?{target['param']}={payload}\nPayload reflected in response.",
                            remediation="Sanitize all user input. Use HTML encoding for output. Implement Content-Security-Policy header.",
                            cvss_score=6.1,
                        )
                        return
                except requests.RequestException:
                    continue

    def _check_csrf(self):
        """Check for missing CSRF protection on forms."""
        all_forms = self.crawl_results.get("forms", [])

        for form in all_forms:
            if form["method"] == "POST":
                has_csrf = any(
                    i["name"].lower() in ("csrf", "csrf_token", "_token", "csrfmiddlewaretoken", "authenticity_token", "_csrf")
                    for i in form["inputs"]
                )
                has_hidden_token = any(
                    i["type"] == "hidden" and ("token" in i["name"].lower() or "csrf" in i["name"].lower())
                    for i in form["inputs"]
                )

                if not has_csrf and not has_hidden_token:
                    self.add_finding(
                        title="Missing CSRF Protection",
                        severity="medium",
                        category="session_management",
                        description=f"The form at {form['page']} (action: {form['action']}) has no CSRF token, making it vulnerable to cross-site request forgery.",
                        evidence=f"Form at {form['page']}: method=POST, action={form['action']}\nInputs: {[i['name'] for i in form['inputs']]}\nNo CSRF token found.",
                        remediation="Add CSRF tokens to all state-changing forms. Use SameSite cookie attribute.",
                        cvss_score=4.3,
                    )
                    return

    def _check_security_headers(self):
        """Check for missing HTTP security headers."""
        try:
            resp = requests.get(self.base_url, timeout=10, verify=False)
            headers = resp.headers
            missing = []

            security_headers = {
                "X-Content-Type-Options": "Prevents MIME type sniffing",
                "X-Frame-Options": "Prevents clickjacking",
                "X-XSS-Protection": "Enables browser XSS filter",
                "Content-Security-Policy": "Prevents XSS and data injection",
                "Strict-Transport-Security": "Enforces HTTPS",
                "Referrer-Policy": "Controls referrer information",
            }

            for header, desc in security_headers.items():
                if header not in headers:
                    missing.append(f"{header}: {desc}")

            if len(missing) >= 3:
                self.add_finding(
                    title="Missing HTTP Security Headers",
                    severity="medium",
                    category="configuration",
                    description=f"The application is missing {len(missing)} important security headers.",
                    evidence="Missing headers:\n" + "\n".join(f"- {h}" for h in missing),
                    remediation="Add security headers: X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Content-Security-Policy, Strict-Transport-Security.",
                    cvss_score=5.3,
                )
        except requests.RequestException:
            pass

    def _check_cookie_security(self):
        """Check for insecure cookie attributes."""
        form = self._find_login_form()
        if not form:
            return

        username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
        password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

        if not username_field or not password_field:
            return

        action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

        try:
            resp = requests.post(
                action_url,
                data={username_field: "' OR '1'='1' --", password_field: "x"},
                allow_redirects=False, timeout=10, verify=False
            )

            set_cookie = resp.headers.get("Set-Cookie", "")
            if set_cookie:
                issues = []
                if "httponly" not in set_cookie.lower():
                    issues.append("HttpOnly flag missing (cookies accessible via JavaScript)")
                if "secure" not in set_cookie.lower():
                    issues.append("Secure flag missing (cookies sent over HTTP)")
                if "samesite" not in set_cookie.lower():
                    issues.append("SameSite attribute missing (vulnerable to CSRF)")

                if len(issues) >= 2:
                    self.add_finding(
                        title="Insecure Cookie Configuration",
                        severity="medium",
                        category="session_management",
                        description="Session cookies are missing critical security attributes.",
                        evidence=f"Set-Cookie: {set_cookie}\nIssues:\n" + "\n".join(f"- {i}" for i in issues),
                        remediation="Set cookies with HttpOnly, Secure, and SameSite=Strict flags.",
                        cvss_score=5.3,
                    )
        except requests.RequestException:
            pass

    def _check_directory_traversal(self):
        """Check for directory/path traversal vulnerabilities."""
        traversal_targets = []

        for path_info in self.crawl_results.get("paths", []):
            path = path_info["path"]
            if any(w in path.lower() for w in ["download", "file", "read", "view", "get", "load", "open"]):
                traversal_targets.append(path)

        traversal_targets.extend(["/download", "/file", "/read", "/view", "/logs", "/export"])

        payloads = [
            ("file", "../../../../etc/passwd"),
            ("file", "..\\..\\..\\..\\windows\\win.ini"),
            ("path", "../../../../etc/passwd"),
            ("filename", "../../../../etc/passwd"),
            ("name", "../../../../etc/passwd"),
        ]

        for target_path in traversal_targets:
            for param, payload in payloads:
                try:
                    resp = requests.get(
                        f"{self.base_url}{target_path}",
                        params={param: payload},
                        timeout=10, verify=False
                    )
                    if resp.status_code == 200:
                        if "root:" in resp.text or "[extensions]" in resp.text or "passwd" in resp.text.lower():
                            self.add_finding(
                                title="Directory Traversal Vulnerability",
                                severity="high",
                                category="injection",
                                description=f"The endpoint {target_path} is vulnerable to path traversal via '{param}' parameter.",
                                evidence=f"GET {target_path}?{param}={payload}\nResponse contains system file contents:\n{resp.text[:300]}",
                                remediation="Validate and sanitize file paths. Use a whitelist of allowed files. Never use user input directly in file paths.",
                                cvss_score=7.5,
                            )
                            return
                except requests.RequestException:
                    continue

    def _check_file_upload(self):
        """Check for unrestricted file upload."""
        upload_paths = ["/upload", "/file-upload", "/import", "/attach"]

        for path_info in self.crawl_results.get("paths", []):
            path = path_info["path"]
            if "upload" in path.lower() or "import" in path.lower():
                upload_paths.insert(0, path)

        for path in upload_paths:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code != 200:
                    continue

                if 'type="file"' not in resp.text.lower() and "multipart" not in resp.text.lower():
                    continue

                from io import BytesIO
                fake_file = BytesIO(b'<?php echo "test"; ?>')

                resp = requests.post(
                    f"{self.base_url}{path}",
                    files={"file": ("test.php", fake_file, "application/x-php")},
                    timeout=10, verify=False
                )

                if resp.status_code == 200 and ("uploaded" in resp.text.lower() or "success" in resp.text.lower()):
                    self.add_finding(
                        title="Unrestricted File Upload",
                        severity="high",
                        category="injection",
                        description=f"The upload endpoint at {path} accepts dangerous file types (.php) without validation.",
                        evidence=f"POST {path} with file='test.php' (PHP content)\nResponse: {resp.text[:300]}",
                        remediation="Validate file extensions and MIME types. Only allow expected file types. Store uploads outside web root.",
                        cvss_score=7.5,
                    )
                    return
            except requests.RequestException:
                continue
