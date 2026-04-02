import logging
import socket
import requests
from scanners.base import BaseScanner
from scanners.web_crawler import WebCrawler

logger = logging.getLogger(__name__)


class IoTScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting IoT scan on {self.base_url}")
        self.crawler = WebCrawler(self.base_url)
        self.crawl_results = self.crawler.crawl()

        self._check_open_ports()
        self._check_default_credentials()
        self._check_telnet_credentials()
        self._check_unauth_data()
        self._check_device_info()
        self._check_command_injection()
        self._check_directory_traversal()
        self._check_security_headers()
        # Double check: retry checks that found nothing
        existing_count = len(self.findings)
        found_titles = [f["title"] for f in self.findings]

        if not any("Default Credentials" in t for t in found_titles):
            logger.info("Double check: retrying default credentials...")
            self._check_default_credentials()
            if len(self.findings) > existing_count:
                existing_count = len(self.findings)

        if not any("Command Injection" in t for t in found_titles):
            logger.info("Double check: retrying command injection...")
            self._check_command_injection()
            if len(self.findings) > existing_count:
                existing_count = len(self.findings)

        if not any("Unauthenticated" in t or "Sensitive" in t for t in found_titles):
            logger.info("Double check: retrying data access checks...")
            self._check_unauth_data()
            self._check_device_info()

        logger.info(f"IoT scan complete. {len(self.findings)} findings.")
        return self.findings

    def _check_open_ports(self):
        import socket
        ports_to_check = [self.target_port, 23, 2323, 80, 443, 8080, 8081, 1883, 5683]
        open_ports = []
        for port in set(ports_to_check):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target_host, port))
                if result == 0:
                    open_ports.append(port)
            except socket.error:
                pass
            finally:
                sock.close()
        if open_ports:
            self.add_finding(
                title="Open Ports Detected on IoT Device",
                severity="medium",
                category="network",
                description=f"The IoT device has {len(open_ports)} open port(s) exposed to the network.",
                evidence=f"Open ports: {', '.join(str(p) for p in open_ports)}",
                remediation="Close unnecessary ports. Use firewall rules to restrict access to management interfaces.",
                cvss_score=5.3,
            )

    def _check_default_credentials(self):
        """Check default credentials on any discovered login form or admin panel."""
        creds = [
            ("admin", "admin"), ("root", "root"), ("admin", "password"),
            ("admin", "1234"), ("admin", "12345"), ("admin", "123456"),
            ("root", "toor"), ("admin", "admin123"), ("user", "user"),
            ("test", "test"), ("guest", "guest"), ("operator", "operator"),
            ("technician", "tech123"), ("admin", "default"), ("root", "password"),
            ("admin", ""), ("root", ""),
        ]

        # Try discovered login forms
        login_forms = self.crawler.get_login_forms()

        # Also try common admin paths directly
        admin_paths = [p for p in self.crawl_results["paths"] if p.get("is_login_page") or p.get("has_form")]

        if not login_forms and not admin_paths:
            # Try common paths even if crawler didn't find forms
            for path in ["/admin", "/login", "/", "/panel"]:
                try:
                    resp = requests.get(f"{self.base_url}{path}", timeout=self.timeout_val, verify=False)
                    if resp.status_code == 200 and ("<form" in resp.text.lower()):
                        admin_paths.append({"path": path, "has_form": True})
                except requests.RequestException:
                    continue

        for form in login_forms:
            username_field = next((i["name"] for i in form["inputs"] if i["name"].lower() in ("username", "user", "email", "login", "name")), None)
            password_field = next((i["name"] for i in form["inputs"] if i["type"] == "password"), None)

            if not username_field or not password_field:
                continue

            action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

            for username, password in creds:
                try:
                    resp = requests.post(
                        action_url,
                        data={username_field: username, password_field: password},
                        timeout=10, allow_redirects=False, verify=False
                    )
                    # Check for successful login indicators
                    if self._is_login_success(resp):
                        self.add_finding(
                            title="Default Credentials Accepted",
                            severity="critical",
                            category="authentication",
                            description=f"Login form at {form['page']} accepts default credentials: {username}:{password}",
                            evidence=f"POST {action_url} with {username}:{password} returned {resp.status_code}.\nResponse indicates successful login.",
                            remediation="Change all default passwords immediately. Implement account lockout after failed attempts.",
                            cvss_score=9.8,
                        )
                        return
                except requests.RequestException:
                    continue

    @property
    def timeout_val(self):
        return 10

    def _is_login_success(self, resp):
        """Determine if a login attempt was successful."""
        # Redirect to dashboard/home/panel
        if resp.status_code in (301, 302, 303):
            location = resp.headers.get("Location", "").lower()
            if any(w in location for w in ["dashboard", "home", "panel", "admin", "index", "welcome", "main"]):
                return True
        # 200 with success indicators
        if resp.status_code == 200:
            text = resp.text.lower()
            if any(w in text for w in ["welcome", "dashboard", "logout", "sign out", "authenticated", "success"]):
                if not any(w in text for w in ["invalid", "error", "failed", "incorrect", "wrong"]):
                    return True
        # Session cookie set
        if resp.cookies and resp.status_code in (200, 301, 302, 303):
            return True
        return False

    def _check_telnet_credentials(self):
        """Check default credentials on Telnet service."""
        creds = [("admin", "admin"), ("root", "root"), ("root", "toor"), ("admin", ""), ("root", "")]

        for port in [23, 2323]:
            for username, password in creds:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target_host, port))
                    banner = sock.recv(1024).decode(errors="ignore")
                    sock.sendall(f"{username}\n".encode())
                    sock.recv(1024)
                    sock.sendall(f"{password}\n".encode())
                    response = sock.recv(1024).decode(errors="ignore")
                    sock.close()
                    if "welcome" in response.lower() or "successful" in response.lower() or "$" in response or "#" in response or ">" in response:
                        self.add_finding(
                            title=f"Default Credentials Accepted (Telnet:{port})",
                            severity="critical",
                            category="authentication",
                            description=f"Telnet service on port {port} accepts default credentials: {username}:{password}",
                            evidence=f"Banner: {banner.strip()}\nLogin response: {response.strip()}",
                            remediation="Disable Telnet. Use SSH with key-based authentication instead.",
                            cvss_score=9.8,
                        )
                        return
                except (socket.error, socket.timeout):
                    continue

    def _check_unauth_data(self):
        """Check for unauthenticated access to sensitive data endpoints."""
        sensitive_paths = [
            "/api/sensor-data", "/api/data", "/api/sensors", "/api/readings",
            "/api/devices", "/api/metrics", "/api/telemetry", "/data",
            "/sensors", "/readings", "/metrics", "/status/full",
        ]

        # Add any discovered API endpoints that return data without auth
        for ep in self.crawl_results.get("api_endpoints", []):
            if ep["status"] == 200 and ep.get("is_json") and not ep.get("requires_auth"):
                if ep["path"] not in sensitive_paths:
                    sensitive_paths.append(ep["path"])

        for path in sensitive_paths:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        if isinstance(data, (dict, list)) and len(str(data)) > 50:
                            self.add_finding(
                                title="Unauthenticated Access to Sensitive Data",
                                severity="high",
                                category="authorization",
                                description=f"Data endpoint {path} is accessible without any authentication.",
                                evidence=f"GET {path} returned 200.\nData keys: {list(data.keys()) if isinstance(data, dict) else f'{len(data)} items'}",
                                remediation="Require authentication for all data endpoints. Implement API key or token-based auth.",
                                cvss_score=7.5,
                            )
                            return
                    except Exception:
                        pass
            except requests.RequestException:
                continue

    def _check_device_info(self):
        """Check for information disclosure."""
        info_paths = [
            "/device-info", "/info", "/api/info", "/api/system",
            "/system", "/api/device", "/device", "/api/version",
            "/version", "/server-info", "/phpinfo.php", "/server-status",
            "/.env", "/config.json", "/config.yaml", "/config.yml",
        ]

        # Add discovered paths
        for p in self.crawl_results.get("paths", []):
            if p["path"] not in info_paths and p["status"] == 200:
                info_paths.append(p["path"])

        sensitive_keywords = [
            "firmware", "mac_address", "serial", "internal_ip", "gateway",
            "password", "secret", "private_key", "api_key", "token",
            "database", "db_host", "ssh", "telnet", "admin_email",
            "version", "debug", "stack_trace"
        ]

        for path in info_paths:
            try:
                resp = requests.get(f"{self.base_url}{path}", timeout=10, verify=False)
                if resp.status_code == 200:
                    text = resp.text.lower()
                    found_keywords = [k for k in sensitive_keywords if k in text]
                    if len(found_keywords) >= 2:
                        self.add_finding(
                            title="Sensitive Information Disclosure",
                            severity="medium",
                            category="information_disclosure",
                            description=f"The endpoint {path} exposes sensitive internal information without authentication.",
                            evidence=f"GET {path} exposed: {', '.join(found_keywords)}\nResponse: {resp.text[:500]}",
                            remediation="Remove or restrict access to information endpoints. Require admin authentication.",
                            cvss_score=5.3,
                        )
                        return
            except requests.RequestException:
                continue

    def _check_command_injection(self):
        """Check for command injection on any discovered forms or API endpoints."""
        # Try discovered forms with text inputs
        for form in self.crawl_results.get("forms", []):
            text_inputs = [i for i in form["inputs"] if i["type"] in ("text", "search", "hidden")]
            if not text_inputs:
                continue

            action_url = form["action"] if form["action"].startswith("http") else f"{self.base_url}{form['action']}"

            for input_field in text_inputs:
                payload = "test; echo chainsentinel_cmd_test"
                try:
                    data = {input_field["name"]: payload}
                    resp = requests.post(action_url, data=data, timeout=10, verify=False)
                    if "chainsentinel_cmd_test" in resp.text:
                        self.add_finding(
                            title="Command Injection Vulnerability",
                            severity="critical",
                            category="injection",
                            description=f"The form at {form['page']} is vulnerable to command injection via field '{input_field['name']}'.",
                            evidence=f"POST {action_url} with {input_field['name']}='{payload}'\nResponse contains injected output.",
                            remediation="Never pass user input to shell commands. Use parameterized APIs or whitelisted commands only.",
                            cvss_score=10.0,
                        )
                        return
                except requests.RequestException:
                    continue

        # Try common diagnostic/command endpoints with JSON
        cmd_paths = ["/api/diagnostic", "/api/cmd", "/api/exec", "/api/command", "/api/run", "/api/shell", "/diagnostic", "/cmd"]
        for path in cmd_paths:
            try:
                resp = requests.post(
                    f"{self.base_url}{path}",
                    json={"cmd": "echo chainsentinel_cmd_test", "command": "echo chainsentinel_cmd_test"},
                    timeout=10, verify=False
                )
                if resp.status_code == 200 and "chainsentinel_cmd_test" in resp.text:
                    self.add_finding(
                        title="Command Injection Vulnerability",
                        severity="critical",
                        category="injection",
                        description=f"The endpoint {path} executes arbitrary system commands.",
                        evidence=f"POST {path} with cmd='echo chainsentinel_cmd_test'\nResponse: {resp.text[:500]}",
                        remediation="Never pass user input to shell commands. Use parameterized APIs or whitelisted commands only.",
                        cvss_score=10.0,
                    )
                    return
            except requests.RequestException:
                continue

    def _check_directory_traversal(self):
        """Check for directory traversal on IoT device."""
        traversal_paths = ["/logs", "/file", "/download", "/read", "/config", "/data"]

        for p in self.crawl_results.get("paths", []):
            if p["status"] == 200:
                traversal_paths.append(p["path"])

        payloads = [
            ("file", "../../../../etc/passwd"),
            ("path", "../../../../etc/passwd"),
            ("file", "../../../etc/shadow"),
        ]

        for path in traversal_paths:
            for param, payload in payloads:
                try:
                    resp = requests.get(
                        f"{self.base_url}{path}",
                        params={param: payload},
                        timeout=10, verify=False
                    )
                    if resp.status_code == 200 and "root:" in resp.text:
                        self.add_finding(
                            title="Directory Traversal on IoT Device",
                            severity="high",
                            category="injection",
                            description=f"The endpoint {path} allows reading arbitrary system files via path traversal.",
                            evidence=f"GET {path}?{param}={payload}\nResponse contains /etc/passwd:\n{resp.text[:300]}",
                            remediation="Validate file paths. Use chroot or restrict file access to specific directories.",
                            cvss_score=7.5,
                        )
                        return
                except requests.RequestException:
                    continue

    def _check_security_headers(self):
        """Check for missing security headers on IoT web interface."""
        try:
            resp = requests.get(self.base_url, timeout=10, verify=False)
            headers = resp.headers
            missing = []

            for header in ["X-Content-Type-Options", "X-Frame-Options", "Content-Security-Policy"]:
                if header not in headers:
                    missing.append(header)

            if len(missing) >= 2:
                self.add_finding(
                    title="Missing Security Headers on IoT Interface",
                    severity="low",
                    category="configuration",
                    description=f"The IoT web interface is missing {len(missing)} security headers.",
                    evidence=f"GET {self.base_url}\nMissing: {', '.join(missing)}",
                    remediation="Add security headers even on embedded web servers.",
                    cvss_score=3.7,
                )
        except requests.RequestException:
            pass
