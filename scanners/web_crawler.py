import logging
import re
import requests
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


class WebCrawler:
    """Discover endpoints, forms, and API paths on a target."""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'ChainSentinel/1.0 Security Scanner'})
        self.discovered_paths = []
        self.discovered_forms = []
        self.discovered_api_endpoints = []

    def crawl(self) -> dict:
        """Run full discovery."""
        self._probe_common_paths()
        self._probe_admin_paths()
        self._probe_api_paths()
        self._discover_forms()
        return {
            "paths": self.discovered_paths,
            "forms": self.discovered_forms,
            "api_endpoints": self.discovered_api_endpoints
        }

    def _probe_common_paths(self):
        """Probe common web paths."""
        paths = [
            "/", "/index", "/index.html", "/home",
            "/health", "/status", "/info", "/about",
            "/robots.txt", "/sitemap.xml",
            "/.env", "/config", "/configuration",
            "/debug", "/test", "/dev",
            "/backup", "/dump", "/export",
            "/swagger", "/swagger-ui", "/api-docs", "/docs", "/redoc",
        ]
        for path in paths:
            try:
                resp = self.session.get(urljoin(self.base_url, path), timeout=self.timeout, allow_redirects=False, verify=False)
                if resp.status_code < 404:
                    self.discovered_paths.append({
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "length": len(resp.content),
                        "headers": dict(resp.headers)
                    })
            except requests.RequestException:
                continue

    def _probe_admin_paths(self):
        """Probe common admin/login paths."""
        paths = [
            "/admin", "/admin/", "/administrator", "/login", "/signin", "/sign-in",
            "/auth", "/authenticate", "/panel", "/dashboard", "/console",
            "/management", "/manager", "/portal", "/user/login", "/account/login",
            "/wp-admin", "/wp-login.php", "/admin/login", "/admin/signin",
            "/cpanel", "/webmail", "/phpmyadmin",
        ]
        for path in paths:
            try:
                resp = self.session.get(urljoin(self.base_url, path), timeout=self.timeout, allow_redirects=True, verify=False)
                if resp.status_code < 404:
                    has_form = "<form" in resp.text.lower()
                    has_password = 'type="password"' in resp.text.lower() or "type='password'" in resp.text.lower()
                    self.discovered_paths.append({
                        "path": path,
                        "status": resp.status_code,
                        "content_type": resp.headers.get("Content-Type", ""),
                        "length": len(resp.content),
                        "has_form": has_form,
                        "has_password_field": has_password,
                        "is_login_page": has_form and has_password
                    })
            except requests.RequestException:
                continue

    def _probe_api_paths(self):
        """Probe common API paths."""
        paths = [
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
            "/rest", "/rest/v1", "/graphql",
            "/api/health", "/api/status", "/api/info", "/api/version",
            "/api/users", "/api/items", "/api/products", "/api/orders",
            "/api/customers", "/api/inventory", "/api/warehouse",
            "/api/sensors", "/api/devices", "/api/data",
            "/api/search", "/api/query",
            "/api/config", "/api/settings", "/api/admin",
            "/api/v1/items", "/api/v1/products", "/api/v1/orders", "/api/v1/users",
            "/api/v1/customers", "/api/v1/inventory", "/api/v1/warehouse",
            "/api/v1/sensors", "/api/v1/devices", "/api/v1/data",
            "/api/v1/search", "/api/v1/config", "/api/v1/health",
            "/api/v2/items", "/api/v2/products", "/api/v2/orders", "/api/v2/users",
            "/v1/items", "/v1/products", "/v1/orders", "/v1/users",
            "/items", "/products", "/orders", "/users", "/customers",
            "/inventory", "/warehouse", "/devices",
        ]
        for path in paths:
            try:
                # Try GET
                resp = self.session.get(urljoin(self.base_url, path), timeout=self.timeout, allow_redirects=False, verify=False)
                content_type = resp.headers.get("Content-Type", "")
                is_json = "json" in content_type or resp.text.strip().startswith(("{", "["))

                if resp.status_code < 404:
                    endpoint = {
                        "path": path,
                        "method": "GET",
                        "status": resp.status_code,
                        "is_json": is_json,
                        "content_type": content_type,
                        "requires_auth": resp.status_code in (401, 403),
                        "response_snippet": resp.text[:200]
                    }
                    self.discovered_api_endpoints.append(endpoint)

                    # If JSON, try to find parameters
                    if is_json and resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                                endpoint["fields"] = list(data[0].keys())
                                endpoint["has_id"] = "id" in data[0]
                                endpoint["sample_id"] = data[0].get("id")
                        except Exception:
                            pass
            except requests.RequestException:
                continue

        # Dynamic API discovery: if we found any API base path, try common sub-paths
        api_bases = set()
        for ep in self.discovered_api_endpoints:
            parts = ep["path"].rstrip("/").rsplit("/", 1)
            if len(parts) > 1:
                api_bases.add(parts[0])

        sub_paths = ["/items", "/products", "/orders", "/users", "/customers",
                     "/inventory", "/warehouse", "/devices", "/sensors", "/data",
                     "/search", "/config", "/health", "/status"]

        for base in api_bases:
            for sub in sub_paths:
                full_path = f"{base}{sub}"
                if full_path not in [ep["path"] for ep in self.discovered_api_endpoints]:
                    try:
                        resp = self.session.get(urljoin(self.base_url, full_path), timeout=self.timeout, allow_redirects=False, verify=False)
                        content_type = resp.headers.get("Content-Type", "")
                        is_json = "json" in content_type or resp.text.strip().startswith(("{", "["))

                        if resp.status_code < 404:
                            endpoint = {
                                "path": full_path,
                                "method": "GET",
                                "status": resp.status_code,
                                "is_json": is_json,
                                "content_type": content_type,
                                "requires_auth": resp.status_code in (401, 403),
                                "response_snippet": resp.text[:200]
                            }
                            self.discovered_api_endpoints.append(endpoint)

                            if is_json and resp.status_code == 200:
                                try:
                                    data = resp.json()
                                    if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                                        endpoint["fields"] = list(data[0].keys())
                                        endpoint["has_id"] = "id" in data[0]
                                        endpoint["sample_id"] = data[0].get("id")
                                except Exception:
                                    pass
                    except requests.RequestException:
                        continue

    def _discover_forms(self):
        """Find HTML forms on discovered pages."""
        for page in self.discovered_paths:
            if page.get("has_form"):
                try:
                    resp = self.session.get(urljoin(self.base_url, page["path"]), timeout=self.timeout, verify=False)
                    forms = self._parse_forms(resp.text, page["path"])
                    self.discovered_forms.extend(forms)
                except requests.RequestException:
                    continue

    def _parse_forms(self, html: str, page_path: str) -> list:
        """Extract form details from HTML."""
        forms = []
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)

        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)

            # Get action
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else page_path

            # Get method
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = (method_match.group(1) if method_match else "GET").upper()

            # Get inputs
            inputs = []
            for input_match in input_pattern.finditer(form_html):
                input_html = input_match.group(0)
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                if name_match:
                    inputs.append({
                        "name": name_match.group(1),
                        "type": (type_match.group(1) if type_match else "text").lower()
                    })

            forms.append({
                "page": page_path,
                "action": action,
                "method": method,
                "inputs": inputs,
                "has_password": any(i["type"] == "password" for i in inputs),
                "has_username": any(i["name"].lower() in ("username", "user", "email", "login", "name") for i in inputs)
            })

        return forms

    def get_login_forms(self) -> list:
        """Return forms that look like login forms."""
        return [f for f in self.discovered_forms if f.get("has_password")]

    def get_search_params(self) -> list:
        """Find endpoints with search/query parameters."""
        results = []
        for ep in self.discovered_api_endpoints:
            path = ep["path"]
            for param in ["search", "q", "query", "keyword", "filter", "name", "term"]:
                try:
                    resp = self.session.get(
                        urljoin(self.base_url, path),
                        params={param: "test"},
                        timeout=self.timeout,
                        verify=False
                    )
                    if resp.status_code == 200:
                        results.append({"path": path, "param": param})
                        break
                except requests.RequestException:
                    continue
        return results
