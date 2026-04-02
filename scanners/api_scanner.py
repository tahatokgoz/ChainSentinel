import logging
import requests
from scanners.base import BaseScanner
from scanners.web_crawler import WebCrawler

logger = logging.getLogger(__name__)


class APIScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting API scan on {self.base_url}")
        self.crawler = WebCrawler(self.base_url)
        self.crawl_results = self.crawler.crawl()

        # Try to find API key or auth method
        self.api_headers = {}
        self._detect_auth()

        # Re-probe endpoints that required auth, now with discovered credentials
        if self.api_headers:
            for ep in self.crawl_results.get("api_endpoints", []):
                if ep.get("requires_auth"):
                    try:
                        resp = requests.get(
                            f"{self.base_url}{ep['path']}",
                            headers=self.api_headers,
                            timeout=10, verify=False
                        )
                        ep["status"] = resp.status_code
                        ep["requires_auth"] = resp.status_code in (401, 403)
                        content_type = resp.headers.get("Content-Type", "")
                        ep["is_json"] = "json" in content_type or resp.text.strip().startswith(("{", "["))
                        ep["response_snippet"] = resp.text[:200]

                        if ep["is_json"] and resp.status_code == 200:
                            try:
                                data = resp.json()
                                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                                    ep["fields"] = list(data[0].keys())
                                    ep["has_id"] = "id" in data[0]
                                    ep["sample_id"] = data[0].get("id")
                            except Exception:
                                pass
                    except Exception:
                        continue

        self._check_sqli_search()
        self._check_idor()
        self._check_auth_weakness()
        self._check_rate_limit()
        self._check_mass_assignment()
        self._check_input_validation()
        self._check_cors()
        self._check_security_headers()
        # Double check: retry checks that found nothing
        existing_count = len(self.findings)
        found_categories = [f["category"] for f in self.findings]

        if "injection" not in found_categories:
            logger.info("Double check: retrying SQLi...")
            self._check_sqli_search()
            if len(self.findings) > existing_count:
                existing_count = len(self.findings)

        if not any("Mass Assignment" in f.get("title", "") for f in self.findings):
            logger.info("Double check: retrying mass assignment...")
            self._check_mass_assignment()
            if len(self.findings) > existing_count:
                existing_count = len(self.findings)

        if not any("API Key" in f.get("title", "") for f in self.findings):
            logger.info("Double check: retrying auth weakness...")
            self._check_auth_weakness()

        logger.info(f"API scan complete. {len(self.findings)} findings.")
        return self.findings

    def _detect_auth(self):
        """Try to detect and use API authentication."""
        # Check if any endpoint requires auth
        for ep in self.crawl_results.get("api_endpoints", []):
            if ep.get("requires_auth"):
                # Try common API keys
                common_keys = ["test-key-001", "admin", "api-key", "test", "demo", "default"]
                for key in common_keys:
                    try:
                        resp = requests.get(
                            f"{self.base_url}{ep['path']}",
                            headers={"X-API-Key": key, "Authorization": f"Bearer {key}"},
                            params={"api_key": key},
                            timeout=10, verify=False
                        )
                        if resp.status_code == 200:
                            self.api_headers = {"X-API-Key": key}
                            return
                    except requests.RequestException:
                        continue

    def _make_request(self, method, path, **kwargs):
        """Make request with discovered auth headers."""
        headers = {**self.api_headers, **kwargs.pop("headers", {})}
        url = f"{self.base_url}{path}" if not path.startswith("http") else path
        try:
            if method == "GET":
                return requests.get(url, headers=headers, timeout=10, verify=False, **kwargs)
            elif method == "POST":
                return requests.post(url, headers=headers, timeout=10, verify=False, **kwargs)
            elif method == "PUT":
                return requests.put(url, headers=headers, timeout=10, verify=False, **kwargs)
        except requests.RequestException:
            return None

    def _check_sqli_search(self):
        """Test SQL injection on all discovered endpoints with parameters."""
        # Collect all testable endpoints
        test_targets = []

        for ep in self.crawl_results.get("api_endpoints", []):
            if ep["status"] == 200 and ep.get("is_json"):
                for param in ["search", "q", "query", "keyword", "filter", "name", "id", "category", "type", "sort"]:
                    test_targets.append({"path": ep["path"], "param": param})

        # Also try crawler's search params
        test_targets.extend(self.crawler.get_search_params())

        # Remove duplicates
        seen = set()
        unique_targets = []
        for t in test_targets:
            key = f"{t['path']}:{t['param']}"
            if key not in seen:
                seen.add(key)
                unique_targets.append(t)

        payloads = [
            ("' OR '1'='1", "boolean-based"),
            ("' UNION SELECT NULL--", "union-based"),
            ("1' AND '1'='1", "boolean-based"),
            ("1 OR 1=1", "boolean-based"),
        ]

        for sp in unique_targets:
            for payload, technique in payloads:
                try:
                    # Normal request for baseline
                    normal_resp = self._make_request("GET", sp["path"], params={sp["param"]: "test123"})
                    if not normal_resp:
                        continue

                    # SQLi request
                    sqli_resp = self._make_request("GET", sp["path"], params={sp["param"]: payload})
                    if not sqli_resp:
                        continue

                    # Check for SQL error in response (any status code)
                    text = sqli_resp.text.lower()
                    if any(w in text for w in ["sql", "syntax", "mysql", "postgresql", "sqlite", "oracle", "operationalerror", "unrecognized token", "near \""]):
                        self.add_finding(
                            title=f"SQL Injection in {sp['path']} ({technique})",
                            severity="critical",
                            category="injection",
                            description=f"The {sp['path']} endpoint is vulnerable to {technique} SQL injection via '{sp['param']}' parameter.",
                            evidence=f"Payload: {sp['param']}={payload}\nResponse: {sqli_resp.text[:500]}",
                            remediation="Use parameterized queries. Never concatenate user input into SQL statements.",
                            cvss_score=9.8,
                        )
                        return

                    # Check for different result count (both must be 200)
                    if normal_resp.status_code == 200 and sqli_resp.status_code == 200:
                        try:
                            normal_data = normal_resp.json()
                            sqli_data = sqli_resp.json()
                            normal_count = len(normal_data) if isinstance(normal_data, list) else 0
                            sqli_count = len(sqli_data) if isinstance(sqli_data, list) else 0
                            if sqli_count > normal_count and normal_count >= 0:
                                self.add_finding(
                                    title=f"SQL Injection in {sp['path']} ({technique})",
                                    severity="critical",
                                    category="injection",
                                    description=f"The {sp['path']} endpoint is vulnerable to {technique} SQL injection via '{sp['param']}' parameter.",
                                    evidence=f"Payload: {sp['param']}={payload}\nNormal results: {normal_count}, SQLi results: {sqli_count}",
                                    remediation="Use parameterized queries. Never concatenate user input into SQL statements.",
                                    cvss_score=9.8,
                                )
                                return
                        except Exception:
                            pass
                except Exception:
                    continue

    def _check_idor(self):
        """Check for IDOR on ID-based endpoints."""
        for ep in self.crawl_results.get("api_endpoints", []):
            if not ep.get("has_id") or not ep.get("sample_id"):
                continue

            path = ep["path"]
            sample_id = ep["sample_id"]

            # Try accessing different IDs
            test_ids = [1, 2, 3, sample_id + 1 if isinstance(sample_id, int) else 2]

            for test_id in test_ids:
                try:
                    resp = self._make_request("GET", f"{path}/{test_id}")
                    if resp and resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, dict) and "id" in data:
                                self.add_finding(
                                    title="IDOR - Unauthorized Resource Access",
                                    severity="high",
                                    category="authorization",
                                    description=f"Authenticated users can access resources at {path}/{{id}} without ownership verification.",
                                    evidence=f"GET {path}/{test_id} returned 200.\nResponse: {resp.text[:500]}",
                                    remediation="Verify that the authenticated user owns the requested resource. Implement proper access control checks.",
                                    cvss_score=7.5,
                                )
                                return
                        except Exception:
                            pass
                except Exception:
                    continue

        # Try common patterns
        common_id_paths = ["/api/orders", "/api/users", "/api/customers", "/api/items", "/api/v1/orders", "/api/v1/users", "/api/v1/items"]
        for path in common_id_paths:
            for test_id in [1, 2, 3]:
                try:
                    resp = self._make_request("GET", f"{path}/{test_id}")
                    if resp and resp.status_code == 200:
                        try:
                            data = resp.json()
                            if isinstance(data, dict):
                                self.add_finding(
                                    title="IDOR - Unauthorized Resource Access",
                                    severity="high",
                                    category="authorization",
                                    description=f"Resources at {path}/{{id}} are accessible without proper authorization checks.",
                                    evidence=f"GET {path}/{test_id} returned 200.\nResponse: {resp.text[:500]}",
                                    remediation="Verify resource ownership before returning data. Implement proper access control.",
                                    cvss_score=7.5,
                                )
                                return
                        except Exception:
                            pass
                except Exception:
                    continue

    def _check_auth_weakness(self):
        """Check for API key accepted in URL and other auth weaknesses."""
        if not self.api_headers:
            return

        api_key = self.api_headers.get("X-API-Key", "")
        if not api_key:
            return

        # Test all discovered endpoints - try with key in URL instead of header
        for ep in self.crawl_results.get("api_endpoints", []):
            path = ep["path"]
            try:
                # Request with key in URL only (no header)
                resp = requests.get(
                    f"{self.base_url}{path}",
                    params={"api_key": api_key},
                    timeout=10, verify=False
                )
                if resp.status_code == 200:
                    # Verify that without any key it fails
                    no_key_resp = requests.get(
                        f"{self.base_url}{path}",
                        timeout=10, verify=False
                    )
                    if no_key_resp.status_code in (401, 403):
                        self.add_finding(
                            title="API Key Accepted in URL Query Parameter",
                            severity="medium",
                            category="authentication",
                            description=f"API keys are accepted as URL query parameters at {path}, which may be logged in server access logs and browser history.",
                            evidence=f"GET {path}?api_key={api_key} returned 200.\nGET {path} without key returned {no_key_resp.status_code}.\nAPI key visible in URL.",
                            remediation="Only accept API keys in request headers (X-API-Key). Reject keys in query parameters.",
                            cvss_score=5.3,
                        )
                        return
            except requests.RequestException:
                continue

    def _check_rate_limit(self):
        """Check for rate limiting on API endpoints."""
        target_path = None
        for ep in self.crawl_results.get("api_endpoints", []):
            if ep["status"] == 200:
                target_path = ep["path"]
                break

        if not target_path:
            target_path = "/"

        blocked = False
        count = 50
        for i in range(count):
            try:
                resp = self._make_request("GET", target_path)
                if resp and resp.status_code == 429:
                    blocked = True
                    break
            except Exception:
                break

        if not blocked:
            self.add_finding(
                title="No Rate Limiting on API Endpoints",
                severity="medium",
                category="availability",
                description=f"No rate limiting detected after {count} rapid requests to {target_path}.",
                evidence=f"Sent {count} rapid requests to {target_path}. No 429 response received.",
                remediation="Implement rate limiting (e.g., 100 requests/minute per API key). Use API gateway or middleware.",
                cvss_score=5.3,
            )

    def _check_mass_assignment(self):
        """Check for mass assignment on update endpoints."""
        # Find all JSON endpoints that return lists with items that have IDs
        for ep in self.crawl_results.get("api_endpoints", []):
            if not ep.get("is_json") or ep["status"] != 200:
                continue

            path = ep["path"]

            try:
                resp = self._make_request("GET", path)
                if not resp or resp.status_code != 200:
                    continue

                data = resp.json()

                # Need a list of objects with IDs
                if not isinstance(data, list) or len(data) == 0:
                    continue
                if not isinstance(data[0], dict) or "id" not in data[0]:
                    continue

                item_id = data[0]["id"]
                original_data = data[0].copy()

                # Try PUT with malicious fields
                malicious_fields = {"is_admin": 1, "role": "admin", "admin": True, "price": 0.01}

                resp = self._make_request("PUT", f"{path}/{item_id}", json=malicious_fields)
                if not resp or resp.status_code != 200:
                    continue

                try:
                    updated = resp.json()
                    accepted = [k for k, v in malicious_fields.items() if updated.get(k) == v]
                    if accepted:
                        self.add_finding(
                            title="Mass Assignment Vulnerability",
                            severity="high",
                            category="authorization",
                            description=f"The API at {path} accepts and applies unexpected fields ({', '.join(accepted)}) in PUT requests.",
                            evidence=f"PUT {path}/{item_id} with {malicious_fields}\nAccepted: {accepted}\nResponse: {resp.text[:500]}",
                            remediation="Whitelist allowed fields for each endpoint. Reject unexpected fields in request body.",
                            cvss_score=7.5,
                        )

                        # Restore
                        restore = {k: original_data.get(k, 0) for k in accepted}
                        self._make_request("PUT", f"{path}/{item_id}", json=restore)
                        return
                except Exception:
                    pass
            except Exception:
                continue

    def _check_input_validation(self):
        """Check for input validation on POST endpoints."""
        # Find endpoints that accept POST (like order creation)
        post_paths = []

        for ep in self.crawl_results.get("api_endpoints", []):
            path = ep["path"]
            # Try POST on discovered endpoints
            post_paths.append(path)

        # Also try common POST paths
        common_post = ["/api/orders", "/api/v1/orders", "/api/items", "/api/v1/items",
                       "/api/users", "/api/v1/users", "/api/products", "/api/v1/products",
                       "/orders", "/items", "/users", "/products"]
        post_paths.extend(common_post)

        test_cases = [
            ({"item_id": 1, "quantity": -1, "amount": -1}, "negative values"),
            ({"item_id": 1, "quantity": 99999999, "amount": 99999999}, "extreme values"),
            ({"id": "abc", "item_id": "abc", "quantity": "abc"}, "non-numeric values"),
        ]

        for path in post_paths:
            for payload, desc in test_cases:
                try:
                    resp = self._make_request("POST", path, json=payload)
                    if resp and resp.status_code in (200, 201):
                        self.add_finding(
                            title=f"Missing Input Validation ({desc})",
                            severity="low",
                            category="input_validation",
                            description=f"The API at {path} accepted invalid data: {desc}.",
                            evidence=f"POST {path} with {payload}\nResponse: {resp.status_code} {resp.text[:300]}",
                            remediation="Validate all input fields: check types, ranges, and formats. Reject invalid data with 400 status.",
                            cvss_score=3.7,
                        )
                        return
                except Exception:
                    continue

    def _check_cors(self):
        """Check for CORS misconfiguration."""
        for ep in self.crawl_results.get("api_endpoints", []):
            if ep["status"] != 200:
                continue
            try:
                resp = self._make_request("GET", ep["path"], headers={"Origin": "https://evil-attacker.com"})
                if not resp:
                    continue

                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                if acao == "*":
                    self.add_finding(
                        title="CORS Misconfiguration - Wildcard Origin",
                        severity="medium",
                        category="configuration",
                        description=f"The API at {ep['path']} allows requests from any origin (Access-Control-Allow-Origin: *).",
                        evidence=f"GET {ep['path']} with Origin: https://evil-attacker.com\nResponse: Access-Control-Allow-Origin: {acao}",
                        remediation="Restrict CORS to trusted domains only. Never use wildcard (*) with credentials.",
                        cvss_score=5.3,
                    )
                    return
                elif "evil-attacker.com" in acao:
                    self.add_finding(
                        title="CORS Misconfiguration - Origin Reflection",
                        severity="high",
                        category="configuration",
                        description=f"The API at {ep['path']} reflects the Origin header in Access-Control-Allow-Origin.",
                        evidence=f"GET {ep['path']} with Origin: https://evil-attacker.com\nResponse: Access-Control-Allow-Origin: {acao}",
                        remediation="Do not reflect the Origin header. Whitelist specific trusted domains.",
                        cvss_score=7.5,
                    )
                    return
            except Exception:
                continue

    def _check_security_headers(self):
        """Check for missing security headers on API responses."""
        for ep in self.crawl_results.get("api_endpoints", []):
            if ep["status"] != 200:
                continue
            try:
                resp = self._make_request("GET", ep["path"])
                if not resp:
                    continue

                headers = resp.headers
                missing = []

                if "X-Content-Type-Options" not in headers:
                    missing.append("X-Content-Type-Options")
                if "X-Frame-Options" not in headers:
                    missing.append("X-Frame-Options")
                if "Strict-Transport-Security" not in headers:
                    missing.append("Strict-Transport-Security")
                if "Cache-Control" not in headers:
                    missing.append("Cache-Control (sensitive data may be cached)")

                if len(missing) >= 2:
                    self.add_finding(
                        title="Missing Security Headers on API",
                        severity="low",
                        category="configuration",
                        description=f"API responses from {ep['path']} are missing important security headers.",
                        evidence=f"GET {ep['path']}\nMissing: {', '.join(missing)}",
                        remediation="Add X-Content-Type-Options: nosniff, X-Frame-Options: DENY, Cache-Control: no-store for sensitive endpoints.",
                        cvss_score=3.7,
                    )
                    return
            except Exception:
                continue
