import logging

import requests

from scanners.base import BaseScanner

logger = logging.getLogger(__name__)

API_KEY = "test-key-001"


class APIScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting API scan on {self.base_url}")
        self._check_sqli_search()
        self._check_idor()
        self._check_key_in_url()
        self._check_rate_limit()
        self._check_mass_assignment()
        self._check_input_validation()
        logger.info(f"API scan complete. {len(self.findings)} findings.")
        return self.findings

    def _headers(self):
        return {"X-API-Key": API_KEY}

    def _check_sqli_search(self):
        payloads = [
            ("' OR '1'='1", "boolean-based"),
            ("' UNION SELECT sql,2,3,4,5,6,7 FROM sqlite_master--", "union-based"),
        ]

        for payload, technique in payloads:
            try:
                # Normal request for baseline
                normal_resp = requests.get(
                    f"{self.base_url}/api/v1/items",
                    headers=self._headers(),
                    params={"search": "Scanner"},
                    timeout=10,
                )
                normal_count = len(normal_resp.json()) if normal_resp.status_code == 200 else 0

                # SQLi request
                sqli_resp = requests.get(
                    f"{self.base_url}/api/v1/items",
                    headers=self._headers(),
                    params={"search": payload},
                    timeout=10,
                )

                if sqli_resp.status_code == 200:
                    sqli_data = sqli_resp.json()
                    if len(sqli_data) > normal_count or (technique == "union-based" and "CREATE TABLE" in sqli_resp.text):
                        self.add_finding(
                            title=f"SQL Injection in Search ({technique})",
                            severity="critical",
                            category="injection",
                            description=f"The /api/v1/items search endpoint is vulnerable to {technique} SQL injection.",
                            evidence=f"Payload: search={payload}\nNormal results: {normal_count}, SQLi results: {len(sqli_data)}\nResponse: {sqli_resp.text[:500]}",
                            remediation="Use parameterized queries. Never concatenate user input into SQL statements.",
                            cvss_score=9.8,
                        )
                        return
            except requests.RequestException as e:
                logger.warning(f"SQLi search check failed: {e}")

    def _check_idor(self):
        # API key test-key-001 belongs to customer_id=1
        # Try to access orders belonging to other customers
        try:
            own_order = requests.get(
                f"{self.base_url}/api/v1/orders/1",
                headers=self._headers(),
                timeout=10,
            )
            other_order = requests.get(
                f"{self.base_url}/api/v1/orders/3",
                headers=self._headers(),
                timeout=10,
            )

            if own_order.status_code == 200 and other_order.status_code == 200:
                other_data = other_order.json()
                if other_data.get("customer_id") != 1:
                    self.add_finding(
                        title="IDOR - Unauthorized Order Access",
                        severity="high",
                        category="authorization",
                        description="Authenticated users can access orders belonging to other customers by changing the order ID.",
                        evidence=f"Customer 1 accessed order 3 (belongs to customer {other_data.get('customer_id')}).\nResponse: {other_order.text[:500]}",
                        remediation="Verify that the authenticated user owns the requested resource. Implement proper access control checks.",
                        cvss_score=7.5,
                    )
        except requests.RequestException as e:
            logger.warning(f"IDOR check failed: {e}")

    def _check_key_in_url(self):
        try:
            resp = requests.get(
                f"{self.base_url}/api/v1/items",
                params={"api_key": API_KEY},
                timeout=10,
            )
            if resp.status_code == 200:
                self.add_finding(
                    title="API Key Accepted in URL Query Parameter",
                    severity="medium",
                    category="authentication",
                    description="API keys are accepted as URL query parameters, which may be logged in server access logs and browser history.",
                    evidence=f"GET /api/v1/items?api_key={API_KEY} returned 200.\nAPI key visible in URL.",
                    remediation="Only accept API keys in request headers (X-API-Key). Reject keys in query parameters.",
                    cvss_score=5.3,
                )
        except requests.RequestException as e:
            logger.warning(f"Key in URL check failed: {e}")

    def _check_rate_limit(self):
        blocked = False
        count = 50

        for i in range(count):
            try:
                resp = requests.get(
                    f"{self.base_url}/api/v1/items",
                    headers=self._headers(),
                    timeout=5,
                )
                if resp.status_code == 429:
                    blocked = True
                    break
            except requests.RequestException:
                break

        if not blocked:
            self.add_finding(
                title="No Rate Limiting on API Endpoints",
                severity="medium",
                category="availability",
                description=f"No rate limiting detected after {count} rapid requests to the API.",
                evidence=f"Sent {count} rapid GET /api/v1/items requests. No 429 response received.",
                remediation="Implement rate limiting (e.g., 100 requests/minute per API key). Use API gateway or middleware.",
                cvss_score=5.3,
            )

    def _check_mass_assignment(self):
        try:
            # Try to set is_admin field
            resp = requests.put(
                f"{self.base_url}/api/v1/items/1",
                headers=self._headers(),
                json={"is_admin": 1, "price": 0.01},
                timeout=10,
            )
            if resp.status_code == 200:
                data = resp.json()
                if data.get("is_admin") == 1 or data.get("price") == 0.01:
                    self.add_finding(
                        title="Mass Assignment Vulnerability",
                        severity="high",
                        category="authorization",
                        description="The API accepts and applies unexpected fields (is_admin, price) in PUT requests.",
                        evidence=f"PUT /api/v1/items/1 with is_admin=1, price=0.01\nResponse: {resp.text[:500]}",
                        remediation="Whitelist allowed fields for each endpoint. Reject unexpected fields in request body.",
                        cvss_score=7.5,
                    )

                # Restore original values
                requests.put(
                    f"{self.base_url}/api/v1/items/1",
                    headers=self._headers(),
                    json={"is_admin": 0, "price": 299.99},
                    timeout=10,
                )
        except requests.RequestException as e:
            logger.warning(f"Mass assignment check failed: {e}")

    def _check_input_validation(self):
        test_cases = [
            ({"item_id": 1, "quantity": -1}, "negative quantity"),
            ({"item_id": 1, "quantity": 99999999}, "extreme quantity"),
            ({"item_id": "abc", "quantity": 1}, "non-numeric item_id"),
        ]

        for payload, desc in test_cases:
            try:
                resp = requests.post(
                    f"{self.base_url}/api/v1/orders",
                    headers=self._headers(),
                    json=payload,
                    timeout=10,
                )
                if resp.status_code == 201:
                    self.add_finding(
                        title=f"Missing Input Validation ({desc})",
                        severity="low",
                        category="input_validation",
                        description=f"The API accepted an order with invalid data: {desc}.",
                        evidence=f"POST /api/v1/orders with {payload}\nResponse: {resp.status_code} {resp.text[:300]}",
                        remediation="Validate all input fields: check types, ranges, and formats. Reject invalid data with 400 status.",
                        cvss_score=3.7,
                    )
                    return  # One finding is enough
            except requests.RequestException as e:
                logger.warning(f"Input validation check failed: {e}")
