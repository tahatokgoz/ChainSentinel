import logging
import socket

import requests

from scanners.base import BaseScanner
from scanners.nmap_wrapper import NmapScanner

logger = logging.getLogger(__name__)


class IoTScanner(BaseScanner):
    def run(self) -> list[dict]:
        logger.info(f"Starting IoT scan on {self.base_url}")
        self._check_open_ports()
        self._check_default_credentials()
        self._check_telnet_credentials()
        self._check_unauth_data()
        self._check_device_info()
        self._check_command_injection()
        logger.info(f"IoT scan complete. {len(self.findings)} findings.")
        return self.findings

    def _check_open_ports(self):
        nm = NmapScanner()
        results = nm.scan_ports(self.target_host, f"{self.target_port},2323")

        if results:
            open_ports = [p for p, info in results.items() if info["state"] == "open"]
            if open_ports:
                self.add_finding(
                    title="Open Ports Detected on IoT Device",
                    severity="medium",
                    category="network",
                    description=f"The IoT device has {len(open_ports)} open port(s) exposed to the network.",
                    evidence=f"Open ports: {', '.join(str(p) for p in open_ports)}\nDetails: {results}",
                    remediation="Close unnecessary ports. Use firewall rules to restrict access to management interfaces.",
                    cvss_score=5.3,
                )

    def _check_default_credentials(self):
        creds = [
            ("admin", "admin"),
            ("root", "root"),
            ("admin", "password"),
            ("technician", "tech123"),
        ]

        for username, password in creds:
            try:
                resp = requests.post(
                    f"{self.base_url}/admin",
                    data={"username": username, "password": password},
                    timeout=10,
                )
                if resp.status_code == 200 and "authenticated" in resp.text.lower():
                    self.add_finding(
                        title="Default Credentials Accepted (HTTP)",
                        severity="critical",
                        category="authentication",
                        description=f"The IoT device admin panel accepts default credentials: {username}:{password}",
                        evidence=f"POST /admin with {username}:{password} returned 200.\nResponse: {resp.text[:500]}",
                        remediation="Change all default passwords immediately. Implement account lockout after failed attempts.",
                        cvss_score=9.8,
                    )
                    return  # One finding is enough
            except requests.RequestException as e:
                logger.warning(f"HTTP credential check failed: {e}")

    def _check_telnet_credentials(self):
        creds = [("admin", "admin"), ("root", "root")]

        for username, password in creds:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.target_host, 2323))

                banner = sock.recv(1024).decode(errors="ignore")
                sock.sendall(f"{username}\n".encode())
                sock.recv(1024)  # Password prompt
                sock.sendall(f"{password}\n".encode())
                response = sock.recv(1024).decode(errors="ignore")
                sock.close()

                if "welcome" in response.lower() or "successful" in response.lower():
                    self.add_finding(
                        title="Default Credentials Accepted (Telnet)",
                        severity="critical",
                        category="authentication",
                        description=f"Telnet service on port 2323 accepts default credentials: {username}:{password}",
                        evidence=f"Banner: {banner.strip()}\nLogin response: {response.strip()}",
                        remediation="Disable Telnet. Use SSH with key-based authentication instead.",
                        cvss_score=9.8,
                    )
                    return
            except (socket.error, socket.timeout) as e:
                logger.warning(f"Telnet check failed: {e}")

    def _check_unauth_data(self):
        try:
            resp = requests.get(f"{self.base_url}/api/sensor-data", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                self.add_finding(
                    title="Unauthenticated Access to Sensor Data",
                    severity="high",
                    category="authorization",
                    description="Sensor data endpoint is accessible without any authentication.",
                    evidence=f"GET /api/sensor-data returned 200.\nData keys: {list(data.keys())}",
                    remediation="Require authentication for all data endpoints. Implement API key or token-based auth.",
                    cvss_score=7.5,
                )
        except requests.RequestException as e:
            logger.warning(f"Sensor data check failed: {e}")

    def _check_device_info(self):
        try:
            resp = requests.get(f"{self.base_url}/device-info", timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                sensitive_fields = [k for k in data if k in (
                    "firmware_version", "mac_address", "internal_ip",
                    "gateway_ip", "serial_number", "admin_email"
                )]
                if sensitive_fields:
                    self.add_finding(
                        title="Sensitive Device Information Disclosure",
                        severity="medium",
                        category="information_disclosure",
                        description="The device exposes sensitive internal information without authentication.",
                        evidence=f"GET /device-info exposed: {', '.join(sensitive_fields)}\nResponse: {resp.text[:500]}",
                        remediation="Remove or restrict access to device information endpoints. Require admin authentication.",
                        cvss_score=5.3,
                    )
        except requests.RequestException as e:
            logger.warning(f"Device info check failed: {e}")

    def _check_command_injection(self):
        try:
            resp = requests.post(
                f"{self.base_url}/api/diagnostic",
                json={"cmd": "echo chainsentinel_test_marker"},
                timeout=10,
            )
            if resp.status_code == 200 and "chainsentinel_test_marker" in resp.text:
                self.add_finding(
                    title="Command Injection Vulnerability",
                    severity="critical",
                    category="injection",
                    description="The diagnostic endpoint executes arbitrary system commands.",
                    evidence=f"POST /api/diagnostic with cmd='echo chainsentinel_test_marker'\nResponse: {resp.text[:500]}",
                    remediation="Never pass user input to shell commands. Use parameterized APIs or whitelisted commands only.",
                    cvss_score=10.0,
                )
        except requests.RequestException as e:
            logger.warning(f"Command injection check failed: {e}")
