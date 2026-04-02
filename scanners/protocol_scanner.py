import logging
import socket
import struct

logger = logging.getLogger(__name__)


class ProtocolScanner:
    """Scanner for industrial and warehouse-specific protocols: Modbus, SNMP, FTP, DNS."""

    def __init__(self, target_host: str):
        self.target_host = target_host
        self.findings = []

    def run(self) -> list[dict]:
        logger.info(f"Starting protocol scan on {self.target_host}")

        self._check_modbus(502)
        self._check_modbus(5020)
        self._check_snmp()
        self._check_ftp()
        self._check_dns_zone_transfer()
        self._check_open_redirect()
        self._check_ssl_tls()

        logger.info(f"Protocol scan complete. {len(self.findings)} findings.")
        return self.findings

    def add_finding(self, **kwargs):
        self.findings.append(kwargs)

    def _check_modbus(self, port: int = 502):
        """Check for unauthenticated Modbus access."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_host, port))
            if result != 0:
                sock.close()
                return

            # Modbus TCP: Read Holding Registers (Function Code 0x03)
            modbus_read = bytes([
                0x00, 0x01,  # Transaction ID
                0x00, 0x00,  # Protocol ID (Modbus)
                0x00, 0x06,  # Length
                0x01,        # Unit ID
                0x03,        # Function Code: Read Holding Registers
                0x00, 0x00,  # Start Address
                0x00, 0x0A,  # Quantity (10 registers)
            ])

            sock.sendall(modbus_read)
            response = sock.recv(256)
            sock.close()

            if len(response) >= 9:
                function_code = response[7]
                if function_code == 0x03:  # Normal response
                    byte_count = response[8]
                    register_data = response[9:9+byte_count]

                    self.add_finding(
                        title=f"Modbus Unauthenticated Access (Port {port})",
                        severity="critical",
                        category="authentication",
                        description=f"Modbus TCP on port {port} allows reading holding registers without authentication. Attackers can read/write PLC data controlling warehouse automation (conveyor belts, sorting systems, temperature controls).",
                        evidence=f"Modbus Read Holding Registers (FC 0x03) on {self.target_host}:{port}\nResponse: {response.hex()}\nRegister data: {register_data.hex() if register_data else 'empty'}",
                        remediation="Implement Modbus security: use VPN/firewall for Modbus traffic, deploy Modbus-aware IDS, segment industrial network from IT network.",
                        cvss_score=9.8,
                    )
                elif function_code == 0x83:  # Exception response
                    exception_code = response[8] if len(response) > 8 else 0
                    if exception_code not in (0x01, 0x04):
                        self.add_finding(
                            title=f"Modbus Service Detected (Port {port})",
                            severity="medium",
                            category="network",
                            description=f"Modbus TCP service detected on port {port}. While read was denied, the service is accessible from the network.",
                            evidence=f"Modbus exception response on {self.target_host}:{port}\nException code: {exception_code}",
                            remediation="Restrict Modbus access to authorized systems only. Use network segmentation.",
                            cvss_score=5.3,
                        )
        except (socket.error, socket.timeout):
            pass

    def _check_snmp(self, port: int = 161):
        """Check for SNMP default community strings."""
        community_strings = ["public", "private", "community", "default", "admin", "manager", "monitor"]

        for community in community_strings:
            try:
                community_bytes = community.encode()

                # OID: 1.3.6.1.2.1.1.1.0 (sysDescr.0)
                oid = bytes([0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00])

                # VarBind
                varbind = bytes([0x30, len(oid) + 2, *oid, 0x05, 0x00])
                varbind_list = bytes([0x30, len(varbind), *varbind])

                # PDU (GET-REQUEST)
                request_id = bytes([0x02, 0x01, 0x01])
                error_status = bytes([0x02, 0x01, 0x00])
                error_index = bytes([0x02, 0x01, 0x00])

                pdu_content = request_id + error_status + error_index + varbind_list
                pdu = bytes([0xA0, len(pdu_content), *pdu_content])

                # Message
                version = bytes([0x02, 0x01, 0x00])  # SNMPv1
                community_tlv = bytes([0x04, len(community_bytes), *community_bytes])

                message_content = version + community_tlv + pdu
                message = bytes([0x30, len(message_content), *message_content])

                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.settimeout(3)
                sock.sendto(message, (self.target_host, port))

                data, addr = sock.recvfrom(65535)
                sock.close()

                if data and len(data) > 2:
                    decoded_info = data.decode(errors='ignore')

                    self.add_finding(
                        title=f"SNMP Default Community String: '{community}'",
                        severity="high",
                        category="authentication",
                        description=f"SNMP service accepts the community string '{community}'. Attackers can enumerate device information, network configuration, and potentially modify settings on warehouse network devices.",
                        evidence=f"SNMP GET sysDescr.0 with community '{community}' on {self.target_host}:{port}\nResponse received: {len(data)} bytes\nDevice info: {decoded_info[:200]}",
                        remediation="Change SNMP community strings to complex values. Disable SNMPv1/v2c, use SNMPv3 with authentication and encryption. Restrict SNMP access by IP.",
                        cvss_score=7.5,
                    )
                    return
            except (socket.error, socket.timeout):
                continue

    def _check_ftp(self, port: int = 21):
        """Check for FTP anonymous access and default credentials."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_host, port))
            if result != 0:
                sock.close()
                return

            banner = sock.recv(1024).decode(errors='ignore')

            # Try anonymous login
            sock.sendall(b'USER anonymous\r\n')
            resp = sock.recv(1024).decode(errors='ignore')

            if '331' in resp:
                sock.sendall(b'PASS anonymous@\r\n')
                resp = sock.recv(1024).decode(errors='ignore')

                if '230' in resp:
                    sock.sendall(b'QUIT\r\n')
                    sock.close()

                    self.add_finding(
                        title="FTP Anonymous Access Allowed",
                        severity="high",
                        category="authentication",
                        description="FTP server allows anonymous login. In warehouse environments, FTP is often used for transferring inventory data, shipping labels, and system backups.",
                        evidence=f"FTP banner: {banner.strip()}\nUSER anonymous → 331\nPASS anonymous@ → 230 (Login successful)",
                        remediation="Disable anonymous FTP access. Use SFTP instead of FTP. Require strong authentication.",
                        cvss_score=7.5,
                    )
                    return

            sock.close()

            # Try default credentials
            creds = [("admin", "admin"), ("ftp", "ftp"), ("user", "user"), ("root", "root")]
            for username, password in creds:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(5)
                    sock.connect((self.target_host, port))
                    sock.recv(1024)

                    sock.sendall(f'USER {username}\r\n'.encode())
                    sock.recv(1024)
                    sock.sendall(f'PASS {password}\r\n'.encode())
                    resp = sock.recv(1024).decode(errors='ignore')

                    if '230' in resp:
                        sock.sendall(b'QUIT\r\n')
                        sock.close()

                        self.add_finding(
                            title="FTP Default Credentials",
                            severity="critical",
                            category="authentication",
                            description=f"FTP server accepts default credentials: {username}:{password}",
                            evidence=f"FTP login with {username}:{password} → 230 (Login successful)",
                            remediation="Change all default FTP passwords. Consider replacing FTP with SFTP.",
                            cvss_score=9.8,
                        )
                        return
                    sock.close()
                except (socket.error, socket.timeout):
                    continue
        except (socket.error, socket.timeout):
            pass

    def _check_dns_zone_transfer(self, port: int = 53):
        """Check if DNS allows zone transfer."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            result = sock.connect_ex((self.target_host, port))
            if result != 0:
                sock.close()
                return

            query = bytes([
                0x00, 0x1C,  # Length (TCP)
                0xAA, 0xBB,  # Transaction ID
                0x00, 0x00,  # Flags: Standard query
                0x00, 0x01,  # Questions: 1
                0x00, 0x00,  # Answers: 0
                0x00, 0x00,  # Authority: 0
                0x00, 0x00,  # Additional: 0
                # Query: local
                0x05, 0x6C, 0x6F, 0x63, 0x61, 0x6C,  # "local"
                0x00,        # Root
                0x00, 0xFC,  # Type: AXFR
                0x00, 0x01,  # Class: IN
            ])

            sock.sendall(query)
            response = sock.recv(1024)
            sock.close()

            if len(response) > 12:
                flags = struct.unpack('!H', response[4:6])[0] if len(response) > 6 else 0
                rcode = flags & 0x0F

                if rcode == 0:
                    self.add_finding(
                        title="DNS Zone Transfer Allowed",
                        severity="medium",
                        category="information_disclosure",
                        description="DNS server allows zone transfers, potentially revealing internal hostnames, IP addresses, and network structure of the warehouse network.",
                        evidence=f"AXFR query to {self.target_host}:{port}\nResponse: {len(response)} bytes, RCODE: {rcode}",
                        remediation="Restrict zone transfers to authorized secondary DNS servers only.",
                        cvss_score=5.3,
                    )
        except (socket.error, socket.timeout):
            pass

    def _check_open_redirect(self):
        """Check for open redirect on web services."""
        import requests

        common_ports = [80, 443, 8080, 8443, 9081, 9082, 9083]

        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((self.target_host, port))
                sock.close()
                if result != 0:
                    continue

                scheme = "https" if port in (443, 8443) else "http"
                base_url = f"{scheme}://{self.target_host}:{port}"

                redirect_params = ["url", "redirect", "next", "return", "returnTo", "redirect_uri", "continue", "dest"]
                evil_url = "https://evil-attacker.com"

                for param in redirect_params:
                    for path in ["/login", "/logout", "/auth", "/", "/redirect"]:
                        try:
                            resp = requests.get(
                                f"{base_url}{path}",
                                params={param: evil_url},
                                allow_redirects=False,
                                timeout=5,
                                verify=False
                            )

                            if resp.status_code in (301, 302, 303, 307, 308):
                                location = resp.headers.get("Location", "")
                                if "evil-attacker.com" in location:
                                    self.add_finding(
                                        title=f"Open Redirect (Port {port})",
                                        severity="medium",
                                        category="injection",
                                        description=f"The application at port {port} redirects to external URLs via '{param}' parameter, enabling phishing attacks against warehouse staff.",
                                        evidence=f"GET {base_url}{path}?{param}={evil_url}\nLocation: {location}",
                                        remediation="Validate redirect URLs. Only allow redirects to trusted internal domains.",
                                        cvss_score=4.7,
                                    )
                                    return
                        except requests.RequestException:
                            continue
            except socket.error:
                continue

    def _check_ssl_tls(self):
        """Check SSL/TLS configuration on HTTPS services."""
        import ssl
        import datetime

        https_ports = [443, 8443, 9443]
        # Also check common HTTP ports for missing SSL
        http_ports = [80, 8080, 8081, 8082, 8083, 9081, 9082, 9083]

        # Check HTTP services without SSL
        http_only_services = []
        for port in http_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target_host, port))
                sock.close()
                if result == 0:
                    http_only_services.append(port)
            except socket.error:
                pass

        if http_only_services:
            # Verify these are actually HTTP (not HTTPS)
            import requests
            confirmed_http = []
            for port in http_only_services:
                try:
                    resp = requests.get(f"http://{self.target_host}:{port}/", timeout=3, verify=False)
                    if resp.status_code < 500:
                        confirmed_http.append(port)
                except:
                    pass

            if confirmed_http:
                self.add_finding(
                    title="Unencrypted HTTP Services Detected",
                    severity="medium",
                    category="configuration",
                    description=f"Services on ports {', '.join(str(p) for p in confirmed_http)} use unencrypted HTTP. Warehouse data including credentials, inventory data, and sensor readings are transmitted in plaintext.",
                    evidence=f"HTTP services found on: {', '.join(str(p) for p in confirmed_http)}\nNo TLS/SSL encryption detected on these ports.",
                    remediation="Enable HTTPS on all web services. Use TLS 1.2 or higher. Redirect HTTP to HTTPS.",
                    cvss_score=5.3,
                )

        # Check HTTPS services for weak configuration
        for port in https_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                result = sock.connect_ex((self.target_host, port))
                if result != 0:
                    sock.close()
                    continue
                sock.close()

                # Get certificate info
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE

                conn = context.wrap_socket(
                    socket.socket(socket.AF_INET, socket.SOCK_STREAM),
                    server_hostname=self.target_host
                )
                conn.settimeout(5)
                conn.connect((self.target_host, port))

                cert = conn.getpeercert(binary_form=False)
                cert_bin = conn.getpeercert(binary_form=True)
                protocol_version = conn.version()
                cipher = conn.cipher()

                conn.close()

                issues = []

                # Check protocol version
                if protocol_version and protocol_version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
                    issues.append(f"Weak protocol: {protocol_version} (should be TLSv1.2+)")

                # Check cipher strength
                if cipher:
                    cipher_name = cipher[0]
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'NULL', 'EXPORT', 'anon']
                    if any(weak in cipher_name.upper() for weak in weak_ciphers):
                        issues.append(f"Weak cipher: {cipher_name}")

                # Check certificate expiry
                if cert:
                    not_after = cert.get('notAfter', '')
                    if not_after:
                        try:
                            expiry = datetime.datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            days_left = (expiry - datetime.datetime.utcnow()).days
                            if days_left < 0:
                                issues.append(f"Certificate EXPIRED ({abs(days_left)} days ago)")
                            elif days_left < 30:
                                issues.append(f"Certificate expiring soon ({days_left} days)")
                        except ValueError:
                            pass

                    # Check self-signed
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    if issuer == subject:
                        issues.append("Self-signed certificate")

                if issues:
                    self.add_finding(
                        title=f"SSL/TLS Configuration Issues (Port {port})",
                        severity="medium" if "EXPIRED" in str(issues) or "Weak protocol" in str(issues) else "low",
                        category="configuration",
                        description=f"SSL/TLS on port {port} has configuration issues that could compromise encryption security.",
                        evidence=f"Port: {port}\nProtocol: {protocol_version}\nCipher: {cipher[0] if cipher else 'unknown'}\nIssues:\n" + "\n".join(f"- {i}" for i in issues),
                        remediation="Use TLS 1.2+. Disable weak ciphers. Use certificates from trusted CAs. Monitor certificate expiry.",
                        cvss_score=5.3,
                    )
                    return
            except (ssl.SSLError, socket.error, socket.timeout, Exception):
                continue

        # Try weak TLS versions explicitly
        for port in https_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target_host, port))
                if result != 0:
                    sock.close()
                    continue
                sock.close()

                # Try TLSv1.0
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.maximum_version = ssl.TLSVersion.TLSv1
                    context.minimum_version = ssl.TLSVersion.TLSv1

                    conn = context.wrap_socket(socket.socket(), server_hostname=self.target_host)
                    conn.settimeout(5)
                    conn.connect((self.target_host, port))
                    conn.close()

                    self.add_finding(
                        title=f"Weak TLS Version Supported (Port {port})",
                        severity="medium",
                        category="configuration",
                        description=f"Port {port} supports TLSv1.0 which is deprecated and vulnerable to POODLE and BEAST attacks.",
                        evidence=f"Successfully connected to {self.target_host}:{port} using TLSv1.0",
                        remediation="Disable TLSv1.0 and TLSv1.1. Only allow TLSv1.2 and TLSv1.3.",
                        cvss_score=5.3,
                    )
                    return
                except (ssl.SSLError, Exception):
                    pass
            except (socket.error, socket.timeout):
                continue
