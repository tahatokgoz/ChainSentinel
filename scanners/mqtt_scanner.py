import logging
import socket
import struct
import time

logger = logging.getLogger(__name__)


class MQTTScanner:
    """Scanner for MQTT broker security on warehouse IoT systems."""

    MQTT_PORTS = [1883, 8883, 1884, 8884]

    def __init__(self, target_host: str, target_port: int = 1883):
        self.target_host = target_host
        self.target_port = target_port
        self.findings = []

    def run(self) -> list[dict]:
        logger.info(f"Starting MQTT scan on {self.target_host}")

        # Find MQTT ports
        self.mqtt_ports = self._find_mqtt_ports()
        if not self.mqtt_ports:
            logger.info("No MQTT ports found.")
            return self.findings

        for port in self.mqtt_ports:
            self._check_anonymous_access(port)
            self._check_default_credentials(port)
            self._check_topic_enumeration(port)
            self._check_version_disclosure(port)

        logger.info(f"MQTT scan complete. {len(self.findings)} findings.")
        return self.findings

    def add_finding(self, **kwargs):
        self.findings.append(kwargs)

    def _find_mqtt_ports(self) -> list:
        """Find open MQTT ports."""
        open_ports = []
        for port in self.MQTT_PORTS:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((self.target_host, port))
                if result == 0:
                    open_ports.append(port)
                sock.close()
            except socket.error:
                pass
        return open_ports

    def _build_connect_packet(self, client_id: str = "ChainSentinel", username: str = None, password: str = None) -> bytes:
        """Build MQTT CONNECT packet."""
        # Variable header
        protocol_name = b'\x00\x04MQTT'
        protocol_level = b'\x04'  # MQTT 3.1.1

        connect_flags = 0x02  # Clean session
        if username:
            connect_flags |= 0x80  # Username flag
        if password:
            connect_flags |= 0x40  # Password flag

        connect_flags_byte = struct.pack('!B', connect_flags)
        keep_alive = struct.pack('!H', 60)

        # Payload
        client_id_bytes = struct.pack('!H', len(client_id)) + client_id.encode()

        payload = client_id_bytes
        if username:
            payload += struct.pack('!H', len(username)) + username.encode()
        if password:
            payload += struct.pack('!H', len(password)) + password.encode()

        variable_header = protocol_name + protocol_level + connect_flags_byte + keep_alive
        remaining = variable_header + payload

        # Fixed header
        packet_type = 0x10  # CONNECT
        remaining_length = len(remaining)

        fixed_header = struct.pack('!B', packet_type)

        # Encode remaining length
        rl_bytes = b''
        while remaining_length > 0:
            byte = remaining_length % 128
            remaining_length //= 128
            if remaining_length > 0:
                byte |= 0x80
            rl_bytes += struct.pack('!B', byte)
        if not rl_bytes:
            rl_bytes = b'\x00'

        return fixed_header + rl_bytes + remaining

    def _build_subscribe_packet(self, topic: str, packet_id: int = 1) -> bytes:
        """Build MQTT SUBSCRIBE packet."""
        # Variable header
        variable_header = struct.pack('!H', packet_id)

        # Payload
        payload = struct.pack('!H', len(topic)) + topic.encode() + b'\x00'  # QoS 0

        remaining = variable_header + payload

        # Fixed header
        fixed_header = struct.pack('!B', 0x82)  # SUBSCRIBE with QoS 1
        remaining_length = len(remaining)

        rl_bytes = b''
        while remaining_length > 0:
            byte = remaining_length % 128
            remaining_length //= 128
            if remaining_length > 0:
                byte |= 0x80
            rl_bytes += struct.pack('!B', byte)

        return fixed_header + rl_bytes + remaining

    def _try_connect(self, port: int, username: str = None, password: str = None) -> tuple:
        """Try MQTT connection, return (success, connack_bytes)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, port))

            connect_packet = self._build_connect_packet(
                client_id=f"ChainSentinel_{int(time.time())}",
                username=username,
                password=password
            )
            sock.sendall(connect_packet)

            response = sock.recv(4)
            sock.close()

            if len(response) >= 4 and response[0] == 0x20:  # CONNACK
                return_code = response[3]
                return (return_code == 0, response)
            return (False, response)
        except (socket.error, socket.timeout, Exception):
            return (False, b'')

    def _check_anonymous_access(self, port: int):
        """Check if MQTT broker allows anonymous connections."""
        success, response = self._try_connect(port)
        if success:
            self.add_finding(
                title=f"MQTT Anonymous Access (Port {port})",
                severity="critical",
                category="authentication",
                description=f"MQTT broker on port {port} allows connections without authentication. Attackers can subscribe to all topics and publish malicious data to warehouse sensors.",
                evidence=f"CONNECT to {self.target_host}:{port} without credentials.\nCONNACK return code: 0 (Connection Accepted)",
                remediation="Enable MQTT authentication. Require username/password for all connections. Use ACLs to restrict topic access.",
                cvss_score=9.1,
            )

    def _check_default_credentials(self, port: int):
        """Check for default MQTT credentials."""
        creds = [
            ("admin", "admin"), ("admin", "password"), ("admin", "public"),
            ("mqtt", "mqtt"), ("user", "user"), ("guest", "guest"),
            ("mosquitto", "mosquitto"), ("admin", "broker"),
            ("root", "root"), ("admin", "1234"),
        ]

        for username, password in creds:
            success, response = self._try_connect(port, username, password)
            if success:
                # Check if anonymous already reported
                if any("Anonymous" in f.get("title", "") and str(port) in f.get("title", "") for f in self.findings):
                    return

                self.add_finding(
                    title=f"MQTT Default Credentials (Port {port})",
                    severity="critical",
                    category="authentication",
                    description=f"MQTT broker on port {port} accepts default credentials: {username}:{password}",
                    evidence=f"CONNECT to {self.target_host}:{port} with {username}:{password}\nCONNACK return code: 0 (Connection Accepted)",
                    remediation="Change all default MQTT passwords. Use strong, unique credentials.",
                    cvss_score=9.8,
                )
                return

    def _check_topic_enumeration(self, port: int):
        """Check if wildcard topic subscription is allowed."""
        success, _ = self._try_connect(port)
        if not success:
            # Try with default creds
            for u, p in [("admin", "admin"), ("mqtt", "mqtt")]:
                success, _ = self._try_connect(port, u, p)
                if success:
                    break

        if not success:
            return

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((self.target_host, port))

            connect_packet = self._build_connect_packet(client_id=f"CS_enum_{int(time.time())}")
            sock.sendall(connect_packet)
            connack = sock.recv(4)

            if len(connack) < 4 or connack[3] != 0:
                sock.close()
                return

            # Subscribe to wildcard topic
            subscribe_packet = self._build_subscribe_packet("#")
            sock.sendall(subscribe_packet)

            suback = sock.recv(5)
            if len(suback) >= 5 and suback[0] == 0x90:  # SUBACK
                granted_qos = suback[4]
                if granted_qos != 0x80:  # Not failure
                    # Wait for any messages
                    sock.settimeout(3)
                    try:
                        data = sock.recv(1024)
                        if len(data) > 0:
                            self.add_finding(
                                title=f"MQTT Wildcard Subscription Allowed (Port {port})",
                                severity="high",
                                category="authorization",
                                description=f"MQTT broker allows subscribing to wildcard topic '#', exposing all warehouse sensor data, inventory updates, and system messages.",
                                evidence=f"SUBSCRIBE to '#' on {self.target_host}:{port}\nSUBACK granted QoS: {granted_qos}\nReceived {len(data)} bytes of data.",
                                remediation="Implement MQTT ACLs. Restrict wildcard subscriptions. Use topic-level access control.",
                                cvss_score=7.5,
                            )
                    except socket.timeout:
                        # No messages but subscription was accepted
                        self.add_finding(
                            title=f"MQTT Wildcard Subscription Allowed (Port {port})",
                            severity="high",
                            category="authorization",
                            description=f"MQTT broker accepts wildcard topic subscription '#'. This could expose all warehouse data.",
                            evidence=f"SUBSCRIBE to '#' accepted.\nSUBACK granted QoS: {granted_qos}",
                            remediation="Implement MQTT ACLs. Restrict wildcard subscriptions.",
                            cvss_score=7.5,
                        )

            sock.close()
        except (socket.error, socket.timeout, Exception):
            pass

    def _check_version_disclosure(self, port: int):
        """Check if MQTT broker reveals version information."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.target_host, port))

            # Send a malformed packet to trigger error response
            sock.sendall(b'\x10\x00')
            response = sock.recv(256)
            sock.close()

            if response and len(response) > 4:
                decoded = response.decode(errors='ignore')
                version_keywords = ['mosquitto', 'emqx', 'hivemq', 'rabbitmq', 'vernemq', 'broker']
                for keyword in version_keywords:
                    if keyword.lower() in decoded.lower():
                        self.add_finding(
                            title=f"MQTT Broker Version Disclosure (Port {port})",
                            severity="low",
                            category="information_disclosure",
                            description=f"MQTT broker on port {port} reveals software information.",
                            evidence=f"Response: {decoded[:200]}",
                            remediation="Configure the MQTT broker to hide version information in error responses.",
                            cvss_score=3.7,
                        )
                        return
        except (socket.error, socket.timeout, Exception):
            pass
