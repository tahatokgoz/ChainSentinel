import logging
import socket

import nmap

logger = logging.getLogger(__name__)


class NetworkDiscovery:
    """Discovers and classifies devices on the LAN."""

    def __init__(self):
        try:
            self.nm = nmap.PortScanner()
            self.available = True
        except Exception:
            logger.warning("Nmap not available. Network discovery disabled.")
            self.available = False

    def get_local_network(self) -> str:
        """Auto-detect local network range (e.g. 192.168.1.0/24)."""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            local_ip = s.getsockname()[0]
            s.close()
            # Replace last octet with 0/24
            network = ".".join(local_ip.split(".")[:-1]) + ".0/24"
            logger.info(f"Local network detected: {network} (IP: {local_ip})")
            return network
        except Exception as e:
            logger.error(f"Could not detect local network: {e}")
            return "192.168.1.0/24"

    def discover_hosts(self, network: str = None) -> list[dict]:
        """Find active hosts on the network."""
        if not self.available:
            return []

        if network is None:
            network = self.get_local_network()

        logger.info(f"Starting network discovery: {network}")

        try:
            # Fast host discovery (-sn = ping scan, host up/down check)
            self.nm.scan(hosts=network, arguments="-sn -T4")
        except nmap.PortScannerError as e:
            logger.error(f"Network discovery failed: {e}")
            return []

        hosts = []
        for host in self.nm.all_hosts():
            if self.nm[host].state() == "up":
                host_info = {
                    "ip": host,
                    "hostname": self.nm[host].hostname() or "Unknown",
                    "state": "up",
                    "mac": "",
                    "vendor": "",
                    "ports": [],
                    "category": "unknown",
                }

                # Get MAC address if available
                if "mac" in self.nm[host].get("addresses", {}):
                    host_info["mac"] = self.nm[host]["addresses"]["mac"]
                if "vendor" in self.nm[host]:
                    vendors = self.nm[host]["vendor"]
                    if vendors:
                        host_info["vendor"] = list(vendors.values())[0]

                hosts.append(host_info)

        logger.info(f"{len(hosts)} active hosts found.")
        return hosts

    def scan_host_ports(self, host: str, ports: str = "20-1000,2323,8080-8090,9080-9090") -> list[dict]:
        """Scan ports of a specific host."""
        if not self.available:
            return []

        logger.info(f"Port scan: {host} (ports: {ports})")

        try:
            self.nm.scan(hosts=host, ports=ports, arguments="-sT -T4")
        except nmap.PortScannerError as e:
            logger.error(f"Port scan failed: {e}")
            return []

        open_ports = []
        if host in self.nm.all_hosts():
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto]:
                    info = self.nm[host][proto][port]
                    if info["state"] == "open":
                        open_ports.append({
                            "port": port,
                            "protocol": proto,
                            "state": info["state"],
                            "service": info.get("name", "unknown"),
                            "product": info.get("product", ""),
                            "version": info.get("version", ""),
                        })

        logger.info(f"{host}: {len(open_ports)} open ports found.")
        return open_ports

    def discover_and_scan(self, network: str = None) -> list[dict]:
        """Full discovery: find hosts + scan ports + classify."""
        hosts = self.discover_hosts(network)

        for host in hosts:
            # Scan ports of each host
            host["ports"] = self.scan_host_ports(host["ip"])
            # Classify device
            host["category"] = self._classify_device(host)

        return hosts

    def _classify_device(self, host: dict) -> str:
        """Classify device based on port and service information."""
        ports = host.get("ports", [])
        port_numbers = [p["port"] for p in ports]
        services = [p["service"].lower() for p in ports]

        # IoT device indicators
        iot_indicators = 0
        if 2323 in port_numbers:  # Telnet (common in IoT)
            iot_indicators += 2
        if 23 in port_numbers:  # Standard Telnet
            iot_indicators += 2
        if any(s in services for s in ["telnet", "mqtt", "coap"]):
            iot_indicators += 2
        if any(p in port_numbers for p in [1883, 5683, 8883]):  # MQTT, CoAP
            iot_indicators += 2
        if any(p in port_numbers for p in range(8080, 8091)):  # Embedded web panel
            iot_indicators += 1

        # Web portal indicators
        web_indicators = 0
        if 80 in port_numbers or 443 in port_numbers:
            web_indicators += 2
        if any(s in services for s in ["http", "https"]):
            web_indicators += 1
        if any(p in port_numbers for p in [8080, 8443, 3000, 5000]):
            web_indicators += 1

        # API indicators
        api_indicators = 0
        if any(p in port_numbers for p in range(9080, 9091)):
            api_indicators += 1
        if any(p in port_numbers for p in [3000, 5000, 8000, 8080]):
            api_indicators += 1

        # Classify by highest score
        scores = {
            "iot_device": iot_indicators,
            "web_portal": web_indicators,
            "api_service": api_indicators,
        }

        max_score = max(scores.values())
        if max_score == 0:
            return "unknown"

        return max(scores, key=scores.get)
