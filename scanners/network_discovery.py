import logging
import socket

try:
    import nmap
except ImportError:
    nmap = None

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
        """Scan ports of a specific host. Runs twice for reliability."""
        if not self.available:
            return []

        logger.info(f"Port scan: {host} (ports: {ports})")

        all_ports = {}

        # First scan
        try:
            self.nm.scan(hosts=host, ports=ports, arguments="-sT -T4")
            if host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto]:
                        info = self.nm[host][proto][port]
                        if info["state"] == "open":
                            all_ports[port] = {
                                "port": port,
                                "protocol": proto,
                                "state": "open",
                                "service": info.get("name", "unknown"),
                                "product": info.get("product", ""),
                                "version": info.get("version", ""),
                            }
        except Exception as e:
            logger.error(f"First port scan failed: {e}")

        # Second scan for verification and catching missed ports
        try:
            self.nm.scan(hosts=host, ports=ports, arguments="-sT -T3")
            if host in self.nm.all_hosts():
                for proto in self.nm[host].all_protocols():
                    for port in self.nm[host][proto]:
                        info = self.nm[host][proto][port]
                        if info["state"] == "open" and port not in all_ports:
                            all_ports[port] = {
                                "port": port,
                                "protocol": proto,
                                "state": "open",
                                "service": info.get("name", "unknown"),
                                "product": info.get("product", ""),
                                "version": info.get("version", ""),
                            }
        except Exception as e:
            logger.error(f"Second port scan failed: {e}")

        # Third pass: socket check for critical warehouse ports that Nmap might miss
        critical_ports = [23, 80, 443, 2323, 8080, 8081, 8082, 8083, 8443, 9081, 9082, 9083, 9084, 1883, 3000, 5000, 8000]
        for port in critical_ports:
            if port not in all_ports:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    if result == 0:
                        all_ports[port] = {
                            "port": port,
                            "protocol": "tcp",
                            "state": "open",
                            "service": "unknown",
                            "product": "",
                            "version": "",
                        }
                except socket.error:
                    pass

        open_ports = sorted(all_ports.values(), key=lambda x: x["port"])
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
        """Classify device based on ports and services."""
        ports = host.get("ports", [])
        port_numbers = [p["port"] for p in ports]
        services = [p["service"].lower() for p in ports]

        categories = []

        # IoT indicators
        if any(p in port_numbers for p in [23, 2323]) or any(s in services for s in ["telnet", "mqtt", "coap"]):
            categories.append("iot_device")
        if any(p in port_numbers for p in [1883, 5683, 8883, 8081, 9081]):
            categories.append("iot_device")

        # Web portal indicators
        if any(p in port_numbers for p in [80, 443, 8080, 8082, 8443, 9082]):
            categories.append("web_portal")
        if any(s in services for s in ["http", "https", "http-proxy"]):
            if "web_portal" not in categories:
                categories.append("web_portal")

        # API indicators
        if any(p in port_numbers for p in [3000, 5000, 8000, 8083, 8084, 9083, 9084]):
            categories.append("api_service")

        # Remove duplicates
        categories = list(dict.fromkeys(categories))

        if not categories:
            return "unknown"
        if len(categories) == 1:
            return categories[0]

        # Multiple categories - return comma separated
        return ",".join(categories)
