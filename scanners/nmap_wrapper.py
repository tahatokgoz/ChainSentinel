import logging

logger = logging.getLogger(__name__)

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False


class NmapScanner:
    def __init__(self):
        if not NMAP_AVAILABLE:
            logger.warning("python-nmap not installed. Port scanning disabled.")
            self.nm = None
        else:
            self.nm = nmap.PortScanner()

    def scan_ports(self, host: str, ports: str = "1-10000") -> dict:
        if not self.nm:
            return {}

        try:
            self.nm.scan(host, ports, arguments="-sT -T4")
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan failed: {e}")
            return {}

        results = {}
        scanned_host = host if host in self.nm.all_hosts() else next(iter(self.nm.all_hosts()), None)
        if not scanned_host:
            return results

        for proto in self.nm[scanned_host].all_protocols():
            for port in self.nm[scanned_host][proto]:
                info = self.nm[scanned_host][proto][port]
                results[port] = {
                    "state": info["state"],
                    "service": info.get("name", "unknown"),
                    "version": info.get("version", ""),
                    "product": info.get("product", ""),
                }
        return results

    def scan_specific(self, host: str, port: int) -> dict:
        if not self.nm:
            return {}

        try:
            self.nm.scan(host, str(port), arguments="-sT")
        except nmap.PortScannerError as e:
            logger.error(f"Nmap scan failed: {e}")
            return {}

        scanned_host = host if host in self.nm.all_hosts() else next(iter(self.nm.all_hosts()), None)
        if not scanned_host:
            return {}

        for proto in self.nm[scanned_host].all_protocols():
            if port in self.nm[scanned_host][proto]:
                info = self.nm[scanned_host][proto][port]
                return {
                    "state": info["state"],
                    "service": info.get("name", "unknown"),
                    "version": info.get("version", ""),
                }
        return {}
