import logging
import socket
from datetime import datetime

from sqlalchemy.orm import Session

from backend.models import Scan, Finding
from scanners.iot_scanner import IoTScanner
from scanners.portal_scanner import PortalScanner
from scanners.api_scanner import APIScanner
from scanners.mqtt_scanner import MQTTScanner
from scanners.protocol_scanner import ProtocolScanner

logger = logging.getLogger(__name__)

SCANNER_MAP = {
    "iot": IoTScanner,
    "portal": PortalScanner,
    "api": APIScanner,
}


def check_host_reachable(host: str, port: int, timeout: int = 3) -> bool:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception:
        return False


def run_scan(scan_id: int, db: Session):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        logger.error(f"Scan {scan_id} not found")
        return

    scan.status = "running"
    scan.started_at = datetime.utcnow()
    db.commit()

    scanner_class = SCANNER_MAP.get(scan.scenario)
    if not scanner_class:
        scan.status = "failed"
        db.commit()
        logger.error(f"Unknown scenario: {scan.scenario}")
        return

    try:
        scanner = scanner_class(scan.target_host, scan.target_port)

        # Check if target is reachable
        if not check_host_reachable(scan.target_host, scan.target_port):
            scan.status = "failed"
            scan.completed_at = datetime.utcnow()
            db.commit()
            logger.warning(f"Scan {scan_id} failed: Target {scan.target_host}:{scan.target_port} is unreachable")
            return

        findings = scanner.run()

        # Additionally run protocol-specific scans for all scan types
        try:
            mqtt = MQTTScanner(target_host=scan.target_host, target_port=scan.target_port)
            mqtt_findings = mqtt.run()
            for f in mqtt_findings:
                findings.append(f)
        except Exception as e:
            logger.warning(f"MQTT scan failed: {e}")

        try:
            proto = ProtocolScanner(target_host=scan.target_host)
            proto_findings = proto.run()
            for f in proto_findings:
                findings.append(f)
        except Exception as e:
            logger.warning(f"Protocol scan failed: {e}")

        for f in findings:
            finding = Finding(
                scan_id=scan.id,
                title=f["title"],
                severity=f["severity"],
                category=f["category"],
                description=f.get("description", ""),
                evidence=f.get("evidence", ""),
                remediation=f.get("remediation", ""),
                cvss_score=f.get("cvss_score"),
            )
            db.add(finding)

        scan.status = "completed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.info(f"Scan {scan_id} completed with {len(findings)} findings")

    except Exception as e:
        scan.status = "failed"
        scan.completed_at = datetime.utcnow()
        db.commit()
        logger.error(f"Scan {scan_id} failed: {e}")
