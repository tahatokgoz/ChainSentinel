import threading

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from backend.database import get_db, SessionLocal
from backend.models import Scan
from backend.schemas import ScanCreate, ScanOut, ScanListOut
from backend.services.scan_runner import run_scan
from scanners.network_discovery import NetworkDiscovery

router = APIRouter()


def _run_scan_in_thread(scan_id: int):
    db = SessionLocal()
    try:
        run_scan(scan_id, db)
    finally:
        db.close()


@router.post("/scans", response_model=ScanOut)
def create_scan(scan_data: ScanCreate, db: Session = Depends(get_db)):
    scan = Scan(
        scenario=scan_data.scenario,
        target_host=scan_data.target_host,
        target_port=scan_data.target_port,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    thread = threading.Thread(target=_run_scan_in_thread, args=(scan.id,))
    thread.start()

    return scan


@router.get("/scans", response_model=list[ScanListOut])
def list_scans(scenario: str = None, status: str = None, db: Session = Depends(get_db)):
    query = db.query(Scan)
    if scenario:
        query = query.filter(Scan.scenario == scenario)
    if status:
        query = query.filter(Scan.status == status)

    scans = query.order_by(Scan.created_at.desc()).all()
    return [
        ScanListOut(
            id=s.id,
            scenario=s.scenario,
            target_host=s.target_host,
            target_port=s.target_port,
            status=s.status,
            findings_count=len(s.findings),
            started_at=s.started_at,
            completed_at=s.completed_at,
            created_at=s.created_at,
        )
        for s in scans
    ]


@router.get("/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan


@router.delete("/scans/{scan_id}")
def delete_scan(scan_id: int, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    findings_count = len(scan.findings)
    db.delete(scan)
    db.commit()
    return {"deleted_scans": 1, "deleted_findings": findings_count}


@router.post("/discovery")
def start_discovery(db: Session = Depends(get_db)):
    discovery = NetworkDiscovery()
    if not discovery.available:
        raise HTTPException(status_code=500, detail="Nmap not available. Please install Nmap.")

    network = discovery.get_local_network()
    hosts = discovery.discover_and_scan(network)

    return {
        "network": network,
        "total_hosts": len(hosts),
        "hosts": hosts
    }


@router.post("/discovery/port-scan")
def port_scan(host_ip: str):
    from scanners.network_discovery import NetworkDiscovery
    discovery = NetworkDiscovery()
    if not discovery.available:
        raise HTTPException(status_code=500, detail="Nmap not available.")

    ports = discovery.scan_host_ports(host_ip)
    return {
        "host": host_ip,
        "total_ports": len(ports),
        "ports": ports
    }


@router.post("/discovery/auto-scan")
def auto_scan(host_ip: str, host_port: int, category: str, db: Session = Depends(get_db)):
    scenario_map = {
        "iot_device": "iot",
        "web_portal": "portal",
        "api_service": "api",
    }

    scenario = scenario_map.get(category)
    if not scenario:
        raise HTTPException(status_code=400, detail=f"Unknown category: {category}")

    scan = Scan(
        scenario=scenario,
        target_host=host_ip,
        target_port=host_port,
        status="pending",
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)

    thread = threading.Thread(target=_run_scan_in_thread, args=(scan.id,))
    thread.start()

    return {"scan_id": scan.id, "scenario": scenario, "target": f"{host_ip}:{host_port}"}


@router.delete("/scans")
def delete_all_scans(all: bool = False, db: Session = Depends(get_db)):
    if not all:
        raise HTTPException(status_code=400, detail="Query parameter ?all=true is required")
    scans = db.query(Scan).all()
    total_scans = len(scans)
    total_findings = sum(len(s.findings) for s in scans)
    for scan in scans:
        db.delete(scan)
    db.commit()
    return {"deleted_scans": total_scans, "deleted_findings": total_findings}
