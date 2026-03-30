#!/usr/bin/env python3
"""ChainSentinel CLI - Warehouse Security Testing Tool"""
import argparse
import json
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.config import LAB_HOST, IOT_PORT, PORTAL_PORT, API_PORT
from backend.database import init_db, SessionLocal
from backend.models import Scan
from backend.services.scan_runner import run_scan
from backend.services.report_generator import generate_report


SCENARIOS = {
    "iot": ("IoT Device", IOT_PORT),
    "portal": ("Supplier Portal", PORTAL_PORT),
    "api": ("WMS API", API_PORT),
}


def cmd_scan(args):
    init_db()
    db = SessionLocal()

    targets = [args.scenario] if args.scenario != "all" else ["iot", "portal", "api"]

    for scenario in targets:
        name, port = SCENARIOS[scenario]
        host = args.host or LAB_HOST

        print(f"\n{'='*60}")
        print(f"  Scanning: {name} ({host}:{port})")
        print(f"{'='*60}")

        scan = Scan(scenario=scenario, target_host=host, target_port=port, status="pending")
        db.add(scan)
        db.commit()
        db.refresh(scan)

        run_scan(scan.id, db)
        db.refresh(scan)

        print(f"\n  Status: {scan.status}")
        print(f"  Findings: {len(scan.findings)}")

        if scan.findings:
            print(f"\n  {'Severity':<10} {'Title'}")
            print(f"  {'-'*50}")
            for f in sorted(scan.findings, key=lambda x: ["critical","high","medium","low","info"].index(x.severity)):
                severity_colors = {
                    "critical": "\033[91m",  # red
                    "high": "\033[93m",      # yellow
                    "medium": "\033[33m",    # orange
                    "low": "\033[94m",       # blue
                    "info": "\033[90m",      # gray
                }
                reset = "\033[0m"
                color = severity_colors.get(f.severity, "")
                print(f"  {color}{f.severity.upper():<10}{reset} {f.title}")

        if args.report:
            filepath = generate_report(scan.id, db)
            print(f"\n  Report: {filepath}")

    db.close()
    print(f"\n{'='*60}")
    print("  All scans completed.")
    print(f"{'='*60}\n")


def cmd_report(args):
    init_db()
    db = SessionLocal()

    scan = db.query(Scan).filter(Scan.id == args.scan_id).first()
    if not scan:
        print(f"Error: Scan #{args.scan_id} not found.")
        db.close()
        return

    filepath = generate_report(args.scan_id, db)
    print(f"Report generated: {filepath}")
    db.close()


def cmd_lab_status(args):
    import requests
    containers = {
        "IoT Device (:8081)": f"http://{LAB_HOST}:{IOT_PORT}/health",
        "Supplier Portal (:8082)": f"http://{LAB_HOST}:{PORTAL_PORT}/health",
        "WMS API (:8083)": f"http://{LAB_HOST}:{API_PORT}/health",
    }

    print("\nLab Status:")
    print("-" * 40)
    for name, url in containers.items():
        try:
            resp = requests.get(url, timeout=3)
            status = "UP" if resp.status_code == 200 else "DOWN"
            color = "\033[92m" if status == "UP" else "\033[91m"
        except Exception:
            status = "DOWN"
            color = "\033[91m"
        print(f"  {color}{status}\033[0m  {name}")
    print()


def main():
    parser = argparse.ArgumentParser(
        description="ChainSentinel - Warehouse Security Testing Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cli.py scan iot              Scan IoT device
  python cli.py scan portal           Scan supplier portal
  python cli.py scan api              Scan WMS API
  python cli.py scan all              Run all scans
  python cli.py scan all --report     Run all scans and generate reports
  python cli.py report 1              Generate report for scan #1
  python cli.py lab status            Check lab container status
        """,
    )

    subparsers = parser.add_subparsers(dest="command")

    # scan command
    scan_parser = subparsers.add_parser("scan", help="Run security scans")
    scan_parser.add_argument("scenario", choices=["iot", "portal", "api", "all"])
    scan_parser.add_argument("--host", default=None, help="Target host (default: localhost)")
    scan_parser.add_argument("--report", action="store_true", help="Generate report after scan")
    scan_parser.set_defaults(func=cmd_scan)

    # report command
    report_parser = subparsers.add_parser("report", help="Generate HTML report")
    report_parser.add_argument("scan_id", type=int, help="Scan ID")
    report_parser.set_defaults(func=cmd_report)

    # lab command
    lab_parser = subparsers.add_parser("lab", help="Lab management")
    lab_sub = lab_parser.add_subparsers(dest="lab_command")
    status_parser = lab_sub.add_parser("status", help="Check lab status")
    status_parser.set_defaults(func=cmd_lab_status)

    args = parser.parse_args()
    if hasattr(args, "func"):
        args.func(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
