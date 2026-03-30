"""
ChainSentinel MCP Server
Start scans, get results, and run analysis via Claude Desktop.
"""
import json
import sys
import requests
from mcp.server.fastmcp import FastMCP

# ChainSentinel backend URL
BACKEND_URL = "http://localhost:9000/api"

mcp = FastMCP("ChainSentinel")


@mcp.tool()
def scan_network() -> str:
    """Discover devices on the LAN. Returns active devices, open ports, and their categories."""
    try:
        resp = requests.post(f"{BACKEND_URL}/discovery", timeout=120)
        if resp.status_code != 200:
            return f"Error: {resp.status_code} - {resp.text}"
        data = resp.json()
        result = f"Network: {data['network']}\nDevices found: {data['total_hosts']}\n\n"
        for host in data['hosts']:
            ports = ", ".join([f"{p['port']}/{p['service']}" for p in host.get('ports', [])])
            result += f"IP: {host['ip']} | Hostname: {host['hostname']} | Category: {host['category']} | Ports: {ports or 'None'}\n"
        return result
    except Exception as e:
        return f"Network discovery failed: {str(e)}"


@mcp.tool()
def scan_iot_device(target_host: str = "localhost", target_port: int = 9081) -> str:
    """Run security test on IoT device. Checks default credentials, command injection, and information leakage."""
    return _run_scan("iot", target_host, target_port)


@mcp.tool()
def scan_supplier_portal(target_host: str = "localhost", target_port: int = 9082) -> str:
    """Run security test on supplier portal. Checks SQL injection, session vulnerabilities, and brute force."""
    return _run_scan("portal", target_host, target_port)


@mcp.tool()
def scan_wms_api(target_host: str = "localhost", target_port: int = 9083) -> str:
    """Run security test on WMS API. Checks SQL injection, IDOR, mass assignment, and rate limiting."""
    return _run_scan("api", target_host, target_port)


@mcp.tool()
def get_scan_results(scan_id: int) -> str:
    """Get detailed results of a specific scan. Scan ID required."""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans/{scan_id}", timeout=10)
        if resp.status_code != 200:
            return f"Error: Scan #{scan_id} not found."
        data = resp.json()
        result = f"Scan #{data['id']} - {data['scenario'].upper()}\n"
        result += f"Target: {data['target_host']}:{data['target_port']}\n"
        result += f"Status: {data['status']}\n"
        result += f"Findings: {len(data.get('findings', []))}\n\n"
        for f in data.get('findings', []):
            result += f"[{f['severity'].upper()}] {f['title']} (CVSS: {f.get('cvss_score', 'N/A')})\n"
            result += f"  Description: {f.get('description', '')}\n"
            result += f"  Remediation: {f.get('remediation', '')}\n\n"
        return result
    except Exception as e:
        return f"Failed to get results: {str(e)}"


@mcp.tool()
def get_all_findings(severity: str = "") -> str:
    """List findings from all scans. Severity filter: critical, high, medium, low (leave empty for all)."""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans", timeout=10)
        if resp.status_code != 200:
            return "Could not fetch scans."
        scans = resp.json()
        all_findings = []
        for scan_summary in scans:
            scan_resp = requests.get(f"{BACKEND_URL}/scans/{scan_summary['id']}", timeout=10)
            if scan_resp.status_code == 200:
                scan_data = scan_resp.json()
                for f in scan_data.get('findings', []):
                    f['scan_id'] = scan_data['id']
                    f['target'] = f"{scan_data['target_host']}:{scan_data['target_port']}"
                    all_findings.append(f)

        if severity:
            all_findings = [f for f in all_findings if f['severity'].lower() == severity.lower()]

        if not all_findings:
            return "No findings found."

        result = f"Total {len(all_findings)} findings:\n\n"
        for f in sorted(all_findings, key=lambda x: x.get('cvss_score', 0) or 0, reverse=True):
            result += f"[{f['severity'].upper()}] {f['title']} (CVSS: {f.get('cvss_score', 'N/A')}) - Target: {f['target']}\n"
        return result
    except Exception as e:
        return f"Failed to fetch findings: {str(e)}"


@mcp.tool()
def get_scan_history() -> str:
    """List all scan history."""
    try:
        resp = requests.get(f"{BACKEND_URL}/scans", timeout=10)
        if resp.status_code != 200:
            return "Could not fetch scan history."
        scans = resp.json()
        if not scans:
            return "No scans yet."
        result = f"Total {len(scans)} scans:\n\n"
        for s in scans:
            result += f"#{s['id']} | {s['scenario'].upper()} | {s['target_host']}:{s['target_port']} | {s['status']} | {s['findings_count']} findings | {s.get('created_at', '')}\n"
        return result
    except Exception as e:
        return f"Failed to fetch history: {str(e)}"


@mcp.tool()
def analyze_findings(scan_id: int) -> str:
    """Analyze scan findings with AI. Produces risk summary, attack chains, and MITRE ATT&CK mapping. AI settings must be configured."""
    try:
        resp = requests.post(f"{BACKEND_URL}/ai/analyze/{scan_id}", timeout=120)
        if resp.status_code != 200:
            error = resp.json().get('detail', 'Unknown error')
            return f"Analysis failed: {error}"
        data = resp.json()
        result = "=== AI SECURITY ANALYSIS ===\n\n"
        result += f"EXECUTIVE SUMMARY:\n{data.get('executive_summary', 'No data')}\n\n"
        result += f"RISK ASSESSMENT:\n{data.get('risk_summary', 'No data')}\n\n"

        if data.get('attack_chains'):
            result += "ATTACK CHAINS:\n"
            for chain in data['attack_chains']:
                result += f"\n  {chain['name']} [{chain.get('risk_level', '').upper()}]\n"
                for i, step in enumerate(chain.get('steps', []), 1):
                    result += f"    {i}. {step}\n"
                result += f"  Impact: {chain.get('impact', '')}\n"

        if data.get('prioritization'):
            result += "\nPRIORITIZATION:\n"
            for p in data['prioritization']:
                result += f"  {p['priority']}. {p['finding']} - {p['reason']}\n"

        if data.get('mitre_mapping'):
            result += "\n🎯 MITRE ATT&CK:\n"
            for m in data['mitre_mapping']:
                result += f"  {m['finding']} → {m['tactic']} / {m['technique_id']} ({m['technique_name']})\n"

        return result
    except Exception as e:
        return f"Analysis failed: {str(e)}"


def _run_scan(scenario: str, target_host: str, target_port: int) -> str:
    """Start scan and wait for results."""
    try:
        # Start scan
        resp = requests.post(f"{BACKEND_URL}/scans", json={
            "scenario": scenario,
            "target_host": target_host,
            "target_port": target_port
        }, timeout=10)
        if resp.status_code != 200:
            return f"Could not start scan: {resp.text}"
        scan = resp.json()
        scan_id = scan['id']

        # Wait until scan completes
        import time
        for _ in range(60):
            time.sleep(2)
            status_resp = requests.get(f"{BACKEND_URL}/scans/{scan_id}", timeout=10)
            if status_resp.status_code == 200:
                scan_data = status_resp.json()
                if scan_data['status'] in ('completed', 'failed'):
                    return get_scan_results(scan_id)

        return f"Scan timed out. Scan ID: {scan_id}"
    except Exception as e:
        return f"Scan failed: {str(e)}"


if __name__ == "__main__":
    mcp.run(transport="stdio")
