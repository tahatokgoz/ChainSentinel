# ChainSentinel ♞

**Warehouse Security Testing Platform** — *by ShahMat Sec*

ChainSentinel is a specialized penetration testing tool designed for warehouse and supply chain systems. It automatically discovers devices on your network, runs security tests, and generates AI-powered analysis reports.

![Python](https://img.shields.io/badge/Python-3.11+-blue)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-green)
![License](https://img.shields.io/badge/License-MIT-yellow)

## Features

- **Automatic Network Discovery** — Scans your LAN, discovers devices, and classifies them (IoT, Web Portal, API)
- **One-Click Pentesting** — Run security tests on all discovered devices with a single click
- **42+ Security Checks** — SQL Injection, Command Injection, IDOR, Brute Force, Default Credentials, Session Vulnerabilities, XSS, CSRF, SSL/TLS Analysis, and more
- **AI-Powered Analysis** — Supports Claude, GPT, Gemini, and Ollama for intelligent vulnerability analysis
- **Attack Chain Detection** — AI identifies how vulnerabilities can be chained together
- **MITRE ATT&CK Mapping** — Automatically maps findings to the MITRE framework
- **PDF Reports** — Generate professional security reports with one click
- **MCP Server** — Integrate with Claude Desktop for conversational security testing
- **Advanced Scanning** — Port scanning and manual pentesting for IT professionals

## Quick Start

### Prerequisites

- Python 3.11+
- Nmap ([download](https://nmap.org/download.html))

### Installation
```bash
git clone https://github.com/yourusername/ChainSentinel.git
cd ChainSentinel
pip install -r requirements.txt
```

### Run
```bash
uvicorn backend.main:app --host 0.0.0.0 --port 9000
```

Open `http://localhost:9000` in your browser.

### Usage

1. Click **Scan Network** to discover devices on your network
2. Click **Run Pentest** on any discovered device or **Pentest All** for all devices
3. View findings in the dashboard
4. Click **AI** to get AI-powered analysis (requires API key setup in AI Settings)
5. Click **Report** to download a PDF report

## AI Integration

ChainSentinel supports multiple AI providers for vulnerability analysis:

| Provider | Type | API Key Required |
|----------|------|-----------------|
| Ollama | Free (Offline) | No |
| Claude (Anthropic) | Paid (Recommended) | Yes |
| GPT (OpenAI) | Paid | Yes |
| Gemini (Google) | Free Tier Available | Yes |

Configure your preferred AI provider in **AI Settings** from the dashboard.

## Documentation

For detailed setup instructions, usage guide, and complete feature reference, see the [ChainSentinel User Guide](docs/ChainSentinel_User_Guide_v1.0.docx).

## MCP Server (Claude Desktop)

ChainSentinel includes an MCP server for Claude Desktop integration. See [README_MCP.md](README_MCP.md) for setup instructions.

## Security Checks

ChainSentinel performs **42+ automated security checks** across 7 scanner modules:

### IoT Device Scanner (8 checks)
| Check | Severity | CVSS |
|-------|----------|------|
| Open Ports Detection | Medium | 5.3 |
| Default Credentials (HTTP) | Critical | 9.8 |
| Default Credentials (Telnet) | Critical | 9.8 |
| Unauthenticated Sensor Data Access | High | 7.5 |
| Sensitive Information Disclosure | Medium | 5.3 |
| Command Injection | Critical | 10.0 |
| Directory Traversal | High | 7.5 |
| Missing Security Headers | Low | 3.7 |

### Web Portal Scanner (12 checks)
| Check | Severity | CVSS |
|-------|----------|------|
| SQL Injection (Auth Bypass) | Critical | 9.8 |
| No Brute Force Protection | Medium | 5.3 |
| Weak Session Tokens | High | 7.5 |
| Session Fixation | High | 7.5 |
| Debug Mode / Info Disclosure | Medium | 5.3 |
| Exposed Sensitive Files | High | 7.2 |
| Reflected XSS | High | 6.1 |
| Missing CSRF Protection | Medium | 4.3 |
| Missing Security Headers | Medium | 5.3 |
| Insecure Cookie Configuration | Medium | 5.3 |
| Directory Traversal | High | 7.5 |
| Unrestricted File Upload | High | 7.5 |

### API Scanner (8 checks)
| Check | Severity | CVSS |
|-------|----------|------|
| SQL Injection (Boolean-based) | Critical | 9.8 |
| IDOR - Unauthorized Access | High | 7.5 |
| API Key in URL Parameter | Medium | 5.3 |
| No Rate Limiting | Medium | 5.3 |
| Mass Assignment | High | 7.5 |
| Missing Input Validation | Low | 3.7 |
| CORS Misconfiguration | Medium | 5.3 |
| Missing Security Headers | Low | 3.7 |

### MQTT Scanner (4 checks)
| Check | Severity | CVSS |
|-------|----------|------|
| Anonymous Access | Critical | 9.1 |
| Default Credentials | Critical | 9.8 |
| Wildcard Topic Subscription | High | 7.5 |
| Broker Version Disclosure | Low | 3.7 |

### Protocol Scanner (6 checks)
| Check | Severity | CVSS |
|-------|----------|------|
| Modbus Unauthenticated Access | Critical | 9.8 |
| SNMP Default Community String | High | 7.5 |
| FTP Anonymous/Default Access | High | 7.5 |
| DNS Zone Transfer | Medium | 5.3 |
| Open Redirect | Medium | 4.7 |
| SSL/TLS Configuration Issues | Medium | 5.3 |

## Tech Stack

- **Backend:** Python, FastAPI, SQLAlchemy, SQLite
- **Frontend:** HTML, Tailwind CSS, Chart.js
- **Scanning:** Nmap, Custom Python scanners
- **AI:** Anthropic Claude, OpenAI GPT, Google Gemini, Ollama
- **Reporting:** ReportLab (PDF)

## Screenshots

*Coming soon*

## Disclaimer

⚠️ **This tool is intended for authorized security testing only.** Only use ChainSentinel on systems you own or have explicit permission to test. Unauthorized access to computer systems is illegal.

## License

MIT License — see [LICENSE](LICENSE) for details.

## Authors

Developed by **ShahMat Sec** ♞

---

*ChainSentinel — Protecting your supply chain, one vulnerability at a time.*
