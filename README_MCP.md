# ChainSentinel MCP Server

Allows you to use ChainSentinel directly through Claude Desktop.

## Setup

### 1. Install required packages
```bash
pip install mcp requests
```

### 2. Update your Claude Desktop config

On Windows, open the `%APPDATA%\Claude\claude_desktop_config.json` file and add the following content:
```json
{
    "mcpServers": {
        "chainsentinel": {
            "command": "python",
            "args": ["mcp_server/server.py"],
            "cwd": "C:\\Users\\Taha\\Projects\\ChainSentinel"
        }
    }
}
```

### 3. Start the ChainSentinel backend
```bash
cd C:\Users\Taha\Projects\ChainSentinel
uvicorn backend.main:app --host 0.0.0.0 --port 9000
```

### 4. Restart Claude Desktop

## Available Commands

You can use the following commands in Claude Desktop:

- **"Scan network"** → Discovers devices on the LAN
- **"Scan IoT device"** → Runs IoT security tests
- **"Scan supplier portal"** → Runs web portal security tests
- **"Scan WMS API"** → Runs API security tests
- **"Show scan results"** → Retrieves details of a specific scan
- **"List all findings"** → Lists findings filtered by severity
- **"Show scan history"** → Displays past scans
- **"Analyze findings"** → AI-powered risk analysis, attack chain detection, MITRE mapping

## Notes

- The backend must be running (localhost:9000)
- AI analysis requires AI settings to be configured from the dashboard
- Nmap must be installed for network scanning
