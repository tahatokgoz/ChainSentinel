import json
import logging
import requests
from ai_providers.base import BaseAIProvider

logger = logging.getLogger(__name__)

SETUP_GUIDE = {
    "provider": "Anthropic (Claude)",
    "steps": [
        "1. Go to console.anthropic.com",
        "2. Create a free account",
        "3. Go to API Keys from the left menu",
        "4. Click Create Key",
        "5. Copy the key (starts with sk-ant-...)",
        "6. Paste it in the field below"
    ],
    "key_prefix": "sk-ant-",
    "key_placeholder": "sk-ant-api03-...",
    "pricing": "~$0.01-0.05 USD per analysis",
    "url": "https://console.anthropic.com"
}


class AnthropicProvider(BaseAIProvider):

    def __init__(self, api_key: str, model: str = "claude-sonnet-4-20250514"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.anthropic.com/v1/messages"

    def test_connection(self) -> bool:
        try:
            resp = requests.post(self.base_url, headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }, json={"model": self.model, "max_tokens": 10,
                "messages": [{"role": "user", "content": "test"}]}, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze_findings(self, findings: list[dict], scan_info: dict) -> dict:
        prompt = self._build_prompt(findings, scan_info)
        try:
            resp = requests.post(self.base_url, headers={
                "x-api-key": self.api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json"
            }, json={"model": self.model, "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}]}, timeout=60)
            if resp.status_code != 200:
                return {"error": f"API error: {resp.status_code}"}
            content = resp.json()["content"][0]["text"]
            return self._parse_response(content)
        except requests.Timeout:
            return {"error": "Request timed out. Please try again."}
        except Exception as e:
            return {"error": str(e)}

    def _build_prompt(self, findings, scan_info):
        findings_text = ""
        for i, f in enumerate(findings, 1):
            findings_text += f"\nFinding {i}:\n- Title: {f.get('title','')}\n- Severity: {f.get('severity','')}\n- Category: {f.get('category','')}\n- CVSS: {f.get('cvss_score','N/A')}\n- Description: {f.get('description','')}\n- Evidence: {f.get('evidence','')}\n- Remediation: {f.get('remediation','')}\n"

        return f"""You are a cybersecurity expert. Analyze the following penetration test findings.

Scan Information:
- Scenario: {scan_info.get('scenario', '')}
- Target: {scan_info.get('target', '')}
- Date: {scan_info.get('date', '')}

Findings:
{findings_text}

Respond in the following JSON format. Return only JSON, nothing else:

{{
    "risk_summary": "Overall risk assessment (3-4 sentences)",
    "executive_summary": "Summary for non-technical executives (2-3 sentences, simple language)",
    "attack_chains": [
        {{
            "name": "Attack chain name",
            "steps": ["Step 1", "Step 2", "Step 3"],
            "impact": "Impact",
            "risk_level": "critical/high/medium/low"
        }}
    ],
    "prioritization": [
        {{
            "finding": "Finding title",
            "priority": 1,
            "reason": "Why it's a priority"
        }}
    ],
    "mitre_mapping": [
        {{
            "finding": "Finding title",
            "tactic": "MITRE ATT&CK Tactic",
            "technique_id": "Txxxx",
            "technique_name": "Technique name"
        }}
    ]
}}"""

    def _parse_response(self, content):
        try:
            content = content.strip()
            if content.startswith("```json"): content = content[7:]
            if content.startswith("```"): content = content[3:]
            if content.endswith("```"): content = content[:-3]
            return json.loads(content.strip())
        except json.JSONDecodeError:
            return {"error": "Failed to parse AI response", "raw_response": content[:1000]}
