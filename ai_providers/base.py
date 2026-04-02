import json
from abc import ABC, abstractmethod


class BaseAIProvider(ABC):

    @abstractmethod
    def analyze_findings(self, findings: list[dict], scan_info: dict) -> dict:
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        pass

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
