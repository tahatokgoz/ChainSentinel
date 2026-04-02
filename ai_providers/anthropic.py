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
