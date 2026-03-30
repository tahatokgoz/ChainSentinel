import json
import logging
import requests
from ai_providers.base import BaseAIProvider

logger = logging.getLogger(__name__)

SETUP_GUIDE = {
    "provider": "OpenAI (GPT)",
    "steps": [
        "1. Go to platform.openai.com",
        "2. Create an account or sign in",
        "3. Go to API Keys page",
        "4. Click Create new secret key",
        "5. Copy the key (starts with sk-...)",
        "6. Paste it in the field below"
    ],
    "key_prefix": "sk-",
    "key_placeholder": "sk-proj-...",
    "pricing": "~$0.01-0.05 USD per analysis",
    "url": "https://platform.openai.com"
}


class OpenAIProvider(BaseAIProvider):

    def __init__(self, api_key: str, model: str = "gpt-4o"):
        self.api_key = api_key
        self.model = model
        self.base_url = "https://api.openai.com/v1/chat/completions"

    def test_connection(self) -> bool:
        try:
            resp = requests.post(self.base_url, headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }, json={"model": self.model, "max_tokens": 10,
                "messages": [{"role": "user", "content": "test"}]}, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze_findings(self, findings, scan_info):
        from ai_providers.anthropic import AnthropicProvider
        ap = AnthropicProvider.__new__(AnthropicProvider)
        prompt = ap._build_prompt(findings, scan_info)
        try:
            resp = requests.post(self.base_url, headers={
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json"
            }, json={"model": self.model, "max_tokens": 4096,
                "messages": [{"role": "user", "content": prompt}]}, timeout=60)
            if resp.status_code != 200:
                return {"error": f"API error: {resp.status_code}"}
            content = resp.json()["choices"][0]["message"]["content"]
            return ap._parse_response(content)
        except Exception as e:
            return {"error": str(e)}
