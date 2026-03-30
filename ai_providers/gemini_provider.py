import json
import logging
import requests
from ai_providers.base import BaseAIProvider

logger = logging.getLogger(__name__)

SETUP_GUIDE = {
    "provider": "Google (Gemini)",
    "steps": [
        "1. Go to aistudio.google.com",
        "2. Sign in with your Google account",
        "3. Click Get API Key",
        "4. Click Create API Key",
        "5. Copy the key",
        "6. Paste it in the field below"
    ],
    "key_prefix": "AI",
    "key_placeholder": "AIza...",
    "pricing": "Free usage limit available",
    "url": "https://aistudio.google.com"
}


class GeminiProvider(BaseAIProvider):

    def __init__(self, api_key: str, model: str = "gemini-2.5-flash"):
        self.api_key = api_key
        self.model = model
        self.base_url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent"

    def test_connection(self) -> bool:
        try:
            resp = requests.post(f"{self.base_url}?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": "test"}]}]}, timeout=10)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze_findings(self, findings, scan_info):
        from ai_providers.anthropic import AnthropicProvider
        ap = AnthropicProvider.__new__(AnthropicProvider)
        prompt = ap._build_prompt(findings, scan_info)
        try:
            resp = requests.post(f"{self.base_url}?key={self.api_key}",
                headers={"Content-Type": "application/json"},
                json={"contents": [{"parts": [{"text": prompt}]}]}, timeout=60)
            if resp.status_code != 200:
                return {"error": f"API error: {resp.status_code}"}
            content = resp.json()["candidates"][0]["content"]["parts"][0]["text"]
            return ap._parse_response(content)
        except Exception as e:
            return {"error": str(e)}
