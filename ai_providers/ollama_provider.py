import logging
import requests
from ai_providers.base import BaseAIProvider

logger = logging.getLogger(__name__)

SETUP_GUIDE = {
    "provider": "Ollama (Free - Local)",
    "steps": [
        "1. Download and install Ollama from ollama.com",
        "2. Open command line",
        "3. Run 'ollama pull llama3.1' to download the model",
        "4. Ollama runs automatically in the background",
        "5. No API key required, leave the field empty",
        "6. Test the connection"
    ],
    "key_prefix": "",
    "key_placeholder": "No API key required",
    "pricing": "Completely free (runs on your computer)",
    "url": "https://ollama.com"
}


class OllamaProvider(BaseAIProvider):

    def __init__(self, api_key: str = "", model: str = "llama3.1"):
        self.model = model
        self.base_url = "http://localhost:11434"

    def test_connection(self) -> bool:
        try:
            resp = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return resp.status_code == 200
        except Exception:
            return False

    def analyze_findings(self, findings, scan_info):
        prompt = self._build_prompt(findings, scan_info)
        try:
            resp = requests.post(f"{self.base_url}/api/generate",
                json={"model": self.model, "prompt": prompt, "stream": False}, timeout=120)
            if resp.status_code != 200:
                return {"error": f"Ollama error: {resp.status_code}"}
            content = resp.json().get("response", "")
            return self._parse_response(content)
        except requests.ConnectionError:
            return {"error": "Ollama is not running. Please start Ollama."}
        except Exception as e:
            return {"error": str(e)}
