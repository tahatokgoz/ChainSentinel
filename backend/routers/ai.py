import json
import logging
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from backend.database import get_db
from backend.models import Scan, AIAnalysis

logger = logging.getLogger(__name__)
router = APIRouter()

# Settings stored in memory (simple approach)
ai_settings = {
    "provider": "",
    "api_key": "",
    "model": ""
}

PROVIDER_MAP = {
    "anthropic": {"module": "ai_providers.anthropic", "class": "AnthropicProvider", "guide_module": "ai_providers.anthropic"},
    "openai": {"module": "ai_providers.openai_provider", "class": "OpenAIProvider", "guide_module": "ai_providers.openai_provider"},
    "gemini": {"module": "ai_providers.gemini_provider", "class": "GeminiProvider", "guide_module": "ai_providers.gemini_provider"},
    "ollama": {"module": "ai_providers.ollama_provider", "class": "OllamaProvider", "guide_module": "ai_providers.ollama_provider"},
}

DEFAULT_MODELS = {
    "anthropic": "claude-sonnet-4-20250514",
    "openai": "gpt-4o",
    "gemini": "gemini-2.5-flash",
    "ollama": "llama3.1"
}


def get_provider_instance():
    if not ai_settings["provider"]:
        return None
    info = PROVIDER_MAP.get(ai_settings["provider"])
    if not info:
        return None
    import importlib
    mod = importlib.import_module(info["module"])
    cls = getattr(mod, info["class"])
    model = ai_settings.get("model") or DEFAULT_MODELS.get(ai_settings["provider"], "")
    return cls(api_key=ai_settings["api_key"], model=model)


@router.get("/ai/settings")
def get_settings():
    return {
        "provider": ai_settings["provider"],
        "api_key": "***" + ai_settings["api_key"][-4:] if len(ai_settings["api_key"]) > 4 else "",
        "model": ai_settings["model"],
        "is_configured": bool(ai_settings["provider"])
    }


@router.post("/ai/settings")
def save_settings(provider: str, api_key: str = "", model: str = ""):
    if provider not in PROVIDER_MAP:
        raise HTTPException(400, f"Invalid provider: {provider}")
    ai_settings["provider"] = provider
    ai_settings["api_key"] = api_key
    ai_settings["model"] = model or DEFAULT_MODELS.get(provider, "")
    return {"message": "Settings saved", "provider": provider}


@router.post("/ai/test")
def test_connection():
    provider = get_provider_instance()
    if not provider:
        raise HTTPException(400, "AI not configured. Select a provider from Settings first.")
    success = provider.test_connection()
    return {"success": success, "message": "Connection successful!" if success else "Connection failed. Check your API key."}


@router.post("/ai/analyze/{scan_id}")
def analyze_scan(scan_id: int, db: Session = Depends(get_db)):
    provider = get_provider_instance()
    if not provider:
        raise HTTPException(400, "AI not configured.")

    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(404, "Scan not found.")
    if scan.status != "completed":
        raise HTTPException(400, "Scan not completed yet.")
    if not scan.findings:
        raise HTTPException(400, "No findings in this scan.")

    # Return cached analysis if exists
    existing = db.query(AIAnalysis).filter(AIAnalysis.scan_id == scan_id).first()
    if existing:
        return {
            "scan_id": scan_id,
            "cached": True,
            "risk_summary": existing.risk_summary,
            "executive_summary": existing.executive_summary,
            "attack_chains": json.loads(existing.attack_chains or "[]"),
            "prioritization": json.loads(existing.prioritization or "[]"),
            "mitre_mapping": json.loads(existing.mitre_mapping or "[]")
        }

    findings = [{"title": f.title, "severity": f.severity, "category": f.category,
                 "cvss_score": f.cvss_score, "description": f.description,
                 "evidence": f.evidence, "remediation": f.remediation} for f in scan.findings]

    scan_info = {"scenario": scan.scenario, "target": f"{scan.target_host}:{scan.target_port}",
                 "date": str(scan.completed_at or scan.created_at)}

    result = provider.analyze_findings(findings, scan_info)

    if "error" in result:
        raise HTTPException(500, result["error"])

    analysis = AIAnalysis(
        scan_id=scan_id,
        provider=ai_settings["provider"],
        model=ai_settings.get("model", ""),
        risk_summary=result.get("risk_summary", ""),
        executive_summary=result.get("executive_summary", ""),
        attack_chains=json.dumps(result.get("attack_chains", []), ensure_ascii=False),
        prioritization=json.dumps(result.get("prioritization", []), ensure_ascii=False),
        mitre_mapping=json.dumps(result.get("mitre_mapping", []), ensure_ascii=False),
        raw_response=json.dumps(result, ensure_ascii=False)
    )
    db.add(analysis)
    db.commit()

    return {
        "scan_id": scan_id,
        "cached": False,
        "risk_summary": result.get("risk_summary", ""),
        "executive_summary": result.get("executive_summary", ""),
        "attack_chains": result.get("attack_chains", []),
        "prioritization": result.get("prioritization", []),
        "mitre_mapping": result.get("mitre_mapping", [])
    }


@router.get("/ai/guides")
def get_guides():
    guides = {}
    for name, info in PROVIDER_MAP.items():
        import importlib
        mod = importlib.import_module(info["guide_module"])
        guides[name] = mod.SETUP_GUIDE
    return guides
