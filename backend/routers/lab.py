import httpx
from fastapi import APIRouter

from backend.config import LAB_HOST, IOT_PORT, PORTAL_PORT, API_PORT
from backend.schemas import LabStatus

router = APIRouter()

CONTAINERS = {
    "iot_device": f"http://{LAB_HOST}:{IOT_PORT}/health",
    "supplier_portal": f"http://{LAB_HOST}:{PORTAL_PORT}/health",
    "wms_api": f"http://{LAB_HOST}:{API_PORT}/health",
}


@router.get("/lab/status", response_model=LabStatus)
async def lab_status():
    results = {}
    async with httpx.AsyncClient(timeout=3) as client:
        for name, url in CONTAINERS.items():
            try:
                resp = await client.get(url)
                results[name] = "up" if resp.status_code == 200 else "down"
            except Exception:
                results[name] = "down"

    return LabStatus(**results)
