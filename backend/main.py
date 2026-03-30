from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from backend.config import BASE_DIR, REPORTS_DIR
from backend.database import init_db
from backend.routers import scans, reports, lab
from backend.routers.ai import router as ai_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="ChainSentinel",
    description="Warehouse Security Testing Tool",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(lab.router, prefix="/api")
app.include_router(ai_router, prefix="/api")

app.mount("/reports-static", StaticFiles(directory=REPORTS_DIR), name="reports-static")
app.mount("/", StaticFiles(directory=f"{BASE_DIR}/frontend", html=True), name="frontend")
