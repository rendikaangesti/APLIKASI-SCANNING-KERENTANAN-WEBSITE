from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from contextlib import asynccontextmanager
import os

from app.core.config import settings
from app.core.database import init_db
from app.api.v1 import scans, targets, reports, ws, live

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables on startup
    await init_db()
    yield

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="DjoeraganCyber Web & API Vulnerability Scanner Platform.",
    lifespan=lifespan
)

# Setup CORS for frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global Exception Handler
from fastapi.responses import JSONResponse
from fastapi import Request

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    import traceback
    err_trace = traceback.format_exc()
    print(f"[SERVER EXCEPTION] {request.method} {request.url.path}: {err_trace}")
    return JSONResponse(
        status_code=500,
        content={
            "detail": f"Server error: {str(exc)}",
            "type": type(exc).__name__,
            "path": request.url.path
        }
    )

# Register API Routers with standard /api/v1 prefix
app.include_router(scans.router, prefix=f"{settings.API_V1_STR}/scans", tags=["Scans"])
app.include_router(targets.router, prefix=f"{settings.API_V1_STR}/targets", tags=["Targets"])
app.include_router(reports.router, prefix=f"{settings.API_V1_STR}/reports", tags=["Reports"])
app.include_router(ws.router, prefix=f"{settings.API_V1_STR}", tags=["WebSocket Telemetry"])
app.include_router(live.router, prefix=f"{settings.API_V1_STR}/live", tags=["Live Audit & Exploration"])

# Also register with /v1 prefix for Serverless runtimes that strip /api
app.include_router(scans.router, prefix="/v1/scans", tags=["Scans-Direct"])
app.include_router(targets.router, prefix="/v1/targets", tags=["Targets-Direct"])
app.include_router(reports.router, prefix="/v1/reports", tags=["Reports-Direct"])
app.include_router(live.router, prefix="/v1/live", tags=["Live-Direct"])

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
@app.get("/api", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION
    }

# Mount static web UI
frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
if os.path.exists(frontend_dist):
    app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")

