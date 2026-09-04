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
from fastapi import Request, BackgroundTasks, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from app.core.database import get_db
from app.schemas.scan import ScanCreate, ScanDetailResponse

# Vercel Serverless Path Normalizer Middleware
@app.middleware("http")
async def vercel_path_rewrite_middleware(request: Request, call_next):
    # Check if route was passed via query parameter from Vercel rewrite
    route_param = request.query_params.get("__route") or request.query_params.get("__path")
    forwarded_uri = (
        request.headers.get("x-forwarded-uri")
        or request.headers.get("x-original-uri")
    )
    
    target_path = None
    if route_param:
        clean_route = route_param.lstrip("/")
        target_path = f"/api/{clean_route}" if not clean_route.startswith("api/") else f"/{clean_route}"
    elif forwarded_uri and forwarded_uri != "/api" and forwarded_uri != "/api/":
        target_path = forwarded_uri.split("?")[0]

    if target_path and target_path != request.scope["path"]:
        request.scope["path"] = target_path

    response = await call_next(request)
    return response

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

# Also register direct /scans prefix
app.include_router(scans.router, prefix="/scans", tags=["Scans-Root"])
app.include_router(targets.router, prefix="/targets", tags=["Targets-Root"])
app.include_router(reports.router, prefix="/reports", tags=["Reports-Root"])
app.include_router(live.router, prefix="/live", tags=["Live-Root"])

# Direct Fallback POST /api and POST /api/ to guarantee start_scan always triggers
@app.post("/api", tags=["Scans-Direct"])
@app.post("/api/", tags=["Scans-Direct"])
async def direct_api_scan_handler(
    payload: ScanCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db)
):
    from app.api.v1.scans import start_scan
    return await start_scan(payload, background_tasks, db)

@app.get("/health", tags=["Health"])
@app.get("/api/health", tags=["Health"])
@app.get("/api", tags=["Health"])
@app.get("/api/", tags=["Health"])
async def health_check():
    return {
        "status": "healthy",
        "service": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "environment": "vercel-serverless" if os.getenv("VERCEL") else "standalone"
    }

# Mount static web UI only in standalone local mode (NOT on Vercel where CDN serves frontend)
if not os.getenv("VERCEL"):
    frontend_dist = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist")
    if os.path.exists(frontend_dist):
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="frontend")


