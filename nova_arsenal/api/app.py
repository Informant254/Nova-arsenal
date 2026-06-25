"""
Nova-Arsenal FastAPI Application

Main entry point for the API server. Mounts all routers, configures CORS,
and serves the web dashboard.
"""

import logging
import os
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from nova_arsenal.api.routes import router as api_router
from nova_arsenal.api.routes_chat import router as chat_router
from nova_arsenal.api.websocket.events import router as ws_router

logger = logging.getLogger(__name__)

# ── App Factory ──────────────────────────────────────────────────────────────

def create_app() -> FastAPI:
    app = FastAPI(
        title="Nova-Arsenal",
        description="Autonomous Security Research Platform",
        version="1.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )

    # ── CORS ─────────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(api_router)
    app.include_router(chat_router)
    app.include_router(ws_router)

    # ── Static files (web dashboard) ─────────────────────────────────────────
    static_dir = Path(__file__).parent / "static"
    if static_dir.exists():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    @app.get("/", include_in_schema=False)
    async def index():
        dashboard = static_dir / "index.html"
        if dashboard.exists():
            return FileResponse(str(dashboard))
        return {"message": "Nova-Arsenal API", "docs": "/docs"}

    @app.get("/health")
    async def health():
        return {"status": "ok", "service": "nova-arsenal"}

    return app


app = create_app()
