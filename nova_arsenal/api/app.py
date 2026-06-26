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
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from nova_arsenal.api.routes import router as api_router
from nova_arsenal.api.routes_chat import router as chat_router
from nova_arsenal.api.routes_chat import set_router as set_chat_router
from nova_arsenal.api.websocket.events import router as ws_router
from nova_arsenal.auth.rate_limit import RateLimitConfig, RateLimitMiddleware
from nova_arsenal.auth.routes import router as auth_router
from nova_arsenal.llm.multi_router import MultiProviderRouter
from nova_arsenal.llm.opencode import OpencodeProvider
from nova_arsenal.llm.router import get_llm_router

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

    # ── Rate Limiting ───────────────────────────────────────────────────────
    app.add_middleware(
        RateLimitMiddleware,
        config=RateLimitConfig(
            global_per_second=50.0,
            global_burst=100,
            auth_per_second=5.0,
            auth_burst=10,
        ),
    )

    # ── Startup ──────────────────────────────────────────────────────────────
    @app.on_event("startup")
    async def startup():
        # Initialize database tables
        try:
            from nova_arsenal.db.session import create_tables
            await create_tables()
            logger.info("Database tables created / verified")
        except Exception as e:
            logger.warning(f"Database initialization skipped (non-fatal): {e}")

        # Start API key cleanup task
        try:
            import asyncio
            from nova_arsenal.auth.cleanup import start_cleanup_task
            asyncio.create_task(start_cleanup_task(interval_seconds=3600))
            logger.info("API key cleanup task started (hourly)")
        except Exception as e:
            logger.warning(f"API key cleanup task skipped: {e}")

        # Initialize LLM router and wire into chat
        llm_router = get_llm_router()
        multi = llm_router.multi_router

        # If multi-router is available, wire it to chat
        if multi:
            set_chat_router(multi)
            logger.info(f"Chat wired to multi-router with providers: {multi.list_providers()}")
        else:
            # Create a basic multi-router even without config
            basic = MultiProviderRouter()
            opencode_key = os.getenv("OPCODE_API_KEY", "")
            if opencode_key:
                try:
                    op = OpencodeProvider(api_key=opencode_key)
                    basic.register_provider("opencode", op)
                    set_chat_router(basic)
                    logger.info("Chat wired to Opencode provider from environment")
                except Exception as e:
                    logger.warning(f"Failed to init Opencode: {e}")

    # ── Routers ──────────────────────────────────────────────────────────────
    app.include_router(api_router)
    app.include_router(chat_router)
    app.include_router(ws_router)
    app.include_router(auth_router)

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
