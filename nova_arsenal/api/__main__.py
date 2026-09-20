"""Nova-Arsenal API server entry point."""

import os

import uvicorn


def main() -> None:
    host = os.getenv("NOVA_API_HOST", "0.0.0.0")
    port = int(os.getenv("NOVA_API_PORT", "8000"))
    reload_enabled = os.getenv("NOVA_API_RELOAD", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    uvicorn.run(
        "nova_arsenal.api.app:app",
        host=host,
        port=port,
        reload=reload_enabled,
        log_level=os.getenv("LOG_LEVEL", "info").lower(),
    )


if __name__ == "__main__":
    main()
