"""
Nova-Arsenal API Server

Start with: python -m nova_arsenal.api
Or: uvicorn nova_arsenal.api.app:app --host 0.0.0.0 --port 8000 --reload
"""

import uvicorn


def main():
    uvicorn.run(
        "nova_arsenal.api.app:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )


if __name__ == "__main__":
    main()
