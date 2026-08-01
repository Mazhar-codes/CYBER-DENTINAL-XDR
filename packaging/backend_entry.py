#!/usr/bin/env python3
"""
Frozen entrypoint for the Cyber Sentinel XDR backend (PyInstaller onedir build).

PyInstaller cannot freeze the `uvicorn backend:sio_app` CLI form directly, so
this script imports the ASGI app and runs uvicorn programmatically.

Config resolution when frozen:
  - Loads a .env sitting NEXT TO backend.exe first (this is where the installer
    writes the operator's XDR_API_KEY / JWT_SECRET_KEY / MONGO_URI / ports), so
    config.py sees real secrets instead of the placeholder defaults that would
    otherwise abort startup.
  - Bundled model files are resolved by config.py via sys._MEIPASS (see its
    frozen-aware BASE_DIR).
"""
import multiprocessing
import os
import sys
from pathlib import Path


def _load_external_env() -> None:
    """Load a .env placed beside backend.exe (installer-provided) before config import."""
    if not getattr(sys, "frozen", False):
        return
    env_file = Path(sys.executable).resolve().parent / ".env"
    if env_file.exists():
        try:
            from dotenv import load_dotenv
            load_dotenv(env_file, override=False)
        except Exception:
            # dotenv missing or unreadable — fall through to process env / defaults.
            pass


def main() -> None:
    multiprocessing.freeze_support()  # required: uvicorn/torch may spawn workers
    _load_external_env()

    import config          # validates secrets at import — needs the .env above
    import uvicorn
    import backend         # defines sio_app (socketio.ASGIApp + middleware)

    host = config.settings.backend_host
    port = config.settings.backend_port
    print(f"[Cyber Sentinel XDR] Backend starting on http://{host}:{port}", flush=True)
    uvicorn.run(backend.sio_app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
