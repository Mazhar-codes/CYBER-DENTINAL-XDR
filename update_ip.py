"""
update_ip.py — Auto-detect the machine's current LAN IP and patch both .env files.

Run this once before starting the XDR backend + frontend, or let start_xdr.bat
call it automatically.
"""
import re
import socket
import sys
from pathlib import Path

ROOT        = Path(__file__).parent
BACKEND_ENV = ROOT / ".env"
FRONTEND_ENV = ROOT / "Cyber Sentinal XDR Frontend" / ".env"


def get_local_ip() -> str:
    """Return the machine's primary LAN IP (no packet is actually sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def patch_env(path: Path, replacements: dict[str, str]) -> bool:
    """
    For each key in replacements, find the line  KEY=<anything>
    and replace the value part with replacements[key].
    Returns True if the file was modified.
    """
    if not path.exists():
        print(f"  [WARN] File not found: {path}")
        return False

    original = path.read_text(encoding="utf-8")
    updated  = original

    for key, new_value in replacements.items():
        pattern     = rf"^({re.escape(key)}=).*$"
        replacement = rf"\g<1>{new_value}"
        updated, n  = re.subn(pattern, replacement, updated, flags=re.MULTILINE)
        if n == 0:
            # Key not present — append it
            updated = updated.rstrip("\n") + f"\n{key}={new_value}\n"
            print(f"  [ADD]   {key}={new_value}")
        else:
            print(f"  [SET]   {key}={new_value}")

    if updated != original:
        path.write_text(updated, encoding="utf-8")
        return True
    return False


def main():
    ip = get_local_ip()
    print(f"\n  Detected LAN IP: {ip}\n")

    print(f"  Patching: {BACKEND_ENV}")
    patch_env(BACKEND_ENV, {
        "FRONTEND_URL": f"http://{ip}:3000",
    })

    print(f"\n  Patching: {FRONTEND_ENV}")
    patch_env(FRONTEND_ENV, {
        "REACT_APP_BACKEND_URL": f"http://{ip}:8000",
    })

    print(f"\n  Done. Both .env files now point to {ip}.\n")


if __name__ == "__main__":
    main()
