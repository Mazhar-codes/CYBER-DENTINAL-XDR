"""
Cyber Sentinel XDR - Licensing / Activation core
=================================================

A single, dependency-free (pure Python standard library) module shared by:

  * server_control.py        -> ServerControl.exe   (product = "server")
  * endpoint_agent/agent.py  -> CyberSentinelAgent.exe (product = "endpoint")

and, on the *vendor* side only, by the private key generator (keygen.py).

What it does
------------
  * Defines a compact, typeable, HMAC-signed **activation code** format.
      - The signed payload carries: product (server/endpoint), kind
        (trial / custom / universal), duration in days, and a random nonce.
      - A code minted for the SERVER is cryptographically rejected on an
        ENDPOINT and vice-versa (the product byte is inside the signature).
  * Binds an activation to THIS machine (hardware id) and records the code's
    nonce in a permanent "consumed" ledger, mirrored in BOTH
    C:\\ProgramData\\CyberSentinel and HKLM\\SOFTWARE\\CyberSentinel.
      - Because that state lives outside the install directory, uninstalling
        and reinstalling the product does NOT return an expired trial: the
        same trial code is refused ("already used on this machine") and a NEW
        code must be entered.
  * Enforces expiry with basic clock-rollback detection.
  * Ships a small allow-list of perpetual **universal** master codes that
    always work (separate ones for server and endpoint) and are exempt from
    the single-use ledger and from expiry.

Security note
-------------
This uses a symmetric HMAC secret embedded in the shipped binaries. That is a
deliberate, common trade-off for offline desktop licensing: it keeps the agent
lean (no crypto dependency) and needs no license server. A determined reverse
engineer who extracts the secret could forge codes; that is out of scope for
this product's threat model (casual trial-reset / reinstall abuse).

CLI (used by the installers and for testing)
--------------------------------------------
  python xdr_license.py status   --product server
  python xdr_license.py check    --product server --code CSXS-....
  python xdr_license.py activate --product server --code CSXS-....
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import time

# ---------------------------------------------------------------------------
# Master signing secret  (KEEP PRIVATE - also lives in keygen.py)
# ---------------------------------------------------------------------------
_SECRET = bytes.fromhex(
    "38222666f3c0bc56af6f159399d261f458f8c0301659a2d1e3de92b27eb622ef"
)

# Hardcoded perpetual master codes. These always work, never expire, are not
# tracked in the single-use ledger. Separate sets per product. (They are ALSO
# valid by signature, so string edits still fail the crypto check.)
UNIVERSAL_CODES = {
    "server": {
        "CSXS-AFJVK-AAAMZ-2Q57X-V5DYE-3EPBF-NBZVJ-7ZAY",
        "CSXS-AFJVK-AAAQ3-LSFJ2-OFVPA-G5MFC-2CWAU-IBZA",
    },
    "endpoint": {
        "CSXE-AFCVK-AAAJE-QRN7J-KMY73-Y3MPL-4NU3D-OSZE",
        "CSXE-AFCVK-AAAQT-2BIFB-O3NHP-VPVYG-AZA6O-DIHY",
    },
}

# product name  <->  single-byte code embedded in the payload
_PROD_BYTE = {"server": ord("S"), "endpoint": ord("E")}
_BYTE_PROD = {v: k for k, v in _PROD_BYTE.items()}

# kind byte
_KIND_TRIAL = ord("T")
_KIND_CUSTOM = ord("C")
_KIND_UNIVERSAL = ord("U")
_KIND_NAME = {_KIND_TRIAL: "trial", _KIND_CUSTOM: "custom", _KIND_UNIVERSAL: "universal"}

_FMT_VERSION = 1
_PAYLOAD_LEN = 11          # ver(1) prod(1) kind(1) days(2) nonce(6)
_SIG_LEN = 10              # truncated HMAC-SHA256
_CLOCK_SKEW = 86400        # 1 day tolerance for clock-rollback detection

DATA_DIR = os.path.join(
    os.environ.get("ProgramData", r"C:\ProgramData"), "CyberSentinel", "license"
)
_REG_PATH = r"SOFTWARE\CyberSentinel\License"


class LicenseError(Exception):
    """Raised when a code cannot be parsed / verified."""


# ---------------------------------------------------------------------------
# Base32 helpers (RFC 4648, unpadded, A-Z2-7 - no easily-confused 0/1/8/9)
# ---------------------------------------------------------------------------

def _b32(data: bytes) -> str:
    return base64.b32encode(data).decode("ascii").rstrip("=")


def _unb32(s: str) -> bytes:
    s = s.upper()
    return base64.b32decode(s + "=" * (-len(s) % 8))


# ---------------------------------------------------------------------------
# Code minting (vendor side) + parsing / verification (client side)
# ---------------------------------------------------------------------------

def make_code(product: str, kind_byte: int, days: int) -> str:
    """Mint a signed activation code. Used by the private keygen only."""
    if product not in _PROD_BYTE:
        raise LicenseError(f"unknown product {product!r}")
    days = max(0, min(0xFFFF, int(days)))
    payload = (
        bytes([_FMT_VERSION, _PROD_BYTE[product], kind_byte])
        + struct.pack(">H", days)
        + os.urandom(6)
    )
    sig = hmac.new(_SECRET, payload, hashlib.sha256).digest()[:_SIG_LEN]
    body = _b32(payload + sig)
    letter = chr(_PROD_BYTE[product])
    grouped = "-".join(body[i : i + 5] for i in range(0, len(body), 5))
    return f"CSX{letter}-{grouped}"


def _normalize(code: str) -> str:
    return re.sub(r"[^A-Za-z0-9]", "", code or "").upper()


def parse_code(code: str) -> dict:
    """
    Verify a code's signature and decode its fields.
    Returns {product, kind, kind_name, days, nonce, canonical}.
    Raises LicenseError on any tampering / malformed input.
    """
    s = _normalize(code)
    if not s.startswith("CSX") or len(s) < 4:
        raise LicenseError("Not a Cyber Sentinel activation code.")
    body = s[4:]  # drop "CSX" + product letter (product is re-checked from payload)
    try:
        raw = _unb32(body)
    except Exception:
        raise LicenseError("Malformed activation code.")
    if len(raw) != _PAYLOAD_LEN + _SIG_LEN:
        raise LicenseError("Malformed activation code (wrong length).")
    payload, sig = raw[:_PAYLOAD_LEN], raw[_PAYLOAD_LEN:]
    expect = hmac.new(_SECRET, payload, hashlib.sha256).digest()[:_SIG_LEN]
    if not hmac.compare_digest(sig, expect):
        raise LicenseError("Invalid activation code (signature check failed).")
    ver, prod_b, kind_b = payload[0], payload[1], payload[2]
    if ver != _FMT_VERSION or prod_b not in _BYTE_PROD:
        raise LicenseError("Unsupported activation code version.")
    days = struct.unpack(">H", payload[3:5])[0]
    return {
        "product": _BYTE_PROD[prod_b],
        "kind": kind_b,
        "kind_name": _KIND_NAME.get(kind_b, "unknown"),
        "days": days,
        "nonce": payload[5:11].hex(),
        "canonical": _canonical(s),
    }


def _canonical(normalized: str) -> str:
    body = normalized[4:]
    grouped = "-".join(body[i : i + 5] for i in range(0, len(body), 5))
    return f"{normalized[:4]}-{grouped}"


# ---------------------------------------------------------------------------
# Hardware fingerprint - stable across app reinstalls (uses OS MachineGuid)
# ---------------------------------------------------------------------------

def hardware_id() -> str:
    parts = []
    try:
        import winreg  # noqa: PLC0415

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Cryptography",
            0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as k:
            parts.append(winreg.QueryValueEx(k, "MachineGuid")[0])
    except Exception:
        pass
    try:
        import platform  # noqa: PLC0415

        parts.append(platform.node())
    except Exception:
        pass
    if not parts:
        import uuid  # noqa: PLC0415

        parts.append(str(uuid.getnode()))
    digest = hashlib.sha256("|".join(parts).encode("utf-8", "replace")).hexdigest()
    return digest[:32]


# ---------------------------------------------------------------------------
# Persistent state - file (ProgramData) + registry (HKLM) mirror
# ---------------------------------------------------------------------------

def _state_file(product: str) -> str:
    return os.path.join(DATA_DIR, f"state_{product}.json")


def _ledger_file() -> str:
    return os.path.join(DATA_DIR, "consumed.txt")


def _ensure_dir():
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass


# ---- registry helpers (best-effort; require admin, both apps run elevated) --

def _reg_open(create=False):
    import winreg  # noqa: PLC0415

    access = winreg.KEY_READ | winreg.KEY_WOW64_64KEY
    if create:
        access = winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
        return winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, _REG_PATH, 0, access)
    return winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, _REG_PATH, 0, access)


def _reg_write_state(product: str, data: dict):
    try:
        import winreg  # noqa: PLC0415

        with _reg_open(create=True) as k:
            winreg.SetValueEx(
                k, f"state_{product}", 0, winreg.REG_SZ, json.dumps(data)
            )
    except Exception:
        pass


def _reg_read_state(product: str):
    try:
        import winreg  # noqa: PLC0415

        with _reg_open() as k:
            raw = winreg.QueryValueEx(k, f"state_{product}")[0]
            return json.loads(raw)
    except Exception:
        return None


def _reg_add_consumed(nonce: str):
    try:
        import winreg  # noqa: PLC0415

        access = winreg.KEY_ALL_ACCESS | winreg.KEY_WOW64_64KEY
        sub = _REG_PATH + r"\Consumed"
        with winreg.CreateKeyEx(winreg.HKEY_LOCAL_MACHINE, sub, 0, access) as k:
            winreg.SetValueEx(k, nonce, 0, winreg.REG_DWORD, 1)
    except Exception:
        pass


def _reg_consumed_set() -> set:
    out = set()
    try:
        import winreg  # noqa: PLC0415

        sub = _REG_PATH + r"\Consumed"
        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, sub, 0,
            winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
        ) as k:
            i = 0
            while True:
                try:
                    name, _, _ = winreg.EnumValue(k, i)
                    out.add(name)
                    i += 1
                except OSError:
                    break
    except Exception:
        pass
    return out


# ---- consumed-nonce ledger (union of file + registry) ----------------------

def _consumed_set() -> set:
    out = set(_reg_consumed_set())
    try:
        with open(_ledger_file(), "r", encoding="ascii", errors="ignore") as f:
            for line in f:
                v = line.strip()
                if v:
                    out.add(v)
    except Exception:
        pass
    return out


def _add_consumed(nonce: str):
    _ensure_dir()
    try:
        with open(_ledger_file(), "a", encoding="ascii") as f:
            f.write(nonce + "\n")
    except Exception:
        pass
    _reg_add_consumed(nonce)


# ---- state read/write (choose the freshest valid record) -------------------

def _write_state(product: str, data: dict):
    _ensure_dir()
    try:
        with open(_state_file(product), "w", encoding="ascii") as f:
            json.dump(data, f)
    except Exception:
        pass
    _reg_write_state(product, data)


def _read_state(product: str):
    hwid = hardware_id()
    candidates = []
    try:
        with open(_state_file(product), "r", encoding="ascii") as f:
            candidates.append(json.load(f))
    except Exception:
        pass
    reg = _reg_read_state(product)
    if reg:
        candidates.append(reg)
    # keep only records that belong to THIS machine
    valid = [c for c in candidates if isinstance(c, dict) and c.get("hwid") == hwid]
    if not valid:
        return None
    # prefer the most recently activated
    return max(valid, key=lambda c: c.get("activated_at", 0))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def activate(code: str, product: str) -> dict:
    """
    Validate and persist an activation. Returns:
        {ok: bool, message: str, kind: str, expires_at: float|None}
    """
    norm = _normalize(code)
    canonical = _canonical(norm) if norm.startswith("CSX") and len(norm) > 4 else norm

    # Universal master codes: verify signature, never expire, never consumed.
    is_listed_universal = canonical in UNIVERSAL_CODES.get(product, set())
    try:
        info = parse_code(code)
    except LicenseError as e:
        return {"ok": False, "message": str(e), "kind": None, "expires_at": None}

    if info["product"] != product:
        other = info["product"]
        return {
            "ok": False,
            "message": f"This is a {other.upper()} activation code. "
                       f"Enter a {product.upper()} code instead.",
            "kind": None,
            "expires_at": None,
        }

    now = time.time()
    hwid = hardware_id()

    if info["kind"] == _KIND_UNIVERSAL or is_listed_universal:
        state = {
            "product": product, "hwid": hwid, "kind": "universal",
            "nonce": info["nonce"], "activated_at": now,
            "expires_at": None, "last_seen": now,
        }
        _write_state(product, state)
        return {"ok": True, "message": "Activated (universal license).",
                "kind": "universal", "expires_at": None}

    # Trial / custom: single-use per machine.
    if info["nonce"] in _consumed_set():
        return {
            "ok": False,
            "message": "This activation code has already been used on this "
                       "computer. Please enter a NEW activation code.",
            "kind": None, "expires_at": None,
        }

    days = info["days"] or 0
    expires = now + days * 86400
    state = {
        "product": product, "hwid": hwid, "kind": info["kind_name"],
        "nonce": info["nonce"], "activated_at": now,
        "expires_at": expires, "last_seen": now,
    }
    _write_state(product, state)
    _add_consumed(info["nonce"])
    return {
        "ok": True,
        "message": f"Activated - {days}-day license.",
        "kind": info["kind_name"], "expires_at": expires,
    }


def check_license(product: str) -> dict:
    """
    Report current license state for *product*. Returns:
        {status, message, remaining, expires_at, kind}
      status in {"ACTIVE", "EXPIRED", "NOT_ACTIVATED", "TAMPERED"}
      remaining = seconds left (None if perpetual / not active)
    """
    state = _read_state(product)
    if not state:
        return {"status": "NOT_ACTIVATED", "message": "Not activated.",
                "remaining": None, "expires_at": None, "kind": None}

    kind = state.get("kind")
    expires = state.get("expires_at")

    if kind == "universal" or expires is None:
        return {"status": "ACTIVE", "message": "Licensed (universal).",
                "remaining": None, "expires_at": None, "kind": "universal"}

    now = time.time()
    last_seen = state.get("last_seen", now)

    # clock-rollback detection: if the clock went backwards well beyond the
    # allowed skew, refuse rather than silently extend the trial.
    if now < last_seen - _CLOCK_SKEW:
        return {"status": "TAMPERED",
                "message": "System clock inconsistency detected. "
                           "Please enter a new activation code.",
                "remaining": None, "expires_at": expires, "kind": kind}

    if now >= expires:
        return {"status": "EXPIRED",
                "message": "Trial period has ended. Enter a new activation code.",
                "remaining": 0, "expires_at": expires, "kind": kind}

    # advance the high-water mark so the clock can't be rewound later
    if now > last_seen:
        state["last_seen"] = now
        _write_state(product, state)

    remaining = expires - now
    return {"status": "ACTIVE",
            "message": f"Licensed - {format_remaining(remaining)} remaining.",
            "remaining": remaining, "expires_at": expires, "kind": kind}


def is_licensed(product: str) -> bool:
    return check_license(product)["status"] == "ACTIVE"


def format_remaining(seconds) -> str:
    if seconds is None:
        return "unlimited"
    seconds = int(max(0, seconds))
    d, r = divmod(seconds, 86400)
    h, r = divmod(r, 3600)
    m, _ = divmod(r, 60)
    if d:
        return f"{d}d {h}h"
    if h:
        return f"{h}h {m}m"
    return f"{m}m"


# ---------------------------------------------------------------------------
# CLI - used by the installers (--activate) and for testing
# ---------------------------------------------------------------------------

def _cli(argv=None) -> int:
    import argparse  # noqa: PLC0415

    p = argparse.ArgumentParser(description="Cyber Sentinel XDR license tool")
    p.add_argument("command", choices=["status", "check", "activate", "hwid"])
    p.add_argument("--product", choices=["server", "endpoint"], default="server")
    p.add_argument("--code", default="")
    args = p.parse_args(argv)

    if args.command == "hwid":
        print(hardware_id())
        return 0

    if args.command == "status":
        st = check_license(args.product)
        print(f"{st['status']}: {st['message']}")
        return 0 if st["status"] == "ACTIVE" else 1

    if args.command == "check":
        try:
            info = parse_code(args.code)
        except LicenseError as e:
            print(f"INVALID: {e}")
            return 1
        if info["product"] != args.product:
            print(f"WRONG_PRODUCT: code is for {info['product']}")
            return 2
        print(f"VALID: {info['kind_name']} {info['days']}d product={info['product']}")
        return 0

    if args.command == "activate":
        res = activate(args.code, args.product)
        print(("OK: " if res["ok"] else "FAIL: ") + res["message"])
        return 0 if res["ok"] else 1

    return 0


if __name__ == "__main__":
    sys.exit(_cli())
