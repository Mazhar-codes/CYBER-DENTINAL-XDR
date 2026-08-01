"""
Centralized configuration for Cyber Sentinel XDR backend.
All hardcoded paths and thresholds live here — override via environment variables or .env file.

.env search order (first match wins):
  1. D:\\Cyber Sentinal\\.env   (project root, one level above Backend/)
  2. Backend\\.env              (alongside this file)

python-dotenv is optional — if absent the module still works and values fall
through to os.environ / the hardcoded defaults below.
"""
import os
import sys
from pathlib import Path

# Frozen-aware base + data roots.
#   BASE_DIR   — where the READ-ONLY model artifacts live.
#   DATA_ROOT  — WRITABLE runtime output (reports, etc.).
#
# script mode (dev):
#   BASE_DIR  = Backend/ (this file's dir); models load from BASE_DIR and the
#               sibling folders under BASE_DIR.parent (the repo root).
#   DATA_ROOT = the repo root, matching the existing on-disk layout.
#
# frozen backend.exe (PyInstaller onedir):
#   BASE_DIR  = <bundle>/Backend  — the spec bundles model files preserving the
#               dev layout (<bundle>/Backend, <bundle>/User Behavior, ...), so
#               BASE_DIR.parent still resolves the sibling model folders.
#   DATA_ROOT = %PROGRAMDATA%\CyberSentinel\server — writable and stable
#               (the install dir is read-only for a service account).
if getattr(sys, "frozen", False):
    BASE_DIR = Path(sys._MEIPASS) / "Backend"
    DATA_ROOT = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "CyberSentinel" / "server"
else:
    BASE_DIR = Path(__file__).parent
    DATA_ROOT = BASE_DIR.parent

# Built React dashboard directory, served same-origin by the backend.
#   dev:    <repo>/Cyber Sentinal XDR Frontend/build
#   frozen: <bundle>/frontend  (backend.spec bundles the build/ folder there)
if getattr(sys, "frozen", False):
    _FRONTEND_DEFAULT = Path(sys._MEIPASS) / "frontend"
else:
    _FRONTEND_DEFAULT = BASE_DIR.parent / "Cyber Sentinal XDR Frontend" / "build"

# ---------------------------------------------------------------------------
# Load .env (project root preferred, Backend/ as fallback)
# ---------------------------------------------------------------------------
try:
    from dotenv import load_dotenv as _load_dotenv

    _root_env = BASE_DIR.parent / ".env"
    _local_env = BASE_DIR / ".env"
    if _root_env.exists():
        _load_dotenv(dotenv_path=_root_env, override=False)
    elif _local_env.exists():
        _load_dotenv(dotenv_path=_local_env, override=False)
except ImportError:
    pass  # python-dotenv not installed — rely on os.environ / defaults


def _env(key: str, default: str) -> str:
    return os.getenv(key, default)


class _Settings:
    # --- Paths ---
    model_dir: str = _env("MODEL_DIR", str(BASE_DIR))
    user_model_dir: str = _env("USER_MODEL_DIR", str(BASE_DIR.parent / "User Behavior" / "final_model_backend_only"))
    user_log_dir: str = _env("USER_LOG_DIR", r"C:\XDR_Logs")
    suricata_eve_path: str = _env("SURICATA_EVE_PATH", r"C:\SuricataLogs\eve.json")
    sysmon_log_path: str = _env("SYSMON_LOG_PATH", r"C:\winlogbeat\logs\sysmon_events.json")
    sysmon_model_dir: str = _env("SYSMON_MODEL_DIR", str(BASE_DIR.parent / "System Behavior" / "System_Behavior_Model" / "DETECTOR1" / "saved_model_v3"))
    frontend_dir: str = _env("XDR_FRONTEND_DIR", str(_FRONTEND_DEFAULT))

    # --- Server ---
    backend_host: str = _env("BACKEND_HOST", "0.0.0.0")
    backend_port: int = int(_env("BACKEND_PORT", "8000"))
    backend_url: str = _env("BACKEND_URL", "http://127.0.0.1:8000")

    # --- MongoDB ---
    # Set MONGO_URI in .env to the MongoDB Atlas SRV connection string.
    # Fallback is localhost; Atlas URI must never be hardcoded here (credentials in .env only).
    mongo_uri: str = _env("MONGO_URI", "mongodb://localhost:27017")
    mongo_db: str = _env("MONGO_DB", "cyber_sentinel")

    # --- Fusion weights (must sum to 1.0) ---
    weight_network: float = float(_env("WEIGHT_NETWORK", "0.35"))
    weight_user:    float = float(_env("WEIGHT_USER",    "0.30"))
    weight_system:  float = float(_env("WEIGHT_SYSTEM",  "0.15"))
    weight_malware: float = float(_env("WEIGHT_MALWARE", "0.20"))

    # --- Threat score thresholds ---
    fusion_high_threshold: float = float(_env("FUSION_HIGH_THRESHOLD", "0.70"))
    fusion_critical_threshold: float = float(_env("FUSION_CRITICAL_THRESHOLD", "0.85"))

    # --- Timing ---
    user_behavior_interval_seconds: int = int(_env("USER_BEHAVIOR_INTERVAL", "60"))
    monitoring_cycle_seconds: int = int(_env("MONITORING_CYCLE_SECONDS", "10"))

    # --- Security ---
    api_key: str = _env("XDR_API_KEY", "changeme-dev-key")

    # --- JWT / Auth ---
    jwt_secret_key: str = _env("JWT_SECRET_KEY", "CHANGE_ME_IN_PRODUCTION_32chars_min")
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = int(_env("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
    refresh_token_expire_days: int = int(_env("REFRESH_TOKEN_EXPIRE_DAYS", "7"))
    bcrypt_rounds: int = int(_env("BCRYPT_ROUNDS", "12"))
    mfa_issuer: str = _env("MFA_ISSUER", "CyberSentinelXDR")
    device_trust_expire_days: int = int(_env("DEVICE_TRUST_EXPIRE_DAYS", "7"))
    backup_code_count: int = int(_env("BACKUP_CODE_COUNT", "10"))

    # --- Email / SMTP ---
    smtp_host: str = _env("SMTP_HOST", "smtp.gmail.com")
    smtp_port: int = int(_env("SMTP_PORT", "587"))
    smtp_user: str = _env("SMTP_USER", "")
    smtp_password: str = _env("SMTP_PASSWORD", "")
    smtp_from_name: str = _env("SMTP_FROM_NAME", "Cyber Sentinel XDR")
    smtp_enabled: bool = _env("SMTP_ENABLED", "false").lower() in ("1", "true", "yes")
    frontend_url: str = _env("FRONTEND_URL", "http://localhost:3000")

    # --- User Behavior Analysis ---
    # Lookback window (minutes) used by Get-WinEvent primary path and Winlogbeat
    # when no override is supplied.  120 minutes gives the IsolationForest enough
    # behavioral history to distinguish anomalies from normal variance.
    # User behavior scoring works via Get-WinEvent by default on any Windows
    # machine; Winlogbeat is an optional enhancement for richer field data.
    uba_lookback_minutes: int = int(_env("UBA_LOOKBACK_MINUTES", "120"))

    # --- Process management ---
    # User behavior works via Get-WinEvent by default; set START_WINLOGBEAT=true
    # only if Winlogbeat is installed and you want it used as the data source.
    start_winlogbeat: bool = _env("START_WINLOGBEAT", "false").lower() in ("1", "true", "yes")

    # --- Incident reports ---
    # Directory where PDF incident reports are saved.
    # Override with XDR_REPORTS_DIR env var for non-default deployments.
    reports_dir: str = _env("XDR_REPORTS_DIR", str(DATA_ROOT / "reports"))

    # --- SOAR ---
    # Network interface name used by isolate_host SOAR action on the server host.
    # Override with XDR_ISOLATE_INTERFACE env var if the interface name differs
    # (e.g. XDR_ISOLATE_INTERFACE=Wi-Fi for wireless deployments).
    soar_isolate_interface: str = _env("XDR_ISOLATE_INTERFACE", "Ethernet")

    # --- Malware scan path allowlist ---
    scan_allowed_roots: list = [
        r"C:\Users",
        r"C:\Temp",
        r"C:\Windows\Temp",
        r"C:\ProgramData",
        r"C:\Downloads",
        str(DATA_ROOT),
    ]


settings = _Settings()

import sys as _sys


def _validate_secrets(s: _Settings) -> None:
    errors = []
    if s.api_key in ("changeme-dev-key", "", None):
        errors.append("XDR_API_KEY must be set to a strong value in .env")
    if s.jwt_secret_key in ("CHANGE_ME_IN_PRODUCTION_32chars_min", "", None):
        errors.append("JWT_SECRET_KEY must be set to a strong value in .env")
    if errors:
        for e in errors:
            print(f"[STARTUP FATAL] {e}", file=_sys.stderr)
        _sys.exit(1)


_validate_secrets(settings)
