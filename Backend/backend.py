"""
Ingestion & Orchestration Agent  —  Cyber Sentinel XDR
Central FastAPI + Socket.IO server that ties every detection agent together.

Start:
    uvicorn backend:sio_app --host 0.0.0.0 --port 8000 --reload
"""
import asyncio
import ctypes
import getpass
import json
import logging
import math
import platform
import random
import re
import signal
import socket
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Optional

import uuid as _uuid

import socketio
import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Request, Security
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.security import APIKeyHeader
from pydantic import BaseModel, Field, validator

sys.path.insert(0, str(Path(__file__).parent))

from config import settings
import os
os.environ.setdefault("USER_LOG_DIR", r"C:\winlogbeat\logs")
os.environ.setdefault("USER_MODEL_DIR", str(Path(__file__).parent.parent / "User Behavior" / "final_model_backend_only"))

from agents.network_detection_agent import NetworkDetectionAgent
from agents.user_behavior_agent import UserBehaviorAgent, _DEFAULT_RULES as _DEFAULT_USER_RULES
from agents.fusion_engine_agent import FusionEngineAgent
from agents.shap_agent import SHAPAgent
from agents.malware_analysis_agent import MalwareAnalysisAgent
from agents.system_monitor_agent import SystemMonitorAgent, _sysmon_event_ring as _system_sysmon_ring
from agents.sysmon_behavior_agent import SysmonBehaviorAgent
import fusion_engine as _fe
from response_engine import generate_response_plan
from report_generator import generate_incident_report
from attack_graph import AttackGraphEngine

# Winlogbeat lifecycle manager — auto-start/stop tied to monitoring lifecycle.
# Gracefully degrades if the module or Winlogbeat itself is not installed.
try:
    from winlogbeat_manager import (
        start_winlogbeat as _wlb_start,
        stop_winlogbeat as _wlb_stop,
        find_winlogbeat as _wlb_find,
        winlogbeat_is_running as _wlb_is_running,
    )
    _WINLOGBEAT_MANAGER_AVAILABLE = True
except ImportError:
    _WINLOGBEAT_MANAGER_AVAILABLE = False

    async def _wlb_start() -> bool:  # type: ignore[misc]
        return False

    async def _wlb_stop() -> None:  # type: ignore[misc]
        return

    def _wlb_find():  # type: ignore[misc]
        return None

    def _wlb_is_running() -> bool:  # type: ignore[misc]
        return False

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Single-instance guard — prevents a second backend from starting.
#
# A launcher (Control Panel + Endpoint Agent GUI) can be clicked more than once,
# or a manual `uvicorn` can be started alongside a launcher one. On Windows two
# servers can both "bind" port 8000 (SO_REUSEADDR last-bind-wins) and the kernel
# then splits incoming connections between them non-deterministically — the agent
# and dashboard randomly hit a live or dead-end socket, producing intermittent
# timeouts and an empty dashboard. We make that impossible: the first backend to
# start grabs an exclusive lock on a dedicated loopback port; any second backend
# fails to grab it, logs a clear message, and exits before binding port 8000.
#
# The guard socket is bound WITHOUT SO_REUSEADDR so a duplicate bind fails
# deterministically (no race), and is kept alive for the whole process lifetime.
# Set XDR_SINGLETON_GUARD=0 to disable (e.g. to run two backends on two ports).
# ---------------------------------------------------------------------------
_SINGLETON_GUARD_SOCK: "Optional[socket.socket]" = None


def _acquire_singleton_lock() -> None:
    global _SINGLETON_GUARD_SOCK
    if os.environ.get("XDR_SINGLETON_GUARD", "1").lower() in ("0", "false", "no"):
        return
    try:
        guard_port = int(os.environ.get("XDR_SINGLETON_GUARD_PORT", "8123"))
    except ValueError:
        guard_port = 8123
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # Deliberately do NOT set SO_REUSEADDR here — we WANT a second bind to fail.
    try:
        sock.bind(("127.0.0.1", guard_port))
        sock.listen(1)
    except OSError:
        logger.critical(
            "ANOTHER CYBER SENTINEL BACKEND IS ALREADY RUNNING "
            "(singleton guard port %d is in use). Refusing to start a second "
            "instance — a duplicate backend would split traffic on port 8000 and "
            "break the agent + dashboard. Stop the other backend first, or set "
            "XDR_SINGLETON_GUARD=0 to override.", guard_port,
        )
        try:
            sock.close()
        except Exception:
            pass
        sys.exit(1)
    _SINGLETON_GUARD_SOCK = sock  # keep the lock for the process lifetime
    logger.info("Single-instance lock acquired on 127.0.0.1:%d", guard_port)


_acquire_singleton_lock()

# ---------------------------------------------------------------------------
# MongoDB (optional — gracefully degrades if unavailable)
# ---------------------------------------------------------------------------
try:
    from pymongo.errors import OperationFailure as _OperationFailure
except ImportError:
    _OperationFailure = None  # type: ignore

try:
    from pymongo import MongoClient, DESCENDING, ASCENDING
    _mongo = MongoClient(
        settings.mongo_uri,
        serverSelectionTimeoutMS=20_000,   # Atlas SRV needs DNS lookup + TLS — give 20 s
        connectTimeoutMS=20_000,
        socketTimeoutMS=30_000,
    )
    _db = _mongo[settings.mongo_db]
    _db.command("ping")
    MONGO_OK = True
    logger.info(f"MongoDB connected — db='{settings.mongo_db}'")
except Exception as _e:
    MONGO_OK = False
    _db = None
    logger.warning(f"MongoDB unavailable — data will not be persisted: {_e}")

# ---------------------------------------------------------------------------
# Atlas M0 storage management — collection caps and trim helpers
# ---------------------------------------------------------------------------
_COLLECTION_CAP = {
    "logs":                 5_000,
    "predictions":          3_000,
    "alerts":               2_000,
    "shap_explanations":    1_000,
    "commands":               500,
    "endpoints":              200,
    "user_behavior_cycles":   500,
    "malware_scans":         1_000,
    "malware_events":        2_000,
    "fused_alerts":          1_000,
    "sysmon_alerts":         1_000,
    "raw_events":            2_000,
    "correlated_alerts":     1_000,
    "high_severity_alerts":    500,
    # Auth collections — sessions and audit_logs are capped; users are unlimited
    "sessions":             10_000,
    "audit_logs":           50_000,
    # Security event log — unauthorized access attempts
    "security_events":       5_000,
    # Credential recovery collections
    "password_reset_tokens":  1_000,   # one-time 10-min tokens; pruned aggressively
    "mfa_recovery_requests":    500,   # admin-reviewed recovery queue
    # Endpoint telemetry & command collections
    "endpoint_logs":        10_000,
    "endpoint_registry":       500,
    "endpoint_commands":     2_000,
    "endpoint_timelines":   50_000,
    "honeypot_events":       5_000,   # decoy-port intrusion hits (deception layer)
    # EDR Orchestration — response plans and incident reports
    "response_plans":        2_000,
    # incident_reports has no cap (PDFs are stored on disk; only metadata here)
    # Attack Graph — persistent entity-relationship graph
    "attack_graph_nodes":    5_000,
    "attack_graph_edges":   10_000,
    # Correlated incident tracking
    "incidents":            10_000,
    # Public contact form submissions
    "contact_inquiries":     1_000,
}

# Incremented each monitoring cycle; used to throttle periodic trim
_cycle_count: int = 0
# Tracks consecutive cycles where Suricata produced 0 flows; used for diagnostic logging
_zero_flow_cycles: int = 0


def _is_storage_full_error(exc: Exception) -> bool:
    """Return True if the exception indicates Atlas free-tier storage exhaustion."""
    msg = str(exc).lower()
    indicators = ("storage", "limit", "8000", "13297", "exceededtimelimit")
    if any(ind in msg for ind in indicators):
        return True
    # pymongo OperationFailure carries a numeric code
    if _OperationFailure and isinstance(exc, _OperationFailure) and exc.code in (8000, 13297):
        return True
    return False


def _trim_collection(collection: str, keep_newest: int) -> None:
    """Delete the oldest documents from *collection* so that at most
    *keep_newest* documents remain.  No-ops when MongoDB is unavailable."""
    if _db is None:
        return
    try:
        col = _db[collection]
        count = col.count_documents({})
        excess = count - keep_newest
        if excess <= 0:
            return
        # Find the _id of the last document to delete (oldest excess docs)
        # Sort ascending (_id = ObjectId, monotonically increasing), skip to
        # the (excess-1) position, take 1 — that is the cutoff document.
        cutoff_doc = col.find({}, {"_id": 1}).sort("_id", ASCENDING).skip(excess - 1).limit(1)
        cutoff_list = list(cutoff_doc)
        if not cutoff_list:
            return
        cutoff_id = cutoff_list[0]["_id"]
        result = col.delete_many({"_id": {"$lte": cutoff_id}})
        logger.info(
            f"Atlas trim: removed {result.deleted_count} old docs from "
            f"'{collection}' (was {count}, cap {keep_newest})"
        )
    except Exception as e:
        logger.error(f"Atlas trim error for '{collection}': {e}")


def _periodic_trim() -> None:
    """Proactively trim all capped collections to their configured limits.
    Called every 100 monitoring cycles to prevent gradual Atlas M0 fill.
    Also trims in-memory dedup/cooldown dicts to prevent unbounded growth."""
    # --- MongoDB collection caps ---
    if _db is not None:
        logger.info("Atlas periodic trim: checking all collections")
        for col_name, cap in _COLLECTION_CAP.items():
            _trim_collection(col_name, cap)

    # --- In-memory dict caps (500 entries each) ---
    _now_mono = time.monotonic()
    try:
        if len(_soc_alert_dedup) > 500:
            # Keep only entries from the last 60 s
            for k in [k for k, v in list(_soc_alert_dedup.items()) if _now_mono - v > 60]:
                _soc_alert_dedup.pop(k, None)
    except Exception:
        pass
    try:
        if len(_malware_direct_emit_ts) > 500:
            for k in [k for k, v in list(_malware_direct_emit_ts.items()) if _now_mono - v > 120]:
                _malware_direct_emit_ts.pop(k, None)
    except Exception:
        pass
    try:
        if len(_last_rp_ts) > 500:
            for k in [k for k, v in list(_last_rp_ts.items()) if _now_mono - v > 300]:
                _last_rp_ts.pop(k, None)
    except Exception:
        pass
    try:
        if len(_endpoint_ingest_rate) > 500:
            for k in [k for k, v in list(_endpoint_ingest_rate.items()) if _now_mono - v > 60]:
                _endpoint_ingest_rate.pop(k, None)
    except Exception:
        pass


def _save(collection: str, doc: dict):
    if not MONGO_OK:
        return
    doc.setdefault("ts", _now())
    clean_doc = {k: v for k, v in doc.items() if k != "_id"}
    try:
        _db[collection].insert_one(clean_doc)
    except Exception as e:
        if _is_storage_full_error(e):
            logger.warning(
                f"Atlas storage full detected on '{collection}' write — "
                f"trimming all collections to 50% of cap, then retrying"
            )
            # Trim every collection to 50 % of its cap to create headroom
            for col_name, cap in _COLLECTION_CAP.items():
                _trim_collection(col_name, max(1, cap // 2))
            # Single retry — do NOT loop
            try:
                clean_doc.pop("_id", None)   # insert_one may have added _id on failure
                _db[collection].insert_one(clean_doc)
                logger.info(f"Retry write to '{collection}' succeeded after trim")
            except Exception as retry_exc:
                logger.error(
                    f"MongoDB write to '{collection}' failed even after trim: {retry_exc}"
                )
        else:
            logger.error(f"MongoDB write error ({collection}): {e}")


def _check_windows_privileges() -> dict:
    """
    Check if the server process has the necessary Windows privileges for SOAR actions.
    Returns {"admin": bool, "warnings": list[str]}.
    Safe to call on non-Windows platforms — returns {"admin": False, "warnings": []}.
    Never raises.
    """
    result: dict = {"admin": False, "warnings": []}
    if sys.platform != "win32":
        return result
    try:
        result["admin"] = bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        pass
    if not result["admin"]:
        result["warnings"].append(
            "Backend not running as Administrator — server-side SOAR actions "
            "(block_ip, isolate_host, lock_account) will fail. "
            "Remediation: Run uvicorn as Administrator or configure the NSSM "
            "service with LocalSystem account."
        )
    return result


def _ensure_db_connected() -> bool:
    """
    Ping MongoDB and return True if the connection is healthy.
    Attempts a single reconnect if the current client is unresponsive.
    Never raises — returns False on any failure.
    """
    global _mongo, _db, MONGO_OK
    try:
        if _db is not None:
            _db.command("ping")
            MONGO_OK = True
            return True
    except Exception as _ping_exc:
        logger.warning("[DB] MongoDB ping failed: %s — attempting reconnect", _ping_exc)

    # Attempt reconnect
    try:
        from pymongo import MongoClient as _MC  # noqa: PLC0415
        _new_mongo = _MC(
            settings.mongo_uri,
            serverSelectionTimeoutMS=5_000,
            connectTimeoutMS=5_000,
            socketTimeoutMS=10_000,
        )
        _new_db = _new_mongo[settings.mongo_db]
        _new_db.command("ping")
        _mongo = _new_mongo
        _db = _new_db
        MONGO_OK = True
        logger.info("[DB] MongoDB reconnected successfully")
        return True
    except Exception as _reconnect_exc:
        logger.warning("[DB] MongoDB reconnect failed: %s", _reconnect_exc)
        MONGO_OK = False
        return False


def _now() -> str:
    """Return the current UTC time as an ISO-8601 string (existing behaviour — do not change)."""
    return datetime.now(timezone.utc).isoformat()


def _now_dt() -> datetime:
    """Return the current UTC time as a timezone-aware datetime object.
    Use this field for MongoDB TTL indexes which require a BSON date, not a string."""
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# Agent instances (initialised in startup)
# ---------------------------------------------------------------------------
_network_agent: Optional[NetworkDetectionAgent] = None
_user_agent: Optional[UserBehaviorAgent] = None
_fusion_agent: Optional[FusionEngineAgent] = None
_shap_agent: Optional[SHAPAgent] = None
_malware_agent: Optional[MalwareAnalysisAgent] = None
_system_agent: Optional[SystemMonitorAgent] = None
_sysmon_agent: Optional[SysmonBehaviorAgent] = None
_graph_engine: "AttackGraphEngine | None" = None
_monitoring_task: Optional[asyncio.Task] = None
_sysmon_ps_task: Optional[asyncio.Task] = None
_monitoring_active: bool = False   # True only while start-monitoring is in effect
_latest_system_score: float = 0.0
_latest_sysmon_score: float = 0.0
_malware_scan_task: Optional[asyncio.Task] = None
_last_system_alert_t: float = 0.0   # rate-limit system anomaly socket emissions
_latest_scores: dict = {
    "network":  {"score": 0.0, "ts": 0.0},
    "user":     {"score": 0.0, "ts": 0.0},
    "system":   {"score": 0.0, "ts": 0.0},
    "malware":  {"score": 0.0, "ts": 0.0},
}
_scores_lock = asyncio.Lock()

# ---------------------------------------------------------------------------
# Module-level startup timestamp — used by /health uptime_seconds field
# ---------------------------------------------------------------------------
_startup_time: float = time.time()

# ---------------------------------------------------------------------------
# In-memory revoked JWT JTI cache — bounded to 10 000 entries.
# Populated by /auth/logout; checked in _require_key_or_jwt and _require_jwt.
# Resets on restart (acceptable for dev/demo — production should use Redis).
# ---------------------------------------------------------------------------
_REVOKED_TOKENS: set = set()
_REVOKED_TOKENS_LOCK = asyncio.Lock()


async def _revoke_token(jti: str) -> None:
    """Add a JWT JTI to the in-memory revocation set. Thread-safe."""
    if not jti:
        return
    async with _REVOKED_TOKENS_LOCK:
        _REVOKED_TOKENS.add(jti)
        # Bounded eviction — drop entire set when it exceeds 10 000 entries.
        # Simple but effective for dev/demo; production should use Redis TTL.
        if len(_REVOKED_TOKENS) > 10_000:
            _REVOKED_TOKENS.clear()


def _is_token_revoked(jti: str) -> bool:
    """Return True if the JTI has been explicitly revoked via /auth/logout."""
    return bool(jti) and jti in _REVOKED_TOKENS


# Per-endpoint cooldown: prevent response plan spam (min 120 s between plans per endpoint)
_last_rp_ts: dict[str, float] = {}
_RP_COOLDOWN = 120.0

# Per-endpoint user-behaviour anomaly state (hysteresis + snooze), keyed by
# endpoint_id → {"anomaly_until": epoch, "snooze_until": epoch}. Hysteresis
# stops the per-tick ANOMALY/NORMAL flicker (the model score wobbles across the
# threshold every 5 s); once anomalous the state stays anomalous for
# _USER_ANOMALY_STICKY seconds. Snooze (set by POST /user-behavior/snooze)
# forces NORMAL for a chosen window so an analyst can silence a known late
# worker; when it expires, if the session is still anomalous the alarm re-fires.
_ep_user_state: dict[str, dict] = {}
_USER_ANOMALY_STICKY = 90.0   # seconds an anomaly persists after the last hot tick

# ---------------------------------------------------------------------------
# Endpoint telemetry rate-limiter — keyed by endpoint_id, value is last ingest time
# ---------------------------------------------------------------------------
_endpoint_ingest_rate: dict = {}   # {endpoint_id: float (monotonic time)}
_stale_ts_last_warn: dict = {}    # endpoint_id -> last warning monotonic time (rate-limit stale-clock log to once/5 min)
_endpoint_heartbeat_task: Optional[asyncio.Task] = None
# Tracks when this backend process started; used to hide stale registry entries
# from previous sessions until the endpoint agent reconnects.
_backend_session_start: datetime = datetime.utcnow()
_server_soar_task: Optional[asyncio.Task] = None

# soc_alert deduplication — same attack_type + sources within window → skip
_soc_alert_dedup: dict[str, float] = {}    # key → last monotonic emit time
_SOC_DEDUP_WINDOW: float = 30.0            # seconds between identical alerts

# Malware direct-emit cooldown — same file path within 60 s → skip
# Prevents duplicate Alert Stream entries when the file-watcher re-scans the
# same PE before the mtime changes.
_malware_direct_emit_ts: dict[str, float] = {}   # file_path → last monotonic emit time
_MALWARE_DIRECT_COOLDOWN: float = 60.0

# ---------------------------------------------------------------------------
# Per-endpoint FusionDecisionEngine cache — Gap 2+5
# Each endpoint gets its own EventBuffer + CorrelationEngine so cross-endpoint
# events do NOT pollute each other's context.  The global _fe instance receives
# every event as well for cross-endpoint APT correlation (unchanged behaviour).
# ---------------------------------------------------------------------------
_endpoint_engines: dict = {}   # {endpoint_id: FusionDecisionEngine}

# ---------------------------------------------------------------------------
# Capture process management (Suricata + Winlogbeat)
# ---------------------------------------------------------------------------
_suricata_proc: Optional[subprocess.Popen] = None
_winlogbeat_proc: Optional[subprocess.Popen] = None

_BASE = Path(__file__).parent
_WINLOGBEAT_DIR = _BASE.parent / "User Behavior" / "winlogbeat-9.3.3-windows-x86_64"

# ---------------------------------------------------------------------------
# Sysmon PowerShell forwarder — reads Get-WinEvent XML, feeds SysmonBehaviorAgent
# ---------------------------------------------------------------------------

_SYSMON_INTERESTING: frozenset = frozenset({"1","3","7","8","10","11","12","13","22","25"})

# Mutual exclusion flag: set to True by SysmonFileReader when Winlogbeat is active.
# When True, the PS forwarder loop exits to prevent double-processing of events.
_sysmon_winlogbeat_active: bool = False


def _parse_sysmon_xml(xml_str: str) -> Optional[dict]:
    """Parse a Sysmon event XML string (from $event.ToXml()) into a flat dict."""
    try:
        ns = "http://schemas.microsoft.com/win/2004/08/events/event"

        def _find(parent, tag):
            el = parent.find(f"{{{ns}}}{tag}")
            return el if el is not None else parent.find(tag)

        root = ET.fromstring(xml_str)
        sys_el = _find(root, "System")
        if sys_el is None:
            return None
        eid_el = _find(sys_el, "EventID")
        if eid_el is None:
            return None
        eid = (eid_el.text or "").strip()
        if eid not in _SYSMON_INTERESTING:
            return None

        ts_el = _find(sys_el, "TimeCreated")
        timestamp = ts_el.get("SystemTime", "") if ts_el is not None else ""

        event_data: dict = {}
        ed_el = _find(root, "EventData")
        if ed_el is not None:
            for data_el in ed_el:
                local = data_el.tag.split("}")[-1] if "}" in data_el.tag else data_el.tag
                if local == "Data":
                    name = data_el.get("Name", "")
                    val = data_el.text or ""
                    if name:
                        event_data[name] = val

        return {
            "event_id": int(eid),
            "timestamp": timestamp,
            "process":   event_data.get("Image", event_data.get("SourceImage", "")),
            "file":      event_data.get("TargetFilename", ""),
            "dest_ip":   event_data.get("DestinationIp", ""),
            "dest_port": str(event_data.get("DestinationPort", "")),
            "pid":       str(event_data.get("ProcessId", event_data.get("SourceProcessId", "0"))),
            "cmdline":   event_data.get("CommandLine", ""),
        }
    except Exception:
        return None


async def _sysmon_ps_loop() -> None:
    """
    Background loop: poll Sysmon Windows Event Log via PowerShell every 2 s,
    parse events, and feed them directly to SysmonBehaviorAgent._handle_event().
    Started by /start-monitoring; cancelled by /stop-monitoring.
    """
    last_rec: int = 0

    # Seed starting RecordId (don't replay old history)
    try:
        r = await asyncio.to_thread(
            subprocess.run,
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
             "-MaxEvents 1 -ErrorAction SilentlyContinue "
             "| Select-Object -ExpandProperty RecordId"],
            capture_output=True, text=True, timeout=10,
        )
        text = (r.stdout or "").strip()
        if text:
            last_rec = int(text)
    except Exception as exc:
        logger.debug(f"Sysmon PS forwarder: could not get starting RecordId: {exc}")

    logger.info(f"Sysmon PS forwarder started (last_rec={last_rec})")

    _ps_winlogbeat_warned = False

    while True:
        await asyncio.sleep(2.0)

        # Mutual exclusion: if Winlogbeat file source has become active, stop this
        # loop to prevent the same Sysmon events being processed twice.
        if _sysmon_winlogbeat_active:
            if not _ps_winlogbeat_warned:
                logger.info(
                    "[SYSMON] PS forwarder disabled — Winlogbeat source active. "
                    "Events are being read from %s instead.",
                    settings.sysmon_log_path,
                )
                _ps_winlogbeat_warned = True
            continue

        try:
            xpath = f"*[System[EventRecordID > {last_rec}]]" if last_rec else "*"
            ps_cmd = (
                f"Get-WinEvent -LogName 'Microsoft-Windows-Sysmon/Operational' "
                f"-FilterXPath '{xpath}' -MaxEvents 200 -Oldest "
                f"-ErrorAction SilentlyContinue "
                f"| ForEach-Object {{ [string]$_.RecordId + ' ' + $_.ToXml() }}"
            )
            result = await asyncio.to_thread(
                subprocess.run,
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
                capture_output=True, text=True, timeout=30,
            )

            for line in (result.stdout or "").splitlines():
                line = line.strip()
                if not line:
                    continue
                space_idx = line.find(" ")
                if space_idx < 1:
                    continue
                try:
                    rec_id = int(line[:space_idx])
                    xml_str = line[space_idx + 1:]
                except ValueError:
                    continue

                if rec_id > last_rec:
                    last_rec = rec_id

                event = _parse_sysmon_xml(xml_str)
                if event is not None and _sysmon_agent is not None:
                    await asyncio.to_thread(_sysmon_agent._handle_event, event)

        except asyncio.CancelledError:
            raise
        except Exception as exc:
            logger.debug(f"Sysmon PS forwarder: loop error: {exc}")

def _detect_capture_interface() -> str:
    """Resolve the Suricata ``-i`` device path for the active capture NIC.

    Precedence:
      1. ``XDR_SURICATA_INTERFACE`` env var (full ``\\Device\\NPF_{GUID}`` or bare ``{GUID}``).
      2. Auto-detect: the 'Up' adapter that owns the default IPv4 gateway — i.e. the
         NIC actually carrying traffic — via Get-NetAdapter. This is why capture
         works on Wi-Fi OR Ethernet with no hardcoded GUID that silently breaks when
         an adapter is reinstalled (the previous hardcoded GUID no longer existed on
         this machine, so Suricata bound a dead interface → "0 flows").
      3. Fallback to the first 'Up' adapter's GUID.

    Returns a ``\\Device\\NPF_{GUID}`` string.
    """
    override = os.environ.get("XDR_SURICATA_INTERFACE", "").strip()
    if override:
        return override if override.lower().startswith(r"\device\npf_") else (r"\Device\NPF_" + override)

    ps = (
        "$ErrorActionPreference='SilentlyContinue';"
        "$g=Get-NetIPConfiguration|Where-Object{$_.IPv4DefaultGateway -ne $null}|Select-Object -First 1;"
        "if($g){(Get-NetAdapter -InterfaceIndex $g.InterfaceIndex).InterfaceGuid}"
        "else{(Get-NetAdapter|Where-Object{$_.Status -eq 'Up'}|Select-Object -First 1).InterfaceGuid}"
    )
    try:
        out = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps],
            capture_output=True, text=True, timeout=15,
            creationflags=(subprocess.CREATE_NO_WINDOW if sys.platform == "win32" else 0),
        ).stdout.strip()
        if out.startswith("{") and out.endswith("}") and len(out) >= 34:
            dev = r"\Device\NPF_" + out
            logger.info("[SURICATA] auto-detected capture interface: %s", dev)
            return dev
        logger.warning("[SURICATA] interface auto-detect returned unexpected output: %r", out)
    except Exception as exc:
        logger.warning("[SURICATA] interface auto-detect failed: %s", exc)

    fallback = r"\Device\NPF_{C7587D8E-1D41-4684-A70D-C30AEC5E8926}"
    logger.warning("[SURICATA] falling back to hardcoded interface %s", fallback)
    return fallback


def _build_suricata_cmd() -> list:
    """Build the Suricata command with the interface resolved at start time."""
    return [
        r"C:\Program Files\Suricata\suricata.exe",
        "-c", r"C:\Program Files\Suricata\suricata.yaml",
        "-i", _detect_capture_interface(),
        "-l", r"C:\SuricataLogs",
    ]
_WINLOGBEAT_CMD = [
    str(_WINLOGBEAT_DIR / "winlogbeat.exe"),
    "-c", str(_WINLOGBEAT_DIR / "winlogbeat.yml"),
    "-e",
]


def _start_capture_processes() -> dict:
    global _suricata_proc, _winlogbeat_proc
    status = {}
    flags = subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0

    _wb_log = _WINLOGBEAT_DIR / "logs" / "winlogbeat_stderr.log"
    _wb_log.parent.mkdir(parents=True, exist_ok=True)

    _procs_to_start = [("suricata", _build_suricata_cmd(), "_suricata_proc", None)]
    if settings.start_winlogbeat:
        _procs_to_start.append(("winlogbeat", _WINLOGBEAT_CMD, "_winlogbeat_proc", str(_WINLOGBEAT_DIR)))

    for name, cmd, proc_attr, cwd in _procs_to_start:
        proc: Optional[subprocess.Popen] = globals()[proc_attr]
        if proc is not None and proc.poll() is None:
            status[name] = "already_running"
            continue
        try:
            stderr_target = (
                open(str(_wb_log), "a", encoding="utf-8")
                if name == "winlogbeat" else subprocess.DEVNULL
            )
            new_proc = subprocess.Popen(
                cmd,
                stdout=subprocess.DEVNULL,
                stderr=stderr_target,
                creationflags=flags,
                cwd=cwd,
            )
            globals()[proc_attr] = new_proc
            status[name] = f"started (pid={new_proc.pid})"
            logger.info(f"{name} started with pid {new_proc.pid}")
        except FileNotFoundError:
            status[name] = "not_found"
            logger.warning(f"{name} executable not found: {cmd[0]}")
        except Exception as exc:
            status[name] = f"error: {exc}"
            logger.error(f"Failed to start {name}: {exc}")
    return status


def _stop_capture_processes() -> dict:
    global _suricata_proc, _winlogbeat_proc
    status = {}
    _procs_to_stop = [("suricata", "_suricata_proc")]
    if settings.start_winlogbeat:
        _procs_to_stop.append(("winlogbeat", "_winlogbeat_proc"))
    for name, proc_attr in _procs_to_stop:
        proc: Optional[subprocess.Popen] = globals()[proc_attr]
        if proc is None or proc.poll() is not None:
            status[name] = "not_running"
            globals()[proc_attr] = None
            continue
        try:
            proc.terminate()
            try:
                proc.wait(timeout=5)
                status[name] = "stopped"
            except subprocess.TimeoutExpired:
                proc.kill()
                status[name] = "killed"
            globals()[proc_attr] = None
            logger.info(f"{name} stopped")
        except Exception as exc:
            status[name] = f"error: {exc}"
            logger.error(f"Failed to stop {name}: {exc}")
    return status


async def _maybe_start_winlogbeat() -> None:
    """Auto-start Winlogbeat at backend startup if START_WINLOGBEAT=true in .env.

    This runs during the FastAPI lifespan startup event, before the monitoring
    loop begins, so that Winlogbeat has time to start shipping logs before the
    first UserBehaviorAgent inference cycle fires.

    The bundled Winlogbeat directory is checked first; if not found, common
    system-wide install paths are tried.  Failure is non-fatal — a warning is
    logged and the rest of startup continues normally.
    """
    if not settings.start_winlogbeat:
        return

    # Already running (started via /start-monitoring earlier in this session)?
    global _winlogbeat_proc
    if _winlogbeat_proc is not None and _winlogbeat_proc.poll() is None:
        logger.info("Winlogbeat already running (PID %d) — skipping auto-start", _winlogbeat_proc.pid)
        return

    # Prefer the bundled copy; fall back to common system install paths.
    winlogbeat_candidates = [
        str(_WINLOGBEAT_DIR / "winlogbeat.exe"),
        r"C:\Program Files\Winlogbeat\winlogbeat.exe",
        r"C:\winlogbeat\winlogbeat.exe",
    ]
    exe = next((p for p in winlogbeat_candidates if Path(p).exists()), None)
    if not exe:
        logger.warning(
            "START_WINLOGBEAT=true but winlogbeat.exe not found in any of: %s",
            winlogbeat_candidates,
        )
        return

    cfg = str(Path(exe).parent / "winlogbeat.yml")
    cmd = [exe, "-e", "-c", cfg]
    try:
        _wb_log = Path(exe).parent / "logs" / "winlogbeat_stderr.log"
        _wb_log.parent.mkdir(parents=True, exist_ok=True)
        stderr_target = open(str(_wb_log), "a", encoding="utf-8")
        _winlogbeat_proc = subprocess.Popen(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=stderr_target,
            cwd=str(Path(exe).parent),
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0),
        )
        logger.info("Winlogbeat auto-started at startup — PID %d (config: %s)", _winlogbeat_proc.pid, cfg)
    except Exception as exc:
        logger.warning("Winlogbeat auto-start failed: %s", exc)


# ---------------------------------------------------------------------------
# Socket.IO (app + sio_app declared after _lifespan below)
# ---------------------------------------------------------------------------
# Build allowed origins from FRONTEND_URL env var so remote deployments work.

def _get_local_ip() -> str:
    """Return the machine's primary LAN IP by probing a UDP socket (no traffic sent)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"

_local_ip = _get_local_ip()
_CORS_ORIGINS: list[str] = list({
    "http://localhost:3000",
    "http://127.0.0.1:3000",
    f"http://{_local_ip}:3000",
    settings.frontend_url,
    # Same-origin: when the backend serves the dashboard itself, the Socket.IO
    # handshake Origin is the backend's own address on its own port. HTTP calls
    # are same-origin (CORS doesn't apply), but the WS handshake is still checked
    # against this list, so include the backend's serving origins.
    f"http://{_local_ip}:{settings.backend_port}",
    f"http://localhost:{settings.backend_port}",
    f"http://127.0.0.1:{settings.backend_port}",
})


def _auto_patch_env_files(ip: str) -> None:
    """Patch both .env files with the current LAN IP at every startup.
    Switching networks (lab Wi-Fi → hotspot → home) never requires manual edits —
    just restart the backend and both files stay in sync automatically."""
    backend_root = Path(__file__).resolve().parent.parent  # D:\Cyber Sentinal
    targets = [
        (backend_root / ".env",
         {"FRONTEND_URL": f"http://{ip}:3000"}),
        (backend_root / "Cyber Sentinal XDR Frontend" / ".env",
         {"REACT_APP_BACKEND_URL": f"http://{ip}:8000"}),
    ]
    for env_path, replacements in targets:
        if not env_path.exists():
            logger.debug("[env-patch] not found: %s", env_path)
            continue
        original = env_path.read_text(encoding="utf-8")
        updated = original
        for key, new_value in replacements.items():
            pattern = rf"^({re.escape(key)}=).*$"
            updated, n = re.subn(pattern, rf"\g<1>{new_value}", updated, flags=re.MULTILINE)
            if n == 0:
                updated = updated.rstrip("\n") + f"\n{key}={new_value}\n"
        if updated != original:
            env_path.write_text(updated, encoding="utf-8")
            logger.info("[env-patch] %s → IP set to %s", env_path.name, ip)


_auto_patch_env_files(_local_ip)

sio = socketio.AsyncServer(
    async_mode="asgi",
    cors_allowed_origins=_CORS_ORIGINS,
    logger=False,
)

# ---------------------------------------------------------------------------
# API key auth
# ---------------------------------------------------------------------------
_api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def _require_key(key: Optional[str] = Security(_api_key_header)):
    if key == settings.api_key:
        return key
    raise HTTPException(status_code=403, detail="Invalid or missing API key")


# ---------------------------------------------------------------------------
# Dual auth: accept EITHER a valid API key OR a valid JWT Bearer token.
# Used to protect ML inference endpoints so both endpoint agents (API key)
# and SOC dashboard users (JWT) can call them.
# ---------------------------------------------------------------------------

async def _require_key_or_jwt(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
) -> str:
    """
    Dependency: allow access if the caller presents either:
      - A valid X-API-Key header matching XDR_API_KEY, OR
      - A valid Bearer JWT in the Authorization header (any role)

    Raises HTTP 401 when a Bearer token is present but invalid/expired.
    Raises HTTP 403 when no credentials are provided at all.
    """
    # 1. API key path (endpoint agents, scripts)
    if api_key == settings.api_key:
        return "api_key"

    # 2. JWT path (SOC dashboard users)
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="Bearer token is empty")
        try:
            from auth.security import decode_token as _decode  # noqa: PLC0415
            payload = _decode(token, settings.jwt_secret_key, settings.jwt_algorithm)
            # Explicit expiry check
            exp = payload.get("exp")
            if exp is not None and time.time() > exp:
                raise HTTPException(
                    status_code=401,
                    content={"error": "TOKEN_EXPIRED", "message": "JWT has expired"},
                )
            # Token revocation check
            jti = payload.get("jti", "")
            if jti and _is_token_revoked(jti):
                raise HTTPException(status_code=401, detail="Token has been revoked")
            if payload.get("type") == "access" and payload.get("sub"):
                return "jwt"
        except HTTPException:
            # Re-raise FastAPI HTTP exceptions (includes 401 Expired) unchanged
            raise
        except Exception:
            raise HTTPException(
                status_code=401,
                detail="JWT token is invalid or expired",
            )

    raise HTTPException(
        status_code=403,
        detail="Provide a valid X-API-Key header or a Bearer JWT token",
    )


# ---------------------------------------------------------------------------
# Security event helpers (unauthorized access logging)
# ---------------------------------------------------------------------------

def _extract_jwt_identity(request: Request) -> tuple[str, str]:
    """
    Safely decode the Bearer JWT from the Authorization header.

    Returns (user_id, role).  On any error (missing token, bad signature,
    expired) returns ("anonymous", "none") — never raises.
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return "anonymous", "none"
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return "anonymous", "none"
        from auth.security import decode_token as _decode_token  # noqa: PLC0415
        payload = _decode_token(token, settings.jwt_secret_key, settings.jwt_algorithm)
        user_id = payload.get("sub", "anonymous") or "anonymous"
        role = payload.get("role", "none") or "none"
        return str(user_id), str(role)
    except Exception:
        return "anonymous", "none"


def _get_client_ip(request: Request) -> str:
    """Return the best-guess client IP (X-Forwarded-For first, then direct)."""
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


async def _persist_security_event(doc: dict) -> None:
    """Write a security_event document to MongoDB. Called via create_task."""
    try:
        _save("security_events", doc)
    except Exception as exc:
        logger.debug(f"[SECURITY] security_event persist failed: {exc}")


async def _log_security_event(
    request: Request,
    http_code: int,
    user_id: str,
    role: str,
) -> None:
    """
    Build a security event document and fire-and-forget write to MongoDB.
    Also emits a WARNING to the Python logger.
    """
    ip = _get_client_ip(request)
    path = request.url.path
    method = request.method

    severity = "MEDIUM" if http_code == 401 else "HIGH"

    # 401 = missing/expired credentials (expected noise — user not logged in).
    # 403 = present but insufficient credentials (more suspicious — log at WARNING).
    if http_code == 401:
        logger.debug(
            f"[SECURITY] Unauthenticated request: user={user_id} role={role} "
            f"endpoint={path} method={method} ip={ip} http_code={http_code}"
        )
    else:
        logger.warning(
            f"[SECURITY] Unauthorized access: user={user_id} role={role} "
            f"endpoint={path} method={method} ip={ip} http_code={http_code}"
        )

    doc = {
        "type": "unauthorized_access",
        "user_id": user_id,
        "role": role,
        "endpoint": path,
        "method": method,
        "ip": ip,
        "timestamp": _now(),
        "severity": severity,
        "http_code": http_code,
    }
    # Non-blocking write — response is returned before the DB write completes
    asyncio.create_task(_persist_security_event(doc))


# ---------------------------------------------------------------------------
# Pydantic request models
# ---------------------------------------------------------------------------
class TelemetryPayload(BaseModel):
    host: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    data: dict


class PredictNetworkPayload(BaseModel):
    flows: list[dict]


class PredictUserPayload(BaseModel):
    lookback_minutes: int = 30
    threshold_override: Optional[float] = None
    usb_override_threshold: int = 10


class FusionPayload(BaseModel):
    host: str
    network_score: float = 0.0
    user_score: float = 0.0
    system_score: float = 0.0
    malware_score: float = 0.0


class PredictMalwarePayload(BaseModel):
    file_path: Optional[str] = None
    features: Optional[list] = None
    host: str = "unknown"


class ScanMalwarePayload(BaseModel):
    directory: str
    extensions: list[str] = ['.exe', '.dll', '.sys']
    host: str = "unknown"


class CommandAckPayload(BaseModel):
    status: str   # "done" | "failed"
    result: str = ""


# ---------------------------------------------------------------------------
# Endpoint Telemetry & Response Command — Pydantic models
# ---------------------------------------------------------------------------
class EndpointIdentity(BaseModel):
    endpoint_id: str
    hostname: str
    ip_address: str = ""   # optional — older/minimal agents may omit
    os: str = ""           # optional — older/minimal agents may omit
    os_version: str = ""
    username: str = ""
    agent_version: str = "1.0.0"


class EndpointTelemetry(BaseModel):
    endpoint: EndpointIdentity
    timestamp: Optional[datetime] = None
    network:           dict = {}
    system:            dict = {}
    user:              dict = {}
    malware:           dict = {}
    suricata:          dict = {}
    sysmon_events:     dict = {}
    winlogbeat_events: dict = {}

    from pydantic import validator  # noqa: PLC0415

    @validator("timestamp", pre=True, always=True)
    def set_timestamp(cls, v):
        return v or datetime.utcnow()

    @validator("winlogbeat_events", pre=True, always=True)
    def coerce_winlogbeat_events(cls, v):
        # Agent may send [] when there are no events; coerce to {} so dict type is satisfied
        if not isinstance(v, dict):
            return {}
        return v

    @validator("network", "system", "user", "malware", "suricata", "sysmon_events", pre=True, always=True, each_item=False)
    def coerce_dict_fields(cls, v):
        # Guard: if an agent sends [] instead of {} for any dict field, coerce silently
        if not isinstance(v, dict):
            return {}
        return v


class EndpointCommandAck(BaseModel):
    command_id: str
    endpoint_id: str
    success: bool
    message: str = ""
    executed_at: str = ""
    action: str = ""      # optional: action name echoed back by the endpoint agent
    target: str = ""      # optional: target (IP / PID / path) echoed back by the endpoint agent


class SendCommand(BaseModel):
    endpoint_id: str
    action: str          # "kill_process" | "block_ip" | "isolate_host" | "quarantine_file"
    target: str = ""     # process name, IP, file path
    parameters: dict = {}
    issued_by: str = ""  # username of analyst


class ContactInquiry(BaseModel):
    name: str
    email: str
    subject: str
    message: str
    phone: Optional[str] = None


# ---------------------------------------------------------------------------
# App lifecycle helpers (called by _lifespan context manager below)
# ---------------------------------------------------------------------------
async def _do_startup():
    global _network_agent, _user_agent, _fusion_agent, _shap_agent, _malware_agent, _system_agent, _sysmon_agent, _graph_engine
    global _backend_session_start
    _backend_session_start = datetime.utcnow()
    logger.info("[startup] backend session start: %s", _backend_session_start.isoformat())

    if settings.api_key == "changeme-dev-key":
        logger.critical("SECURITY WARNING: XDR_API_KEY is using the default insecure value. Set XDR_API_KEY env var before production use.")

    # Check Administrator privileges via the structured helper — required for netsh / net.exe.
    _priv_check = _check_windows_privileges()
    if _priv_check["warnings"]:
        for _w in _priv_check["warnings"]:
            logger.critical("[STARTUP] %s", _w)
        logger.critical(
            "SOAR WARNING: The following SOAR actions WILL FAIL: block_ip, unblock_ip, "
            "isolate_host, unisolate_host, lock_account, unlock_account. "
            "Restart uvicorn as Administrator (right-click -> Run as administrator) "
            "or run: Start-Process python -ArgumentList '-m uvicorn ...' -Verb RunAs"
        )
    elif _priv_check["admin"]:
        logger.info("SOAR: Running as Administrator — all netsh/net actions will execute.")

    _default_jwt = "CHANGE_ME_IN_PRODUCTION_32chars_min"
    if settings.jwt_secret_key == _default_jwt:
        logger.critical(
            "SECURITY WARNING: JWT_SECRET_KEY is using the default insecure value. "
            "Set JWT_SECRET_KEY env var (minimum 32 chars) before production use."
        )
    elif len(settings.jwt_secret_key) < 32:
        logger.critical(
            f"SECURITY WARNING: JWT_SECRET_KEY is only {len(settings.jwt_secret_key)} chars. "
            "A minimum of 32 characters is required for HS256 security."
        )

    # Log MongoDB connection status clearly during startup
    if MONGO_OK:
        logger.info(f"MongoDB Atlas connected — db='{settings.mongo_db}'")
    else:
        logger.warning("MongoDB Atlas NOT connected — running without persistence. Check network/credentials.")

    # ── Auto-purge phantom demo data on every startup ─────────────────────────
    # Removes DEMO-* endpoints and their associated alerts so the dashboard
    # starts clean without requiring a manual /demo/cleanup call.
    if MONGO_OK and _db is not None:
        try:
            _demo_filter = {"hostname": {"$regex": "^DEMO-", "$options": "i"}}
            _demo_id_filter = {"endpoint_id": {"$regex": "^demo-", "$options": "i"}}
            _alert_filter = {"$or": [
                {"source": "demo_inject"},
                {"hostname": {"$regex": "^DEMO-", "$options": "i"}},
                {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
            ]}
            r_ep  = _db["endpoint_registry"].delete_many({"$or": [_demo_filter, _demo_id_filter]})
            r_fa  = _db["fused_alerts"].delete_many(_alert_filter)
            r_ca  = _db["critical_alerts"].delete_many(_alert_filter)
            r_al  = _db["alerts"].delete_many(_alert_filter)
            r_gn  = _db["attack_graph_nodes"].delete_many({"$or": [
                {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
                {"label": {"$regex": "^DEMO-", "$options": "i"}},
                {"node_id": {"$regex": "demo", "$options": "i"}},
                {"metadata.source": "demo_inject"},
            ]})
            _total = r_ep.deleted_count + r_fa.deleted_count + r_ca.deleted_count + r_al.deleted_count + r_gn.deleted_count
            if _total:
                logger.info("[startup] Auto-purged %d phantom demo documents from MongoDB", _total)
        except Exception as _dp_err:
            logger.debug("[startup] Demo purge skipped: %s", _dp_err)

    # Fusion engine (always available — pure Python)
    _fusion_agent = FusionEngineAgent(
        weights={
            "network": settings.weight_network,
            "user": settings.weight_user,
            "system": settings.weight_system,
            "malware": settings.weight_malware,
        },
        high_threshold=settings.fusion_high_threshold,
        critical_threshold=settings.fusion_critical_threshold,
    )

    # Load persisted thresholds from MongoDB so values survive server restarts.
    # Applied immediately after _fusion_agent is constructed so both fusion
    # thresholds and the two detection thresholds are live from the first cycle.
    try:
        _saved = await asyncio.to_thread(_load_thresholds_from_db)
        global _network_anomaly_threshold, _system_anomaly_threshold
        global _malware_threshold, _user_behavior_threshold
        global _auto_response_enabled
        _network_anomaly_threshold = _saved.get("network_anomaly_threshold", _network_anomaly_threshold)
        _system_anomaly_threshold  = _saved.get("system_anomaly_threshold",  _system_anomaly_threshold)
        _malware_threshold         = _saved.get("malware_threshold",         _malware_threshold)
        _user_behavior_threshold   = _saved.get("user_behavior_threshold",   _user_behavior_threshold)
        _auto_response_enabled     = bool(_saved.get("auto_response_enabled", True))
        if _fusion_agent is not None:
            _fusion_agent.high_threshold     = _saved.get("fusion_high_threshold",     _fusion_agent.high_threshold)
            _fusion_agent.critical_threshold = _saved.get("fusion_critical_threshold", _fusion_agent.critical_threshold)
        logger.info(
            "[startup] Persisted thresholds applied: network=%.2f system=%.2f "
            "fusion_high=%.2f fusion_critical=%.2f malware=%.2f user=%.2f",
            _network_anomaly_threshold, _system_anomaly_threshold,
            _fusion_agent.high_threshold if _fusion_agent else float("nan"),
            _fusion_agent.critical_threshold if _fusion_agent else float("nan"),
            _malware_threshold, _user_behavior_threshold,
        )
    except Exception as _thr_exc:
        logger.warning(f"[startup] Could not load persisted thresholds (using defaults): {_thr_exc}")

    # Network detection agent
    try:
        _network_agent = NetworkDetectionAgent(
            model_dir=settings.model_dir,
            eve_path=settings.suricata_eve_path,
        )
        logger.info("NetworkDetectionAgent ready")
    except Exception as e:
        logger.error(f"NetworkDetectionAgent init failed: {e}")

    # Auto-start Winlogbeat before user behavior agent so logs are available
    # for the first inference cycle.  No-op when START_WINLOGBEAT=false (default).
    await _maybe_start_winlogbeat()

    # User behavior agent (runs as background task)
    try:
        _user_agent = UserBehaviorAgent(
            interval_seconds=settings.user_behavior_interval_seconds,
            on_result=_handle_user_result,
        )
        # Apply any admin-saved User Behavior ruleset so the first cycle uses it.
        try:
            global _user_behavior_rules
            _user_behavior_rules = await asyncio.to_thread(_load_user_rules_from_db)
            _user_agent.apply_rules(_user_behavior_rules)
        except Exception as _ur_exc:
            logger.warning(f"[startup] Could not apply persisted user rules: {_ur_exc}")
        await _user_agent.start()
        logger.info("UserBehaviorAgent started")
    except Exception as e:
        logger.error(f"UserBehaviorAgent init failed: {e}")

    # SHAP agent (optional — requires shap library)
    # Loads explainers for both network classifier and malware LightGBM if available
    classifier_path  = Path(settings.model_dir) / "network_classifier.pkl"
    features_path    = Path(settings.model_dir) / "network_features.pkl"
    mal_model_path   = Path(settings.model_dir) / "malware_model.pkl"
    mal_feat_path    = Path(settings.model_dir) / "malware_feature_names.pkl"
    try:
        _shap_agent = SHAPAgent(
            str(classifier_path) if classifier_path.exists() else None,
            str(features_path)   if features_path.exists()   else None,
            malware_model_path   = str(mal_model_path) if mal_model_path.exists() else None,
            malware_features_path= str(mal_feat_path)  if mal_feat_path.exists()  else None,
        )
        logger.info(f"SHAPAgent ready: {_shap_agent.status()}")
    except Exception as e:
        logger.warning(f"SHAPAgent unavailable: {e}")

    # Malware analysis agent (optional — requires malware_model.pkl)
    try:
        _malware_agent = MalwareAnalysisAgent(model_dir=settings.model_dir)
        logger.info(f"MalwareAnalysisAgent ready: {_malware_agent.status()}")
    except Exception as e:
        logger.error(f"MalwareAnalysisAgent init failed: {e}")

    # System monitor agent (optional — requires torch + system_model.pt)
    try:
        # Interval between system-monitor inference ticks. Each tick runs the LSTM
        # autoencoder + BehavioralDetector (torch + XGBoost + TF-IDF), which is CPU
        # heavy; at the old 1 s default it pinned ~1 core continuously and starved
        # the async event loop on a single machine, so the backend stopped answering
        # the agent + dashboard shortly after Start Monitoring. 5 s cuts that load 5×
        # with no meaningful loss of system-anomaly coverage. Override via env.
        try:
            _sysmon_interval = max(1, int(os.environ.get("XDR_SYSTEM_MONITOR_INTERVAL", "5")))
        except ValueError:
            _sysmon_interval = 5
        _system_agent = SystemMonitorAgent(
            model_dir=settings.model_dir,
            on_result=_handle_system_result,
            interval_seconds=_sysmon_interval,
        )
        await _system_agent.start()
        _bdet_status = _system_agent.status()
        logger.info(f"SystemMonitorAgent started: {_bdet_status}")
        if _bdet_status.get("behavioral_detector_loaded"):
            logger.info(
                "BehavioralDetector (DETECTOR1/detector.pkl) loaded successfully"
                " — process behavior detection ACTIVE"
            )
        else:
            logger.warning(
                "BehavioralDetector: detector.pkl NOT loaded"
                " — system detection running on LSTM only."
                " Run: python train_system_model.py --source dataset"
            )
    except Exception as e:
        logger.error(f"SystemMonitorAgent init failed: {e}")

    # Sysmon Behavior Agent (optional — requires detector.pkl + winlogbeat running)
    try:
        from pathlib import Path as _Path
        _pkl = _Path(settings.sysmon_model_dir) / "detector.pkl"
        _sysmon_agent = SysmonBehaviorAgent(
            model_pkl_path=str(_pkl),
            sysmon_log_path=settings.sysmon_log_path,
            on_result=_handle_sysmon_result,
            on_telemetry=_handle_sysmon_telemetry,
        )
        await _sysmon_agent.start()
        logger.info(f"SysmonBehaviorAgent started: {_sysmon_agent.status()}")
    except Exception as e:
        logger.error(f"SysmonBehaviorAgent init failed: {e}")

    # Create MongoDB indexes for auth collections (idempotent — safe to re-run).
    #
    # This used to be ~40 create_index() calls awaited directly on the event
    # loop, each a blocking network round-trip to MongoDB Atlas — sequentially
    # that added many seconds (sometimes 20s+) to every single backend restart
    # and blocked all other request handling the whole time it ran. Indexes
    # are idempotent and are not required before the app can start serving
    # traffic, so this now runs as a fire-and-forget background thread instead
    # of gating "Application startup complete" / the health check.
    def _create_all_mongo_indexes() -> None:
        try:
            # users — unique on email and username for fast lookup + constraint enforcement
            _db["users"].create_index("email",    unique=True, background=True)
            _db["users"].create_index("username", unique=True, background=True)
            # sessions — fast lookup by jti (token blacklist check) and by user_id
            _db["sessions"].create_index("jti",     unique=True, background=True, sparse=True)
            _db["sessions"].create_index("user_id", background=True)
            _db["sessions"].create_index([("user_id", ASCENDING), ("is_active", ASCENDING)], background=True)
            # audit_logs — fast range queries and user-filtered views
            _db["audit_logs"].create_index([("timestamp", DESCENDING)], background=True)
            _db["audit_logs"].create_index("user", background=True)
            # security_events — fast descending time queries + user/ip filtering
            _db["security_events"].create_index([("timestamp", DESCENDING)], background=True)
            _db["security_events"].create_index("user_id", background=True)
            _db["security_events"].create_index("ip", background=True)
            logger.info("MongoDB auth indexes created/verified")
        except Exception as _idx_err:
            logger.warning(f"MongoDB auth index creation skipped: {_idx_err}")

        try:
            # password_reset_tokens — lookup by jti (fast single-use check) + expiry filter
            _db["password_reset_tokens"].create_index("token_jti", unique=True, background=True, sparse=True)
            _db["password_reset_tokens"].create_index("user_id", background=True)
            _db["password_reset_tokens"].create_index([("created_at", DESCENDING)], background=True)
            # Compound index: active unexpired tokens per user (used by reset_password scanner)
            _db["password_reset_tokens"].create_index(
                [("used", ASCENDING), ("expires_at", DESCENDING)], background=True
            )
            # IP-based rate-limit queries: how many tokens from this IP in the last hour
            _db["password_reset_tokens"].create_index("ip", background=True)
            # mfa_recovery_requests — status filter + newest-first + per-user pending check
            _db["mfa_recovery_requests"].create_index("request_id", unique=True, background=True)
            _db["mfa_recovery_requests"].create_index("user_id", background=True)
            _db["mfa_recovery_requests"].create_index(
                [("status", ASCENDING), ("requested_at", DESCENDING)], background=True
            )
            logger.info("MongoDB credential recovery indexes created/verified")
        except Exception as _rec_idx_err:
            logger.warning(f"MongoDB credential recovery index creation skipped: {_rec_idx_err}")

        try:
            # endpoint_logs — fast lookup by endpoint and time
            _db["endpoint_logs"].create_index("endpoint_id", background=True)
            _db["endpoint_logs"].create_index([("timestamp", DESCENDING)], background=True)
            # endpoint_registry — unique endpoint_id + fast last_seen queries
            _db["endpoint_registry"].create_index("endpoint_id", unique=True, background=True)
            _db["endpoint_registry"].create_index([("last_seen", DESCENDING)], background=True)
            # endpoint_commands — filtering by endpoint + status + time
            _db["endpoint_commands"].create_index("endpoint_id", background=True)
            _db["endpoint_commands"].create_index("status", background=True)
            _db["endpoint_commands"].create_index([("created_at", DESCENDING)], background=True)
            # endpoint_timelines — compound index for per-endpoint timeline queries (Gap 3)
            _db["endpoint_timelines"].create_index(
                [("endpoint_id", ASCENDING), ("timestamp", DESCENDING)], background=True
            )
            logger.info("MongoDB endpoint indexes created/verified")
        except Exception as _ep_idx_err:
            logger.warning(f"MongoDB endpoint index creation skipped: {_ep_idx_err}")

        try:
            # settings — single-document collection; key field for upsert lookups
            _db["settings"].create_index("key", unique=True, background=True)
            # case_notes — per-endpoint queries, time-sorted, and analyst-filtered
            _db["case_notes"].create_index([("endpoint_id", DESCENDING)], background=True)
            _db["case_notes"].create_index([("created_at", DESCENDING)], background=True)
            _db["case_notes"].create_index("analyst", background=True)
            # note_id unique lookup (used by DELETE /case-notes/{note_id})
            _db["case_notes"].create_index("note_id", unique=True, background=True)
            # feedback — analyst FP/TP labels (Feature #1); export corpus for retraining
            _db["feedback"].create_index([("created_at", DESCENDING)], background=True)
            _db["feedback"].create_index("verdict", background=True)
            _db["feedback"].create_index("used_in_training", background=True)
            logger.info("MongoDB settings/case_notes indexes created/verified")
        except Exception as _sc_idx_err:
            logger.warning(f"MongoDB settings/case_notes index creation skipped: {_sc_idx_err}")

        try:
            # attack_graph_nodes — unique node_id, time-sorted access, per-endpoint filter
            _db["attack_graph_nodes"].create_index([("node_id", 1)], unique=True, background=True)
            _db["attack_graph_nodes"].create_index([("last_updated", -1)], background=True)
            _db["attack_graph_nodes"].create_index([("endpoint_id", 1)], background=True)
            # attack_graph_edges — unique edge_id, source/target lookup, time-sorted, replay seq
            _db["attack_graph_edges"].create_index([("edge_id", 1)], unique=True, background=True)
            _db["attack_graph_edges"].create_index([("source", 1), ("target", 1)], background=True)
            _db["attack_graph_edges"].create_index([("timestamp", -1)], background=True)
            _db["attack_graph_edges"].create_index([("chain_seq", 1)], background=True)
            logger.info("MongoDB attack graph indexes created/verified")
        except Exception as _ag_idx_err:
            logger.warning(f"MongoDB attack graph index creation skipped: {_ag_idx_err}")

        try:
            # incidents — correlated incident tracking
            _db["incidents"].create_index("incident_id", unique=True, background=True)
            _db["incidents"].create_index(
                [("endpoint_id", ASCENDING), ("status", ASCENDING)], background=True
            )
            _db["incidents"].create_index([("last_event_at", DESCENDING)], background=True)
            _db["incidents"].create_index([("severity", ASCENDING)], background=True)
            logger.info("MongoDB incidents indexes created/verified")
        except Exception as _inc_idx_err:
            logger.warning(f"MongoDB incidents index creation skipped: {_inc_idx_err}")

        try:
            # TTL indexes — MongoDB automatically deletes documents older than the expiry.
            # fused_alerts: 30-day TTL on ts_dt (CRITICAL/HIGH ones are also in critical_alerts)
            # endpoint_logs: 90-day TTL on ts_dt
            # sysmon_alerts: 30-day TTL on ts_dt
            # critical_alerts: NO TTL — permanent evidence store (uncapped, no expiry)
            #
            # We use ts_dt (a BSON datetime) not ts (ISO string) because MongoDB TTL
            # indexes require a proper date field.  Documents written before this
            # migration (without ts_dt) are simply not expired by the TTL index —
            # they are still cleaned up by the soft-cap trim logic.
            _db["fused_alerts"].create_index(
                [("ts_dt", ASCENDING)],
                expireAfterSeconds=30 * 24 * 3600,   # 30 days
                background=True,
                name="ttl_fused_alerts_30d",
            )
            _db["endpoint_logs"].create_index(
                [("ts_dt", ASCENDING)],
                expireAfterSeconds=90 * 24 * 3600,   # 90 days
                background=True,
                name="ttl_endpoint_logs_90d",
            )
            _db["sysmon_alerts"].create_index(
                [("ts_dt", ASCENDING)],
                expireAfterSeconds=30 * 24 * 3600,   # 30 days
                background=True,
                name="ttl_sysmon_alerts_30d",
            )
            # critical_alerts — fast lookup indexes only; no TTL
            _db["critical_alerts"].create_index([("endpoint_id", 1)], background=True)
            _db["critical_alerts"].create_index([("severity", 1)], background=True)
            _db["critical_alerts"].create_index([("ts_dt", -1)], background=True)
            _db["critical_alerts"].create_index([("attack_type", 1)], background=True)
            logger.info("MongoDB TTL and critical_alerts indexes created/verified")
        except Exception as _ttl_idx_err:
            logger.warning(f"MongoDB TTL index creation skipped: {_ttl_idx_err}")

    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(_create_all_mongo_indexes))
        logger.info("MongoDB index creation dispatched to background thread")

    # Initialize AttackGraphEngine (uses _db — works even when MongoDB is None)
    _graph_engine = AttackGraphEngine(_db if MONGO_OK else None)
    logger.info("[STARTUP] AttackGraphEngine initialized")

    # Gap 1 — server_host self-registration
    # Upsert this backend process into endpoint_registry so the SOC dashboard
    # always shows the server as a first-class endpoint.
    _server_registry_doc = {
        "endpoint_id": "server_host",
        "hostname":    socket.gethostname(),
        "ip_address":  "127.0.0.1",
        "os":          platform.system(),
        "os_version":  platform.version(),
        "username":    getpass.getuser(),
        "is_server":   True,
        "status":      "online",
        "last_seen":   datetime.utcnow().isoformat(),
    }
    if MONGO_OK and _db is not None:
        try:
            _db["endpoint_registry"].update_one(
                {"endpoint_id": "server_host"},
                {"$set": _server_registry_doc},
                upsert=True,
            )
            logger.info(
                f"server_host registered in endpoint_registry: "
                f"hostname={_server_registry_doc['hostname']} "
                f"os={_server_registry_doc['os']}"
            )
        except Exception as _srv_reg_err:
            logger.warning(f"server_host self-registration failed: {_srv_reg_err}")
    else:
        logger.info("server_host self-registration skipped (MongoDB unavailable)")

    # Startup cleanup — mark all remote endpoints offline so phantom entries
    # from previous sessions don't appear in the endpoint grid until they
    # reconnect and send actual telemetry.
    if MONGO_OK and _db is not None:
        try:
            result = _db["endpoint_registry"].update_many(
                {"endpoint_id": {"$ne": "server_host"}},
                {"$set": {"status": "offline"}},
            )
            logger.info(
                "[startup] Marked %d stale remote endpoints offline",
                result.modified_count,
            )
        except Exception as _cleanup_err:
            logger.warning("[startup] Endpoint registry cleanup failed: %s", _cleanup_err)

    # Pre-create the per-endpoint FusionDecisionEngine for server_host (Gap 2+5)
    try:
        _get_or_create_endpoint_engine("server_host")
        logger.info("Per-endpoint FusionDecisionEngine pre-created for server_host")
    except Exception as _eng_err:
        logger.warning(f"server_host FusionDecisionEngine pre-creation failed: {_eng_err}")

    # Enumerate all non-loopback IPv4 addresses so operators can see every
    # interface the backend is reachable on after a network change.
    try:
        _all_ips = [
            info[4][0]
            for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
            if not info[4][0].startswith("127.")
        ]
        _all_ips = list(dict.fromkeys(_all_ips))  # deduplicate, preserve order
    except Exception:
        _all_ips = []
    if _all_ips:
        for _ip in _all_ips:
            logger.info(f"[SERVER] Listening on http://{_ip}:{settings.backend_port}")
        logger.info(f"[SERVER] Endpoints connect via: http://{_all_ips[0]}:{settings.backend_port}")
    else:
        logger.info(f"[SERVER] Listening on 0.0.0.0:{settings.backend_port} (all interfaces)")
        logger.info(f"[SERVER] Endpoints connect via: http://<this-machine-ip>:{settings.backend_port}")

    # ---------------------------------------------------------------------------
    # Startup health report — printed once, after all agents are initialised
    # ---------------------------------------------------------------------------
    _default_jwt = "CHANGE_ME_IN_PRODUCTION_32chars_min"
    _jwt_status  = "SET" if settings.jwt_secret_key != _default_jwt else "DEFAULT (insecure)"
    _api_status  = "DEFAULT (insecure)" if settings.api_key == "changeme-dev-key" else "SET"
    logger.info("=" * 60)
    logger.info("CYBER SENTINEL XDR — STARTUP COMPLETE")
    logger.info(f"  MongoDB:        {'OK' if MONGO_OK else 'FAILED'}")
    logger.info(f"  Backend URL:    http://0.0.0.0:{settings.backend_port}")
    logger.info(f"  API Key:        {_api_status}")
    logger.info(f"  JWT Secret:     {_jwt_status}")
    logger.info(f"  Agents started: network, system, malware, user, sysmon, server_soar")
    logger.info("CORS origins: %s", _CORS_ORIGINS)
    logger.info("=" * 60)


async def _do_shutdown():
    global _monitoring_task, _malware_scan_task, _sysmon_ps_task, _endpoint_heartbeat_task, _server_soar_task

    async def _shutdown_inner():
        # 1. Cancel all background tasks
        bg_tasks = [t for t in [
            _monitoring_task, _malware_scan_task, _sysmon_ps_task,
            _endpoint_heartbeat_task, _server_soar_task,
        ] if t and not t.done()]
        for task in bg_tasks:
            task.cancel()
        # Await cancellations so the event loop drains them cleanly before we
        # continue.  return_exceptions=True prevents one CancelledError from
        # blocking the rest.
        if bg_tasks:
            await asyncio.gather(*bg_tasks, return_exceptions=True)

        # 2. Stop agents with a per-step timeout; CancelledError is expected on
        # Python 3.13 + uvicorn when the loop starts cleaning up concurrently.
        try:
            coros = []
            if _user_agent:
                coros.append(_user_agent.stop())
            if _system_agent:
                coros.append(_system_agent.stop())
            if _sysmon_agent:
                coros.append(_sysmon_agent.stop())
            if coros:
                await asyncio.wait_for(
                    asyncio.gather(*coros, return_exceptions=True),
                    timeout=3.0,
                )
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

        try:
            await asyncio.wait_for(asyncio.to_thread(_stop_capture_processes), timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            _stop_capture_processes()

        # Stop Winlogbeat (non-blocking — best-effort on shutdown)
        try:
            await asyncio.wait_for(_wlb_stop(), timeout=2.0)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            pass

    # Hard outer timeout — shutdown must complete within 5 seconds regardless
    # of what any individual step does.  This prevents Ctrl+C hangs.
    try:
        await asyncio.wait_for(_shutdown_inner(), timeout=5.0)
    except (asyncio.CancelledError, asyncio.TimeoutError):
        pass


# ---------------------------------------------------------------------------
# SIGTERM → graceful shutdown helper
# Only SIGTERM is intercepted here.  SIGINT (Ctrl+C) is intentionally left
# alone so uvicorn receives KeyboardInterrupt and exits normally.
# The handler cannot call async code directly, so it schedules _do_shutdown()
# as an asyncio Task on the running event loop.
# ---------------------------------------------------------------------------
def _handle_signal(signum, frame):
    logger.warning(
        "[SIGNAL] Signal %s received — scheduling graceful shutdown", signum
    )
    try:
        # asyncio.get_running_loop() raises RuntimeError when no event loop is
        # running in the current thread.  This is the correct call from a signal
        # handler context on Python 3.10+ (get_event_loop() is deprecated there
        # and may return the wrong loop or emit a DeprecationWarning).
        loop = asyncio.get_running_loop()
        loop.create_task(_do_shutdown())
    except RuntimeError:
        logger.debug("[SIGNAL] No running event loop — cannot schedule shutdown task")
    except Exception as _sig_exc:
        logger.debug("[SIGNAL] Could not schedule shutdown: %s", _sig_exc)


try:
    signal.signal(signal.SIGTERM, _handle_signal)
    # Do NOT install a SIGINT handler — let Ctrl+C propagate as KeyboardInterrupt
    # so uvicorn's own shutdown logic fires correctly.
except Exception as _sig_setup_exc:
    # signal.signal() can raise on non-main threads (e.g. uvicorn reload worker)
    logger.debug("[SIGNAL] Signal handler setup skipped: %s", _sig_setup_exc)


# ---------------------------------------------------------------------------
# Lifespan context manager (modern replacement for @app.on_event)
# ---------------------------------------------------------------------------
def _quiet_loop_exception_handler(loop, context):
    """Swallow the benign ConnectionResetError [WinError 10054] that Windows'
    ProactorEventLoop logs whenever a client (browser Socket.IO reconnect,
    endpoint agent, dashboard poll) drops a TCP connection before the server
    finishes writing. These are harmless — the peer is simply gone — but under
    reconnect storms they flood the log and add real overhead. Everything else
    is delegated to the default handler so genuine errors are never hidden."""
    exc = context.get("exception")
    if isinstance(exc, ConnectionResetError):
        return
    msg = context.get("message", "") or ""
    if "_call_connection_lost" in msg or "SHUT_RDWR" in msg:
        return
    loop.default_exception_handler(context)


@asynccontextmanager
async def _lifespan(_app: FastAPI):
    await _do_startup()
    # Quiet the harmless WinError 10054 connection-reset spam (see handler above).
    try:
        asyncio.get_running_loop().set_exception_handler(_quiet_loop_exception_handler)
    except Exception:
        pass
    try:
        yield
    except asyncio.CancelledError:
        # ── Python 3.13 / asyncio.timeout() regression fix ──────────────────
        # In Python 3.13 asyncio.wait_for() was reimplemented to use
        # asyncio.timeout() internally.  asyncio.timeout.__aenter__ records
        # the task's _num_cancels_requested as `_cancelling`.  If the lifespan
        # task is force-cancelled here (second Ctrl+C, force_exit, or event-
        # loop teardown) and we suppress the CancelledError WITHOUT calling
        # task.uncancel(), the counter stays at 1.  Then inside _do_shutdown()
        # the asyncio.timeout context records _cancelling=1; the first await
        # inside _shutdown_inner triggers a fresh CancelledError; __aexit__
        # calls task.uncancel() (counter → 0), sees 0 <= 1, and immediately
        # raises TimeoutError — bypassing _do_shutdown() entirely so no
        # background task is ever cancelled.
        #
        # task.uncancel() resets the counter to 0 so the awaits inside
        # _do_shutdown() / _shutdown_inner() run as normal coroutines.
        _ct = asyncio.current_task()
        if _ct is not None and hasattr(_ct, "uncancel"):
            _ct.uncancel()
    finally:
        await _do_shutdown()


app = FastAPI(title="Cyber Sentinel XDR", version="1.0.0", lifespan=_lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=_CORS_ORIGINS,
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=True,
)
sio_app = socketio.ASGIApp(sio, app)

# ---------------------------------------------------------------------------
# Auth router — must be registered after app is created
# ---------------------------------------------------------------------------
from auth.router import router as auth_router  # noqa: E402
app.include_router(auth_router)


# ---------------------------------------------------------------------------
# Logout token revocation middleware
# Intercepts POST /auth/logout and /auth/logout-all to add the JTI to the
# in-memory revocation cache — without modifying the auth package.
#
# Implemented as a pure ASGI middleware (not BaseHTTPMiddleware) to avoid
# the anyio task-group machinery that causes noisy CancelledError tracebacks
# during uvicorn shutdown when BaseHTTPMiddleware is used.
# ---------------------------------------------------------------------------
class _LogoutRevocationMiddleware:
    """Revoke the Bearer token JTI from the in-memory cache on logout."""

    def __init__(self, app_):
        self.app = app_

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        status_code: int | None = None

        async def _send_wrapper(message):
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message.get("status")
            await send(message)

        await self.app(scope, receive, _send_wrapper)

        # Only intercept successful logout responses
        path = scope.get("path", "")
        method = scope.get("method", "")
        if method == "POST" and path in ("/auth/logout", "/auth/logout-all"):
            if status_code is not None and 200 <= status_code < 300:
                try:
                    headers = dict(scope.get("headers", []))
                    auth_header = headers.get(b"authorization", b"").decode("utf-8", errors="ignore")
                    if auth_header.startswith("Bearer "):
                        token = auth_header.removeprefix("Bearer ").strip()
                        if token:
                            from auth.security import decode_token as _decode_rev  # noqa: PLC0415
                            payload = _decode_rev(
                                token, settings.jwt_secret_key, settings.jwt_algorithm
                            )
                            jti = payload.get("jti", "")
                            if jti:
                                asyncio.create_task(_revoke_token(jti))
                                logger.debug("[JWT] Token JTI revoked on logout: %s", jti)
                except Exception:
                    pass


# Pure ASGI middleware — wrap the socketio ASGI app directly
sio_app = _LogoutRevocationMiddleware(sio_app)


# ---------------------------------------------------------------------------
# Global RequestValidationError handler — log 422 details to console
# ---------------------------------------------------------------------------

@app.exception_handler(RequestValidationError)
async def _validation_error_handler(request: Request, exc: RequestValidationError):
    """Log Pydantic validation failures so 422 causes are visible in the server console."""
    logger.warning(
        "[422] Validation error on %s %s — errors: %s",
        request.method,
        request.url.path,
        exc.errors(),
    )
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


# Global HTTPException handler — standardized 401/403 responses
# ---------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException):
    """
    Intercept 401 and 403 HTTPExceptions from any endpoint and return a
    standardized JSON error body.  All other status codes are passed through
    with their original detail string so existing behaviour is unchanged.

    Security events are logged to MongoDB and the Python logger for every
    401/403 interception.  The MongoDB write is non-blocking (create_task)
    so the response is sent immediately regardless of DB latency.

    The _extract_jwt_identity() call is wrapped in a bare try/except to
    guarantee the handler never itself raises an HTTPException (which would
    cause infinite recursion through this same handler).
    """
    if exc.status_code == 401:
        try:
            user_id, role = _extract_jwt_identity(request)
            await _log_security_event(request, 401, user_id, role)
        except Exception:
            pass
        detail_msg = exc.detail if isinstance(exc.detail, str) else "Authentication required"
        return JSONResponse(
            status_code=401,
            content={"error": "UNAUTHORIZED", "message": detail_msg, "code": 401},
        )

    if exc.status_code == 403:
        try:
            user_id, role = _extract_jwt_identity(request)
            await _log_security_event(request, 403, user_id, role)
        except Exception:
            pass
        return JSONResponse(
            status_code=403,
            content={"error": "FORBIDDEN", "message": "Insufficient permissions", "code": 403},
        )

    # All other HTTP errors: preserve original FastAPI behaviour
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
        headers=dict(exc.headers) if exc.headers else None,
    )


# ---------------------------------------------------------------------------
# Socket.IO events
# ---------------------------------------------------------------------------
@sio.event
async def connect(sid, environ, data=None):
    logger.info(f"Dashboard connected: {sid}")
    await sio.emit("status", {"message": "Connected to Cyber Sentinel XDR"}, to=sid)

    # Replay any confirmed-malicious files that were detected before this client
    # connected.  The 60 s cooldown in _maybe_emit_malware_fusion_alert is
    # intentionally bypassed here (we emit directly to the new SID only) so
    # the Alert Stream is populated immediately on connect regardless of timing.
    for _cf_path, _cf_data in list(_malware_confirmed.items()):
        try:
            _cf_fusion = _cf_data["fusion"]
            _cf_result = _cf_data["result"]
            if _cf_fusion is None:
                continue
            if _cf_fusion.severity not in ("HIGH", "CRITICAL"):
                continue
            if _cf_result.get("label") != "malicious":
                continue
            _score_pct = round(_cf_fusion.threat_score * 100)
            _replay_payload = {
                "ts":            _cf_data["ts"],
                "hostname":      "local",
                "endpoint_id":   "local",
                "attack_type":   "Malware Activity",
                "confidence":    _score_pct,
                "severity":      _cf_fusion.severity,
                "prediction":    "ATTACK",
                "source":        "malware",
                "file_path":     _cf_path,
                "label":         "malicious",
                "malware_score": _cf_result.get("score", 0.0),
                "trust_reason":  _cf_result.get("trust_reason", ""),
                "shap_explanation": _cf_data.get("shap") or [],
                "description": (
                    f"Malicious file detected on local — "
                    f"score {_cf_result.get('score', 0.0):.0%}, "
                    f"fusion score {_cf_fusion.threat_score:.0%}"
                ),
            }
            await sio.emit("network_anomaly", _replay_payload, to=sid)
            logger.debug(
                "[MALWARE] Replayed confirmed alert to new client %s — file=%s",
                sid, _cf_path,
            )
        except Exception as _rep_err:
            logger.debug("[MALWARE] connect-replay error for %s: %s", _cf_path, _rep_err)


@sio.event
async def disconnect(sid):
    logger.info(f"Dashboard disconnected: {sid}")


# ---------------------------------------------------------------------------
# REST Endpoints
# ---------------------------------------------------------------------------

@app.get("/health")
async def health():
    # --- Group 4: integration status checks ---
    def _check_integration_status() -> dict:
        """Probe external tool log files to determine if each tool is active."""
        import os as _os_local
        import time as _time_local
        status: dict = {}

        # Suricata — eve.json must exist and have been written within the last 5 minutes
        # (was hardcoded to the bare C:\SuricataLogs\eve.json path, ignoring
        # settings.suricata_eve_path — diverged from the actual eve.json location
        # whenever SURICATA_EVE_PATH pointed elsewhere, e.g. start.ps1's suricata_1
        # subfolder, so this status always read a stale/wrong file independent of
        # whether Suricata was really running)
        suricata_eve = settings.suricata_eve_path
        try:
            if _os_local.path.isfile(suricata_eve):
                age_s = _time_local.time() - _os_local.path.getmtime(suricata_eve)
                status["suricata_ok"] = age_s < 300  # 5 minutes
            else:
                status["suricata_ok"] = False
        except Exception:
            status["suricata_ok"] = False

        # Sysmon — check if the Winlogbeat-forwarded sysmon NDJSON file exists
        sysmon_log = r"C:\winlogbeat\logs\sysmon_events.json"
        try:
            status["sysmon_ok"] = _os_local.path.isfile(sysmon_log)
        except Exception:
            status["sysmon_ok"] = False

        # Winlogbeat — check if C:\XDR_Logs\ exists and contains .ndjson files
        xdr_logs_dir = r"C:\XDR_Logs"
        try:
            if _os_local.path.isdir(xdr_logs_dir):
                ndjson_files = [
                    f for f in _os_local.listdir(xdr_logs_dir)
                    if f.endswith(".ndjson")
                ]
                status["winlogbeat_ok"] = len(ndjson_files) > 0
            else:
                status["winlogbeat_ok"] = False
        except Exception:
            status["winlogbeat_ok"] = False

        # Winlogbeat manager — live process check + install detection
        # (runs inside the thread because _wlb_is_running uses subprocess.run)
        try:
            status["winlogbeat_running"] = _wlb_is_running()
            status["winlogbeat_installed"] = _wlb_find() is not None
        except Exception:
            status["winlogbeat_running"] = False
            status["winlogbeat_installed"] = False

        return status

    # Run all slow I/O concurrently so total time = slowest single op, not sum.
    # return_exceptions=True prevents one slow/failing call from cancelling others.
    (
        _r_integration,
        _,                     # _ensure_db_connected — side-effects only
        _r_active_mits,
        _r_online_eps,
        _r_offline_eps,
    ) = await asyncio.gather(
        asyncio.to_thread(_check_integration_status),
        asyncio.to_thread(_ensure_db_connected),
        asyncio.to_thread(_count_active_mitigations),
        asyncio.to_thread(_count_online_endpoints),
        asyncio.to_thread(_count_offline_endpoints),
        return_exceptions=True,
    )
    integration         = _r_integration       if isinstance(_r_integration, dict) else {}
    _active_mitigations = _r_active_mits       if isinstance(_r_active_mits, int)  else 0
    _online_eps         = _r_online_eps        if isinstance(_r_online_eps, int)   else 0
    _offline_eps        = _r_offline_eps       if isinstance(_r_offline_eps, int)  else 0

    # Derive explicit per-model status from loaded agent state (in-memory, fast)
    _net_agent_status   = _network_agent is not None
    _user_agent_status  = _user_agent.status() if _user_agent else None
    _sys_agent_status   = _system_agent.status() if _system_agent else None
    _mal_agent_status   = _malware_agent.status() if _malware_agent else None
    _shap_agent_status  = _shap_agent.status() if _shap_agent else None

    # Admin privilege check (fast Windows API call)
    try:
        _is_admin_now = bool(ctypes.windll.shell32.IsUserAnAdmin()) if sys.platform == "win32" else None
    except Exception:
        _is_admin_now = None

    return {
        "status": "ok",
        "ts": _now(),
        "mongo": MONGO_OK,
        # SOC operational fields
        "uptime_seconds":      int(time.time() - _startup_time),
        "active_mitigations":  _active_mitigations,
        "endpoints_online":    _online_eps,
        "endpoints_offline":   _offline_eps,
        "mongo_connected":     MONGO_OK,
        "admin_privileges":    _is_admin_now,
        "agents": {
            "network": "running" if (_monitoring_task and not _monitoring_task.done()) else "stopped",
            "system":  "running" if (_system_agent is not None and getattr(_system_agent, "_running", False)) else "stopped",
            "soar":    "running" if (_server_soar_task and not _server_soar_task.done()) else "stopped",
        },
        # --- Explicit per-model status (ok / unavailable) ---
        "network_model": {
            "status": "ok" if _net_agent_status else "unavailable",
            "agent_loaded": _net_agent_status,
        },
        "user_model": {
            "status": "ok" if (_user_agent_status or {}).get("runtime_available") else "unavailable",
            "agent_loaded": _user_agent_status is not None,
            "detail": _user_agent_status,
        },
        "system_model": {
            "status": "ok" if (_sys_agent_status or {}).get("model_loaded") else "unavailable",
            "agent_loaded": _sys_agent_status is not None,
            "behavioral_detector_loaded": (_sys_agent_status or {}).get("behavioral_detector_loaded", False),
            "detail": _sys_agent_status,
        },
        "malware_model": {
            "status": "ok" if (_mal_agent_status or {}).get("model_loaded") else "unavailable",
            "agent_loaded": _mal_agent_status is not None,
            "detail": _mal_agent_status,
        },
        "shap": {
            "status": "ok" if _shap_agent_status is not None else "unavailable",
            "detail": _shap_agent_status,
        },
        "fusion_engine": {
            "status": "ok",
        },
        "sysmon": {
            "status": "ok" if (_sysmon_agent is not None and (_sysmon_agent.status() or {}).get("running")) else "unavailable",
            "detail": _sysmon_agent.status() if _sysmon_agent else None,
        },
        "suricata": {
            "status": "ok" if integration.get("suricata_ok") else "unavailable",
            "eve_fresh": integration.get("suricata_ok", False),
        },
        # --- Legacy flat keys retained for backwards-compat with older frontend consumers ---
        "network_agent": _net_agent_status,
        "user_agent": _user_agent_status,
        "malware_agent": _mal_agent_status,
        "system_agent": _sys_agent_status,
        "sysmon_agent": _sysmon_agent.status() if _sysmon_agent else None,
        "shap_agent": _shap_agent_status,
        "monitoring": _monitoring_task is not None and not _monitoring_task.done(),
        "malware_watcher": _malware_scan_task is not None and not _malware_scan_task.done(),
        "correlation_engine": True,
        "fusion_engine_v2": True,
        "endpoint_api": {
            "ingest":       "POST /endpoint/ingest",
            "commands":     "GET  /endpoint/commands/{endpoint_id}",
            "command_ack":  "POST /endpoint/command/ack",
            "send_command": "POST /endpoint/command",
            "list":         "GET  /endpoint/list",
            "detail":       "GET  /endpoint/{endpoint_id}",
            "heartbeat":    _endpoint_heartbeat_task is not None and not _endpoint_heartbeat_task.done(),
        },
        # Integration status — probed from external tool log files
        "suricata_ok":   integration.get("suricata_ok", False),
        "sysmon_ok":     integration.get("sysmon_ok", False),
        "winlogbeat_ok": integration.get("winlogbeat_ok", False),
        "winlogbeat_status": {
            "configured": settings.start_winlogbeat,
            "log_dir": settings.user_log_dir,
            "log_files_found": integration.get("winlogbeat_ok", False),
        },
        # Richer Winlogbeat status from winlogbeat_manager — includes install
        # detection and live process check independent of the start_winlogbeat flag.
        # Values pre-computed inside the to_thread() call to avoid blocking the loop.
        "winlogbeat": {
            "status": "running" if integration.get("winlogbeat_running") else "stopped",
            "installed": integration.get("winlogbeat_installed", False),
            "manager_available": _WINLOGBEAT_MANAGER_AVAILABLE,
        },
    }


@app.get("/health/winlogbeat")
async def health_winlogbeat():
    """Return Winlogbeat process status and log directory health.

    Does NOT require authentication — consumed by the Settings page integration
    status panel which loads before auth is complete.

    Returns:
        running (bool): True if a winlogbeat.exe process is found via psutil.
        pid (int | null): PID of the running process, or null.
        log_dir (str): Path being monitored for ndjson files.
        log_files (int): Number of .ndjson files currently in log_dir.
        configured (bool): Whether START_WINLOGBEAT=true in .env.
        last_result_events (int | null): events_count from the most recent
            inference cycle, or null if no cycle has run yet.
    """
    import psutil as _psutil  # noqa: PLC0415

    def _check() -> dict:
        running = False
        pid = None
        for proc in _psutil.process_iter(["pid", "name"]):
            try:
                if "winlogbeat" in (proc.info.get("name") or "").lower():
                    running = True
                    pid = proc.info["pid"]
                    break
            except (_psutil.NoSuchProcess, _psutil.AccessDenied):
                continue

        import os as _os_wb  # noqa: PLC0415
        log_dir = settings.user_log_dir
        try:
            ndjson_count = len([
                f for f in _os_wb.listdir(log_dir)
                if f.endswith(".ndjson")
            ]) if _os_wb.path.isdir(log_dir) else 0
        except Exception:
            ndjson_count = 0

        last_events = None
        if _user_agent and _user_agent.last_result:
            last_events = _user_agent.last_result.get("events_count")

        return {
            "running": running,
            "pid": pid,
            "log_dir": log_dir,
            "log_files": ndjson_count,
            "configured": settings.start_winlogbeat,
            "last_result_events": last_events,
        }

    return await asyncio.to_thread(_check)


@app.post("/ingest", dependencies=[Depends(_require_key)])
async def ingest(payload: TelemetryPayload):
    """Receive endpoint telemetry. Stored in MongoDB; does not trigger ML."""
    doc = payload.dict()
    doc["received_at"] = _now()
    for log in doc.get("logs", []):
        log.setdefault("timestamp", doc.get("timestamp", datetime.utcnow().isoformat()))
    _save("logs", doc)
    return {"status": "accepted"}


@app.post("/predict/network", dependencies=[Depends(_require_key_or_jwt)])
async def predict_network(payload: PredictNetworkPayload):
    """Run the 3-stage network detection pipeline on submitted flows."""
    if not _network_agent:
        raise HTTPException(503, "NetworkDetectionAgent not initialised")
    result = await asyncio.to_thread(_network_agent.detect_from_flows, payload.flows)
    await _process_network_result(result)
    return result


@app.post("/predict/user", dependencies=[Depends(_require_key_or_jwt)])
async def predict_user(payload: PredictUserPayload):
    """Run user behavior inference on-demand."""
    if not _user_agent:
        raise HTTPException(503, "UserBehaviorAgent not initialised")
    result = await _user_agent.run_once(
        lookback_minutes=payload.lookback_minutes,
        threshold_override=payload.threshold_override,
        usb_override_threshold=payload.usb_override_threshold,
    )
    asyncio.create_task(_handle_user_result(result))
    return result


@app.post("/predict/malware", dependencies=[Depends(_require_key_or_jwt)])
async def predict_malware(payload: PredictMalwarePayload):
    """Run malware inference on a single file path or pre-computed feature vector."""
    if not _malware_agent:
        raise HTTPException(503, "MalwareAnalysisAgent not initialised")
    if payload.file_path is None and payload.features is None:
        raise HTTPException(400, "Provide file_path or features")

    if payload.file_path is not None:
        result = await asyncio.to_thread(_malware_agent.predict, payload.file_path)
    else:
        result = await asyncio.to_thread(_malware_agent.predict_from_features, payload.features)

    ts = _now()
    shap_explanation = _maybe_explain_malware(result.get("features_scaled"))
    result_doc = {**result, "host": payload.host, "ts": ts, "shap_explanation": shap_explanation}
    result_doc.pop("features_scaled", None)
    _save("malware_scans", result_doc)
    _save("malware_events", result_doc)
    _save("predictions", {**result_doc, "model": "malware"})

    if result.get("label") in ("malicious", "suspicious") and not result.get("trusted", False):
        malware_score = result.get("score", 0.0)
        async with _scores_lock:
            _latest_scores["malware"] = {"score": max(_latest_scores["malware"]["score"], malware_score), "ts": time.monotonic()}
        _scores = _get_current_scores()
        fusion = _fusion_agent.fuse(
            network_score=_scores["network"],
            user_score=_scores["user"],
            system_score=_scores["system"],
            malware_score=malware_score,
        ) if _fusion_agent else None
        alert_doc = {**result_doc, "fusion": fusion.to_dict() if fusion else None}
        _save("alerts", alert_doc)
        _malware_alert_payload = _strip_mongo({
            **alert_doc,
            "file_size": result.get("file_size", 0),
            "fusion": {
                "threat_score": round(float(fusion.threat_score), 4) if fusion else 0.0,
                "severity": fusion.severity if fusion else "LOW",
                "attack_type": "Malware Activity",
            },
        })
        await sio.emit("malware_alert", _malware_alert_payload)
        if _graph_engine:
            _mal_ev_predict = {**_malware_alert_payload, "endpoint_id": payload.host}
            try:
                g_nodes, g_edges = _graph_engine.process_malware_alert(_mal_ev_predict)
                await _emit_graph_update(g_nodes, g_edges)
            except Exception as _ge:
                logger.debug(f"[GRAPH] malware_alert (predict) hook error: {_ge}")
            asyncio.create_task(asyncio.to_thread(
                _graph_engine.ingest_to_incident, "malware", _mal_ev_predict
            ))
        if fusion and fusion.should_respond:
            shap_fusion = _explain_fusion(fusion)
            fused_alert_doc = {**fusion.to_dict(), "source": "malware", "ts": ts, "shap": shap_fusion, "ts_dt": _now_dt()}
            # Exclude ts_dt (datetime) from socket emit payload — not JSON-serialisable
            _malware_fusion_payload = {k: v for k, v in fused_alert_doc.items() if k not in ("_id", "ts_dt")}
            await sio.emit("fusion_alert", _malware_fusion_payload)
            _save("fused_alerts", fused_alert_doc)
            # Dual-write HIGH/CRITICAL to uncapped permanent evidence store
            if fusion.severity in ("HIGH", "CRITICAL"):
                _save("critical_alerts", fused_alert_doc)
            if _graph_engine:
                try:
                    g_nodes, g_edges = _graph_engine.process_fusion_alert(_malware_fusion_payload)
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] fusion_alert (malware/predict) hook error: {_ge}")
                asyncio.create_task(asyncio.to_thread(
                    _graph_engine.ingest_to_incident, "fusion", _malware_fusion_payload
                ))
        if result.get("label") == "malicious" and not result.get("trusted", False):
            _save("commands", {
                "host": payload.host,
                "actions": ["quarantine_file"],
                "params": {"file_path": result.get("file_path", "")},
                "status": "pending",
                "trigger": "malware_direct",
                "score": result.get("score"),
                "ts": _now(),
            })
        # Guarantee Alert Stream entry for HIGH/CRITICAL malicious files.
        # _maybe_emit_malware_fusion_alert handles its own cooldown and severity
        # gate, so it is safe to call unconditionally here.
        await _maybe_emit_malware_fusion_alert(fusion, result, payload.host, ts, shap_explanation)

    if result.get("label") == "malicious" and not result.get("trusted", False):
        try:
            fe_event = {
                "source": "malware",
                "timestamp": ts,
                "host": payload.host,
                "severity": "CRITICAL",
                "confidence": result.get("score", 0.0),
                "prediction": result.get("file_path", "malware_detected"),
                "label": "malicious",
                "trusted": False,
            }
            fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
            await _emit_soc_alert_if_correlated(fe_out, ts)
        except Exception as _fe_exc:
            logger.debug(f"fusion_engine.ingest_event (predict_malware) skipped: {_fe_exc}")

    await sio.emit("malware_scan", _strip_mongo({**result_doc, "file_size": result.get("file_size", 0)}))
    return result_doc


@app.post("/scan/malware", dependencies=[Depends(_require_key_or_jwt)])
async def scan_malware(payload: ScanMalwarePayload):
    """Scan a directory for malware across files matching given extensions."""
    if not _malware_agent:
        raise HTTPException(503, "MalwareAnalysisAgent not initialised")

    from pathlib import Path as _Path
    req_path = _Path(payload.directory).resolve()
    allowed = any(
        req_path.resolve().is_relative_to(_Path(root).resolve())
        for root in settings.scan_allowed_roots
    )
    if not allowed:
        raise HTTPException(400, f"Directory not in allowed scan roots: {settings.scan_allowed_roots}")

    results: list[dict] = await asyncio.to_thread(
        _malware_agent.scan_directory, payload.directory, payload.extensions
    )

    malware_count = 0
    for result in results:
        ts = _now()
        shap_explanation = _maybe_explain_malware(result.get("features_scaled"))
        result_doc = {**result, "host": payload.host, "ts": ts, "shap_explanation": shap_explanation}
        result_doc.pop("features_scaled", None)
        _save("malware_scans", result_doc)
        _save("malware_events", result_doc)
        if result.get("label") in ("malicious", "suspicious") and not result.get("trusted", False):
            malware_count += 1
            malware_score = result.get("score", 0.0)
            async with _scores_lock:
                _latest_scores["malware"] = {"score": max(_latest_scores["malware"]["score"], malware_score), "ts": time.monotonic()}
            _scores = _get_current_scores()
            fusion = _fusion_agent.fuse(
                network_score=_scores["network"],
                user_score=_scores["user"],
                system_score=_scores["system"],
                malware_score=malware_score,
            ) if _fusion_agent else None
            alert_doc = {**result_doc, "fusion": fusion.to_dict() if fusion else None}
            _save("alerts", alert_doc)
            _scan_malware_payload = _strip_mongo({
                **alert_doc,
                "file_size": result.get("file_size", 0),
                "fusion": {
                    "threat_score": round(float(fusion.threat_score), 4) if fusion else 0.0,
                    "severity": fusion.severity if fusion else "LOW",
                    "attack_type": "Malware Activity",
                },
            })
            await sio.emit("malware_alert", _scan_malware_payload)
            if _graph_engine:
                _mal_ev_scan = {**_scan_malware_payload, "endpoint_id": payload.host}
                try:
                    g_nodes, g_edges = _graph_engine.process_malware_alert(_mal_ev_scan)
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] malware_alert (scan) hook error: {_ge}")
                asyncio.create_task(asyncio.to_thread(
                    _graph_engine.ingest_to_incident, "malware", _mal_ev_scan
                ))
            if fusion and fusion.should_respond:
                shap_fusion = _explain_fusion(fusion)
                fused_alert_doc = {**fusion.to_dict(), "source": "malware", "ts": ts, "shap": shap_fusion, "ts_dt": _now_dt()}
                # Exclude ts_dt (datetime) from socket emit payload — not JSON-serialisable
                _scan_fusion_payload = {k: v for k, v in fused_alert_doc.items() if k not in ("_id", "ts_dt")}
                await sio.emit("fusion_alert", _scan_fusion_payload)
                _save("fused_alerts", fused_alert_doc)
                # Dual-write HIGH/CRITICAL to uncapped permanent evidence store
                if fusion.severity in ("HIGH", "CRITICAL"):
                    _save("critical_alerts", fused_alert_doc)
                if _graph_engine:
                    try:
                        g_nodes, g_edges = _graph_engine.process_fusion_alert(_scan_fusion_payload)
                        await _emit_graph_update(g_nodes, g_edges)
                    except Exception as _ge:
                        logger.debug(f"[GRAPH] fusion_alert (malware/scan) hook error: {_ge}")
                    asyncio.create_task(asyncio.to_thread(
                        _graph_engine.ingest_to_incident, "fusion", _scan_fusion_payload
                    ))
            if result.get("label") == "malicious" and not result.get("trusted", False):
                _save("commands", {
                    "host": payload.host,
                    "actions": ["quarantine_file"],
                    "params": {"file_path": result.get("file_path", "")},
                    "status": "pending",
                    "trigger": "malware_direct",
                    "score": result.get("score"),
                    "ts": _now(),
                })
            if result.get("label") == "malicious" and not result.get("trusted", False):
                try:
                    fe_event = {
                        "source": "malware",
                        "timestamp": ts,
                        "host": payload.host,
                        "severity": "CRITICAL",
                        "confidence": result.get("score", 0.0),
                        "prediction": result.get("file_path", "malware_detected"),
                        "label": "malicious",
                        "trusted": False,
                    }
                    fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
                    await _emit_soc_alert_if_correlated(fe_out, ts)
                except Exception as _fe_exc:
                    logger.debug(f"fusion_engine.ingest_event (scan_malware) skipped: {_fe_exc}")
            # Guarantee Alert Stream entry for HIGH/CRITICAL malicious files.
            await _maybe_emit_malware_fusion_alert(fusion, result, payload.host, ts, shap_explanation)

    return {
        "scanned": len(results),
        "malware_count": malware_count,
        "results": [_strip_mongo(r) for r in results],
    }


@app.post("/system/analyze", dependencies=[Depends(_require_key_or_jwt)])
async def system_analyze(request: Request):
    """
    Manually submit a batch of system telemetry for LSTM analysis.

    Request body:
        {
          "features": [[float, ...], ...],  // shape (N, 20) raw psutil feature rows
          "source": "manual"                // optional label
        }

    Response:
        {
          "anomaly_score": 0.82,
          "severity": "HIGH",
          "status": "ANOMALOUS",
          "buffer_fill": 45,
          "threshold": 0.35,
          "features_snapshot": [...],
          "source": "manual"
        }
    """
    if _system_agent is None:
        raise HTTPException(503, "SystemMonitorAgent not initialised")

    body = await request.json()
    features_list = body.get("features", [])
    source = body.get("source", "manual")

    if not isinstance(features_list, list) or len(features_list) == 0:
        raise HTTPException(400, "Provide a non-empty 'features' list of lists (shape N x 20)")

    for row in features_list:
        if not isinstance(row, list) or len(row) != 20:
            raise HTTPException(
                400,
                f"Each feature row must be a list of exactly 20 floats; got length {len(row) if isinstance(row, list) else type(row)}"
            )
        _system_agent._buffer.append([float(v) for v in row])

    buffer_fill = len(_system_agent._buffer)
    window_size = _system_agent.window_size

    if buffer_fill >= window_size:
        score = await asyncio.to_thread(_system_agent._infer)
    else:
        last_features = list(_system_agent._buffer)[-1] if _system_agent._buffer else [0.0] * 20
        score = _system_agent._heuristic_score(last_features)

    score = float(score)
    _system_agent._last_score = score

    from agents.system_monitor_agent import _score_to_severity
    severity = _score_to_severity(score)

    last_features_snapshot = list(_system_agent._buffer)[-1] if _system_agent._buffer else []

    return {
        "anomaly_score": round(score, 4),
        "severity": severity,
        "status": "ANOMALOUS" if score >= 0.35 else "NORMAL",
        "buffer_fill": buffer_fill,
        "threshold": 0.35,
        "features_snapshot": [round(float(v), 4) for v in last_features_snapshot],
        "source": source,
    }


@app.get("/sysmon/status", dependencies=[Depends(_require_key_or_jwt)])
async def sysmon_status():
    """Return SysmonBehaviorAgent status."""
    if _sysmon_agent is None:
        return {
            "agent_running": False,
            "model_loaded": False,
            "log_path": None,
            "total_events": 0,
            "total_alerts": 0,
            "last_score": 0.0,
        }

    st = _sysmon_agent.status()

    return {
        "agent_running": st.get("running", False),
        "model_loaded": st.get("model_loaded", False),
        "log_path": st.get("log_path"),
        "total_events": st.get("total_events", 0),
        "total_alerts": st.get("total_alerts", 0),
        "last_score": st.get("last_score", 0.0),
    }


class SimulateUserAttackPayload(BaseModel):
    n_file_creates: int = 600
    n_file_reads: int = 200
    n_failed_logons: int = 3
    username: Optional[str] = None


@app.post("/simulate-user-attack", dependencies=[Depends(_require_key)])
async def simulate_user_attack(payload: SimulateUserAttackPayload):
    """Inject a fake Winlogbeat-format ndjson file that the UserBehaviorAgent
    will pick up on its next inference cycle, simulating an insider-threat
    pattern (bulk file creates + reads + failed logons) for demo purposes."""

    username: str = payload.username or os.environ.get("USERNAME", "DELL")
    host: str = os.environ.get("COMPUTERNAME", "DELL-PC")

    n_creates = payload.n_file_creates
    n_reads = payload.n_file_reads
    n_failed = payload.n_failed_logons
    unique_dirs = 55

    def _ts(offset_minutes: float = 0) -> str:
        t = datetime.now(timezone.utc) - timedelta(minutes=offset_minutes)
        return t.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    def _file_event(eid: int, fname: str, offset: float) -> dict:
        return {
            "@timestamp": _ts(offset),
            "winlog": {
                "event_id": str(eid),
                "provider_name": "Microsoft-Windows-Sysmon",
                "event_data": {"TargetFilename": fname},
                "user_data": {"TargetUserName": username},
            },
            "user": {"name": username},
            "host": {"name": host},
            "message": fname,
        }

    def _logon_event(eid: int, offset: float) -> dict:
        return {
            "@timestamp": _ts(offset),
            "winlog": {
                "event_id": str(eid),
                "provider_name": "Microsoft-Windows-Security-Auditing",
                "event_data": {},
                "user_data": {"TargetUserName": username},
            },
            "user": {"name": username},
            "host": {"name": host},
            "message": f"Logon event {eid} for {username}",
        }

    def _build_events() -> list:
        evts: list = []

        # Bulk FileCreate events (Sysmon event 11)
        for i in range(1, n_creates + 1):
            path = f"D:/User Anomaly/file{i:04d}.txt"
            evts.append(_file_event(11, path, random.uniform(0, 15)))

        # FileRead events (Sysmon event 15) spread across unique_dirs directories
        dirs = [f"D:/SimDirs/dir{d:03d}" for d in range(1, unique_dirs + 1)]
        for i in range(n_reads):
            path = f"{dirs[i % unique_dirs]}/scan_{i:04d}.dat"
            evts.append(_file_event(15, path, random.uniform(0, 20)))

        # Failed logon attempts (event 4625)
        for _ in range(n_failed):
            evts.append(_logon_event(4625, random.uniform(0, 10)))

        # One successful logon so the session looks realistic
        evts.append(_logon_event(4624, 5))

        random.shuffle(evts)
        return evts

    log_path = Path("C:/XDR_Logs")
    log_file = log_path / "sim_attack.ndjson"

    def _write_file():
        log_path.mkdir(parents=True, exist_ok=True)
        evts = _build_events()
        with log_file.open("w", encoding="utf-8") as fh:
            for e in evts:
                fh.write(json.dumps(e) + "\n")
        return len(evts)

    n_written = await asyncio.to_thread(_write_file)
    logger.info(f"Attack simulation injected: {n_written} events for user {username}")

    return {
        "status": "injected",
        "events_written": n_written,
        "log_file": str(log_file).replace("/", "\\"),
        "message": "Attack simulation injected. Anomaly will appear on dashboard within 60s.",
        "attack_summary": {
            "file_creates": n_creates,
            "file_reads": n_reads,
            "failed_logons": n_failed,
            "unique_dirs": unique_dirs,
            "target_user": username,
        },
    }


@app.post("/fusion", dependencies=[Depends(_require_key_or_jwt)])
async def fusion_endpoint(payload: FusionPayload):
    """Combine model scores into a single threat score."""
    if not _fusion_agent:
        raise HTTPException(503, "FusionEngineAgent not initialised")
    result = _fusion_agent.fuse(
        network_score=payload.network_score,
        user_score=payload.user_score,
        system_score=payload.system_score,
        malware_score=payload.malware_score,
        endpoint_id=payload.host,
    )
    logger.info(
        f"[FUSION] Threat detected: severity={result.severity} "
        f"score={result.threat_score:.3f} endpoint={result.endpoint_id}"
    )
    ts = _now()
    shap_fusion = _explain_fusion(result)
    doc = {**result.to_dict(), "host": payload.host, "ts": ts, "shap": shap_fusion}
    _save("predictions", doc)
    if result.should_respond:
        _save("alerts", {**doc, "trigger": "fusion_threshold"})
    # Always emit threat_score so the dashboard gauge stays live
    await sio.emit("threat_score", doc)
    # Emit fusion_alert for HIGH/CRITICAL so AlertsTable and ResponseModal receive it
    if result.severity in ("HIGH", "CRITICAL"):
        fused_doc = {**doc, "source": "fusion_api", "attack_type": result.attack_type, "ts_dt": _now_dt()}
        _save("fused_alerts", fused_doc)
        _save("critical_alerts", fused_doc)
        await sio.emit("fusion_alert", _strip_mongo({k: v for k, v in fused_doc.items() if k != "ts_dt"}))
        if result.severity == "HIGH" or result.severity == "CRITICAL":
            await _maybe_generate_network_response_plan(
                endpoint_id=payload.host or "server_host",
                severity=result.severity,
                attack_type=result.attack_type or "Fusion Injection",
                fusion=result,
            )
    return result.to_dict()


class DemoInjectPayload(BaseModel):
    attack_type:    str   = "PortScan"
    network_score:  float = 0.95
    user_score:     float = 0.90
    system_score:   float = 0.85
    malware_score:  float = 0.90
    host:           str   = "server_host"
    hostname:       str   = "server_host"
    src_ip:         str   = "10.0.0.99"
    endpoint_id:    Optional[str] = None   # real UUID from endpoint_registry; overrides host for fuse()


@app.post("/demo/inject", dependencies=[Depends(_require_key)])
async def demo_inject(payload: DemoInjectPayload):
    """
    Demo/test only — directly emit a high-severity fusion alert with the
    specified scores and attack type.  Populates AlertsTable, ResponseModal,
    and triggers response plan generation just like a real detection.
    """
    if not _fusion_agent:
        raise HTTPException(503, "FusionEngineAgent not initialised")

    ep_id = payload.endpoint_id or payload.host
    fusion = _fusion_agent.fuse(
        network_score=payload.network_score,
        user_score=payload.user_score,
        system_score=payload.system_score,
        malware_score=payload.malware_score,
        endpoint_id=ep_id,
    )
    # Override attack_type from payload (fuse() may return "Unknown" for injections)
    fusion.attack_type = payload.attack_type

    ts = _now()
    shap_fusion = _explain_fusion(fusion)

    # Confidence in 0-100 scale for the Alert Stream table
    conf_pct = round(fusion.threat_score * 100, 1)

    # Emit network_anomaly so the Alert Stream row appears immediately.
    # confidence is 0-100 so the frontend table shows "XX.X%".
    await sio.emit("network_anomaly", {
        "src_ip":        payload.src_ip,
        "dst_ip":        payload.src_ip,       # realistic: same subnet
        "protocol":      "TCP",
        "attack_type":   payload.attack_type,
        "severity":      fusion.severity,
        "confidence":    conf_pct,
        "hostname":      payload.hostname,
        "endpoint_id":   ep_id,
        "ts":            ts,
        "shap_reasons":  shap_fusion.get("reason", []) if shap_fusion else [],
    })

    # Emit fusion_alert so ResponseModal + SOAR pipeline fire
    fused_payload = {
        **fusion.to_dict(),
        "source":      "demo_inject",
        "attack_type": payload.attack_type,
        "hostname":    payload.hostname,
        "endpoint_id": ep_id,
        "src_ip":      payload.src_ip,
        "confidence":  conf_pct,
        "ts":          ts,
        "shap":        shap_fusion,
    }
    _save("fused_alerts", {**fused_payload, "ts_dt": _now_dt()})
    if fusion.severity in ("HIGH", "CRITICAL"):
        _save("critical_alerts", {**fused_payload, "ts_dt": _now_dt()})
    await sio.emit("fusion_alert", fused_payload)

    # Persist to attack_graph_nodes so the snapshot endpoint finds it on page load/refresh.
    now_str = datetime.utcnow().isoformat()
    if _db is not None:
        try:
            _risk_pct_pre = int(fusion.threat_score * 100)
            _safe_at_pre  = payload.attack_type.lower().replace(" ", "_").replace("+", "").replace("—", "").strip("_")
            _anode_pre    = f"alert-{_safe_at_pre}-{ep_id}"
            _epnode_pre   = f"ep-{ep_id}"
            _anode_doc    = {
                "node_id":     _anode_pre,
                "type":        "alert",
                "label":       payload.attack_type,
                "risk_score":  _risk_pct_pre,
                "severity":    fusion.severity,
                "endpoint_id": ep_id,
                "timestamp":   now_str,
                "last_updated": now_str,
                "metadata":    {
                    "attack_type":  payload.attack_type,
                    "threat_score": fusion.threat_score,
                    "src_ip":       payload.src_ip,
                    "hostname":     payload.hostname,
                    "source":       "demo_inject",
                },
            }
            _epnode_doc = {
                "node_id":      _epnode_pre,
                "type":         "endpoint",
                "label":        payload.hostname,
                "risk_score":   _risk_pct_pre,
                "severity":     fusion.severity,
                "endpoint_id":  ep_id,
                "timestamp":    now_str,
                "last_updated": now_str,
                "metadata":     {"ip": payload.src_ip, "status": "under_attack", "source": "demo_inject"},
            }
            _db["attack_graph_nodes"].update_one(
                {"node_id": _anode_pre},
                {"$set": _anode_doc},
                upsert=True,
            )
            _db["attack_graph_nodes"].update_one(
                {"node_id": _epnode_pre},
                {"$set": _epnode_doc},
                upsert=True,
            )
            _db["attack_graph_edges"].update_one(
                {"edge_id": f"{_epnode_pre}->{_anode_pre}:triggered"},
                {"$set": {
                    "edge_id":      f"{_epnode_pre}->{_anode_pre}:triggered",
                    "source":       _epnode_pre,
                    "target":       _anode_pre,
                    "relation":     "triggered",
                    "timestamp":    now_str,
                    "last_updated": now_str,
                    "metadata":     {"severity": fusion.severity, "source": "demo_inject"},
                }},
                upsert=True,
            )
        except Exception as _ge:
            logger.debug("[demo/inject] graph_nodes write skipped: %s", _ge)

    # Emit graph_update so the Attack Graph shows the attack node immediately.
    # The graph_update handler in useAttackGraphData.ts is the only reliable
    # real-time path — it uses nodeMap from prev.NODES and is immune to the
    # React Strict Mode double-render issue that affects fusion_alert/network_anomaly handlers.
    risk_pct = int(fusion.threat_score * 100)
    _safe_attack = payload.attack_type.lower().replace(" ", "_").replace("+", "").replace("—", "").strip("_")
    _alert_nid  = f"alert-{_safe_attack}-{ep_id}"
    _ep_nid     = f"ep-{ep_id}"
    await sio.emit("graph_update", {
        "nodes": [
            {
                "node_id":    _ep_nid,
                "type":       "endpoint",
                "label":      payload.hostname,
                "risk_score": risk_pct,
                "severity":   fusion.severity,
                "endpoint_id": ep_id,
                "timestamp":  ts,
                "metadata":   {
                    "attack_type": payload.attack_type,
                    "ip":          payload.src_ip,
                    "status":      "under_attack",
                },
            },
            {
                "node_id":    _alert_nid,
                "type":       "alert",
                "label":      payload.attack_type,
                "risk_score": risk_pct,
                "severity":   fusion.severity,
                "endpoint_id": ep_id,
                "timestamp":  ts,
                "metadata":   {
                    "attack_type":  payload.attack_type,
                    "threat_score": fusion.threat_score,
                    "src_ip":       payload.src_ip,
                    "shap_reasons": shap_fusion.get("reason", []) if shap_fusion else [],
                },
            },
        ],
        "edges": [
            {
                "edge_id":  f"{_ep_nid}->{_alert_nid}:triggered",
                "source":   _ep_nid,
                "target":   _alert_nid,
                "relation": "triggered",
                "timestamp": ts,
                "metadata": {"severity": fusion.severity},
            }
        ],
    })

    # Generate response plan so the Respond button appears in AlertsTable
    if fusion.severity in ("HIGH", "CRITICAL"):
        await _maybe_generate_network_response_plan(
            endpoint_id=payload.host,
            severity=fusion.severity,
            attack_type=payload.attack_type,
            fusion=fusion,
        )

    logger.info(
        "[DEMO] Injected %s alert: severity=%s score=%.3f host=%s",
        payload.attack_type, fusion.severity, fusion.threat_score, payload.host,
    )
    return {
        "status":     "injected",
        "severity":   fusion.severity,
        "score":      round(fusion.threat_score, 4),
        "attack_type": fusion.attack_type,
    }


@app.post("/demo/cleanup", dependencies=[Depends(_require_key)])
async def demo_cleanup():
    """
    Remove all injected demo data from MongoDB so the dashboard starts clean.

    Clears:
      • endpoint_registry  — phantom DEMO-* endpoints created by old demo runs
      • fused_alerts        — alerts with source="demo_inject"
      • critical_alerts     — same
      • alerts              — alerts linked to demo_inject source
      • attack_graph_nodes  — threat nodes whose endpoint_id starts with "demo-"
      • attack_graph_edges  — edges referencing removed nodes

    Also removes entries whose hostname matches the legacy "DEMO-" prefix pattern,
    so old runs using /endpoint/ingest with fake hostnames are cleaned too.

    Emits `cleanup_complete` to all connected frontend clients so they re-fetch
    the endpoint list and remove phantom cards from the Endpoint Grid.
    """
    if _db is None:
        raise HTTPException(503, "MongoDB not available")

    import re as _re
    counts: dict = {}

    try:
        # Phantom endpoints: hostname starts with "DEMO-" (case-insensitive)
        # OR endpoint_id starts with "demo-"
        _demo_ep_pattern = _re.compile("^DEMO-", _re.IGNORECASE)
        _demo_id_pattern = _re.compile("^demo-", _re.IGNORECASE)

        phantom_docs = list(_db["endpoint_registry"].find(
            {"$or": [
                {"hostname": {"$regex": "^DEMO-", "$options": "i"}},
                {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
            ]},
            {"endpoint_id": 1, "_id": 0},
        ))
        phantom_ids = {d["endpoint_id"] for d in phantom_docs if d.get("endpoint_id")}

        r = _db["endpoint_registry"].delete_many({"$or": [
            {"hostname": {"$regex": "^DEMO-", "$options": "i"}},
            {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
        ]})
        counts["endpoint_registry"] = r.deleted_count

        # Emit offline event for each removed phantom so React state clears them
        for ep_id in phantom_ids:
            await sio.emit("endpoint_offline", {"endpoint_id": ep_id})

        # fused_alerts and critical_alerts: source=="demo_inject" OR legacy DEMO-* hostname
        _alert_filter = {"$or": [
            {"source": "demo_inject"},
            {"hostname": {"$regex": "^DEMO-", "$options": "i"}},
            {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
        ]}
        for col_name in ("fused_alerts", "critical_alerts", "alerts"):
            r = _db[col_name].delete_many(_alert_filter)
            counts[col_name] = r.deleted_count

        # attack_graph_nodes: DEMO-* phantom nodes AND demo_inject sourced nodes
        _node_filter = {"$or": [
            {"endpoint_id": {"$regex": "^demo-", "$options": "i"}},
            {"label": {"$regex": "^DEMO-", "$options": "i"}},
            {"node_id": {"$regex": "demo", "$options": "i"}},
            {"metadata.source": "demo_inject"},
        ]}
        # Also collect node_ids so we can remove their edges
        dead_nodes = {n["node_id"] for n in _db["attack_graph_nodes"].find(
            _node_filter, {"node_id": 1, "_id": 0}
        ) if n.get("node_id")}
        r = _db["attack_graph_nodes"].delete_many(_node_filter)
        counts["attack_graph_nodes"] = r.deleted_count

        if dead_nodes:
            r = _db["attack_graph_edges"].delete_many({"$or": [
                {"source": {"$in": list(dead_nodes)}},
                {"target": {"$in": list(dead_nodes)}},
            ]})
            counts["attack_graph_edges"] = r.deleted_count

    except Exception as _ce:
        logger.error("[DEMO] cleanup error: %s", _ce)
        raise HTTPException(500, f"Cleanup partial failure: {_ce}")

    # Signal frontend to re-fetch endpoint list
    await sio.emit("cleanup_complete", {"removed": counts})

    logger.info("[DEMO] Cleanup complete — %s", counts)
    return {"status": "cleaned", "removed": counts}


@app.get("/shap", dependencies=[Depends(_require_key_or_jwt)])
async def get_shap(alert_id: Optional[str] = None, model: Optional[str] = None):
    """
    Return the most recent (or specified) SHAP explanation.

    Query parameters:
        alert_id  (optional) — filter by a specific alert document ID.
        model     (optional) — filter by source model.
                               Accepted values: "network", "malware", "system".
                               When omitted the most recent explanation across
                               all models is returned.

    Returns the explanation document from the shap_explanations collection,
    or a placeholder when no document is found.
    """
    if MONGO_OK:
        query: dict = {}
        if alert_id:
            query["alert_id"] = alert_id
        if model:
            # "system" explanations are stored with source="system";
            # network/malware use the alert_id path and have no source field.
            if model == "system":
                query["source"] = "system"
            elif model in ("network", "malware"):
                # Network and malware docs don't carry an explicit source field
                # in the legacy schema — exclude system docs instead.
                query["source"] = {"$ne": "system"}
        try:
            doc = _db["shap_explanations"].find_one(query, sort=[("_id", DESCENDING)])
        except Exception as _db_err:
            logger.warning("[/shap] MongoDB unavailable: %s", _db_err)
            return {"reason": [], "top_features": [], "message": "No explanation available"}
        if doc:
            doc.pop("_id", None)
            return doc
    return {"reason": [], "top_features": [], "message": "No explanation available"}


@app.get("/commands", dependencies=[Depends(_require_key)])
async def get_commands(host: str):
    """Endpoint agent polls here for pending SOAR commands."""
    if not MONGO_OK:
        return {"commands": []}
    try:
        docs = list(_db["commands"].find({"host": host, "status": "pending"}))
    except Exception as _db_err:
        logger.warning("[/commands] MongoDB unavailable: %s", _db_err)
        return {"commands": []}
    for d in docs:
        d["_id"] = str(d["_id"])
    return {"commands": docs}


@app.post("/commands/{command_id}/ack", dependencies=[Depends(_require_key)])
async def ack_command(command_id: str, payload: CommandAckPayload):
    """Endpoint agent acknowledges command completion."""
    if MONGO_OK:
        from bson import ObjectId
        _db["commands"].update_one(
            {"_id": ObjectId(command_id)},
            {"$set": {"status": payload.status, "result": payload.result, "completed_at": _now()}},
        )
    return {"ok": True}


@app.get("/start-monitoring")
async def start_monitoring():
    global _monitoring_task, _malware_scan_task, _sysmon_ps_task, _endpoint_heartbeat_task, _server_soar_task, _monitoring_active
    _monitoring_active = True
    capture_status = await asyncio.to_thread(_start_capture_processes)
    already_running = _monitoring_task and not _monitoring_task.done()
    if not already_running:
        _monitoring_task = asyncio.create_task(_monitoring_loop(), name="network_monitor")
    # Start malware file-watcher independently (restarts even if network loop was running)
    if not (_malware_scan_task and not _malware_scan_task.done()):
        _malware_scan_task = asyncio.create_task(_malware_scan_loop(), name="malware_watcher")
    # Start Sysmon PowerShell event forwarder (feeds SysmonBehaviorAgent directly)
    if not (_sysmon_ps_task and not _sysmon_ps_task.done()):
        _sysmon_ps_task = asyncio.create_task(_sysmon_ps_loop(), name="sysmon_ps_forwarder")
        logger.info("Sysmon PS forwarder task started")
    # Start endpoint heartbeat monitor
    if not (_endpoint_heartbeat_task and not _endpoint_heartbeat_task.done()):
        _endpoint_heartbeat_task = asyncio.create_task(
            _endpoint_heartbeat_loop(), name="endpoint_heartbeat"
        )
        logger.info("Endpoint heartbeat monitor task started")
    # Start server-host SOAR executor loop
    if not (_server_soar_task and not _server_soar_task.done()):
        _server_soar_task = asyncio.create_task(
            _server_soar_loop(), name="server_soar_executor"
        )
        logger.info("Server SOAR executor task started")
    # Auto-start Winlogbeat if installed — non-blocking; falls back to Get-WinEvent
    asyncio.create_task(_wlb_start(), name="winlogbeat_start")
    asyncio.create_task(sio.emit("audit_event", {
        "user": "system", "action": "monitoring_started",
        "timestamp": _now(), "status": "success",
        "detail": "Network monitoring started", "ip": "localhost",
    }))
    return {
        "status": "already_running" if already_running else "started",
        "capture": capture_status,
        "malware_watcher": "started" if _malware_scan_task else "unavailable",
        "sysmon_forwarder": "started" if _sysmon_ps_task else "unavailable",
        "endpoint_heartbeat": "started" if _endpoint_heartbeat_task else "unavailable",
        "server_soar": "started" if _server_soar_task else "unavailable",
    }


@app.get("/stop-monitoring")
async def stop_monitoring():
    global _monitoring_task, _malware_scan_task, _sysmon_ps_task, _endpoint_heartbeat_task, _server_soar_task, _monitoring_active
    _monitoring_active = False
    if _monitoring_task and not _monitoring_task.done():
        _monitoring_task.cancel()
    _monitoring_task = None
    if _malware_scan_task and not _malware_scan_task.done():
        _malware_scan_task.cancel()
    _malware_scan_task = None
    if _sysmon_ps_task and not _sysmon_ps_task.done():
        _sysmon_ps_task.cancel()
    _sysmon_ps_task = None
    if _endpoint_heartbeat_task and not _endpoint_heartbeat_task.done():
        _endpoint_heartbeat_task.cancel()
    _endpoint_heartbeat_task = None
    if _server_soar_task and not _server_soar_task.done():
        _server_soar_task.cancel()
    _server_soar_task = None
    capture_status = await asyncio.to_thread(_stop_capture_processes)
    # Stop Winlogbeat if it was started by this monitoring session
    await _wlb_stop()
    asyncio.create_task(sio.emit("audit_event", {
        "user": "system", "action": "monitoring_stopped",
        "timestamp": _now(), "status": "success",
        "detail": "Network monitoring stopped", "ip": "localhost",
    }))
    return {
        "status": "stopped",
        "capture": capture_status,
        "malware_watcher": "stopped",
        "endpoint_heartbeat": "stopped",
        "server_soar": "stopped",
    }


@app.get("/storage-status")
async def storage_status():
    """Return current document counts vs. caps for every managed collection."""
    if not MONGO_OK or _db is None:
        return {"collections": {}, "mongo_ok": False}
    collections: dict[str, dict] = {}
    for col_name, cap in _COLLECTION_CAP.items():
        try:
            count = _db[col_name].count_documents({})
        except Exception:
            count = -1
        pct_full = round(count / cap * 100) if cap > 0 and count >= 0 else 0
        collections[col_name] = {"count": count, "cap": cap, "pct_full": pct_full}
    return {"collections": collections, "mongo_ok": MONGO_OK}


@app.get("/security/events")
async def get_security_events(
    request: Request,
    limit: int = 50,
    skip: int = 0,
    severity: Optional[str] = None,
    user_id: Optional[str] = None,
    ip: Optional[str] = None,
    event_type: Optional[str] = None,
    since: Optional[str] = None,
    api_key: Optional[str] = Security(_api_key_header),
):
    """
    Return recent unauthorized access events from the security_events collection.

    Access control: valid X-API-Key OR a Bearer JWT belonging to a user
    with the 'admin' role.  Any other caller receives 403.

    Query params (all optional, backward-compatible):
      limit      — max documents to return (1–500, default 50)
      skip       — offset for pagination (default 0)
      severity   — filter by severity: LOW | MEDIUM | HIGH | CRITICAL
      user_id    — filter by exact user_id string
      ip         — filter by IP address (prefix match if ends with '.', exact otherwise)
      event_type — filter by event_type field
      since      — ISO datetime string; return only events after this timestamp
    """
    # --- Auth: API key path ---
    authed_via_key = api_key == settings.api_key

    # --- Auth: JWT admin path ---
    authed_via_jwt = False
    if not authed_via_key:
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            token = auth_header.removeprefix("Bearer ").strip()
            if token:
                try:
                    from auth.security import decode_token as _decode_tok  # noqa: PLC0415
                    payload = _decode_tok(token, settings.jwt_secret_key, settings.jwt_algorithm)
                    if (
                        payload.get("type") == "access"
                        and payload.get("sub")
                        and payload.get("role") == "admin"
                    ):
                        authed_via_jwt = True
                except Exception:
                    pass

    if not authed_via_key and not authed_via_jwt:
        raise HTTPException(
            status_code=403,
            detail="Admin role or API key required",
        )

    if not MONGO_OK or _db is None:
        return {"events": [], "total": 0, "mongo_ok": False}

    limit = max(1, min(limit, 500))
    skip = max(0, skip)

    # Build filter query conditionally
    query: dict = {}

    if severity is not None:
        query["severity"] = severity.upper()

    if user_id is not None and user_id.strip():
        query["user_id"] = user_id.strip()

    if ip is not None and ip.strip():
        _ip = ip.strip()
        # Prefix match when caller supplies a subnet prefix like "192.168."
        # Exact match for full IPs — use $regex for both so the same field path works
        if _ip.endswith("."):
            query["ip"] = {"$regex": f"^{_ip}", "$options": "i"}
        else:
            query["ip"] = _ip

    if event_type is not None and event_type.strip():
        query["event_type"] = event_type.strip()

    if since is not None and since.strip():
        try:
            _since_dt = datetime.fromisoformat(since.strip().rstrip("Z"))
            query["timestamp"] = {"$gt": _since_dt.isoformat()}
        except ValueError:
            logger.warning("[SECURITY_EVENTS] Invalid 'since' value: %s", since)

    try:
        total = _db["security_events"].count_documents(query)
        docs = list(
            _db["security_events"]
            .find(query)
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        for d in docs:
            d.pop("_id", None)
    except Exception as exc:
        logger.error(f"security_events query failed: {exc}")
        return {"events": [], "total": 0, "error": str(exc)}

    return {"events": docs, "total": total}


@app.get("/audit-logs", dependencies=[Depends(_require_key_or_jwt)])
async def get_audit_logs(
    limit: int = 100,
    skip: int = 0,
):
    """
    Return historical auth audit events from the audit_logs collection.

    Access control: valid X-API-Key OR any authenticated JWT.

    Query params (all optional):
      limit — max documents to return (1–200, default 100)
      skip  — offset for pagination (default 0)

    Response: {"status": "ok", "logs": [...], "total": N}
    """
    if _db is None:
        return {"status": "ok", "logs": [], "total": 0}
    try:
        limit = max(1, min(limit, 200))
        skip = max(0, skip)
        cursor = (
            _db["audit_logs"]
            .find({}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        logs = list(cursor)
        total = _db["audit_logs"].count_documents({})
        return {"status": "ok", "logs": logs, "total": total}
    except Exception as exc:
        logger.error(f"[/audit-logs] {exc}")
        return {"status": "ok", "logs": [], "total": 0}


@app.post("/audit/client-event", dependencies=[Depends(_require_key_or_jwt)])
async def log_client_audit_event(request: Request, payload: dict = Body(...)):
    """Accept frontend-originated audit events (e.g. sound alerts toggle, UI settings changes)."""
    username = _jwt_sub_from_request(request) or "api_key"
    ip = request.client.host if request.client else "unknown"
    doc = {
        "user":      payload.get("user") or username,
        "action":    payload.get("action", "client_event"),
        "timestamp": _now(),
        "status":    payload.get("status", "success"),
        "detail":    payload.get("detail", ""),
        "ip":        ip,
        "source":    "client",
    }
    if MONGO_OK and _db is not None:
        try:
            _db["audit_logs"].insert_one({**doc})
        except Exception:
            pass
    await sio.emit("audit_event", doc)
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Analyst feedback labeling (false-positive / true-positive) — Feature #1
# Records analyst verdicts as a labeled corpus for periodic OFFLINE retraining.
# ADDITIVE: never modifies a running model; retraining is a separate, gated step.
# ---------------------------------------------------------------------------
@app.post("/feedback", dependencies=[Depends(_require_key_or_jwt)])
async def submit_feedback(request: Request, payload: dict = Body(...)):
    """Record an analyst verdict on an alert (false_positive / true_positive / benign)."""
    username = _jwt_sub_from_request(request) or "api_key"
    ip = request.client.host if request.client else "unknown"
    verdict = str(payload.get("verdict", "")).lower().strip()
    if verdict not in ("false_positive", "true_positive", "benign"):
        raise HTTPException(
            status_code=400,
            detail="verdict must be one of: false_positive, true_positive, benign",
        )
    # Resolve the raw feature vector for retraining. Prefer an inline snapshot
    # from the caller; otherwise look it up server-side from the response plan
    # (reference_id == plan_id), which stashed `source_features` at creation.
    # This is what makes a label "retrain-ready" (see retrain_from_feedback.py).
    _ref = str(payload.get("reference_id", "")).strip()
    _resolved_features = payload.get("features")
    _feat_source = "payload" if isinstance(_resolved_features, dict) and _resolved_features else "none"
    _plan_src_ip = ""
    if _feat_source == "none" and _ref and MONGO_OK and _db is not None:
        try:
            _plan_doc = await asyncio.to_thread(
                lambda: _db["response_plans"].find_one(
                    {"plan_id": _ref},
                    {"source_features": 1, "src_ip": 1, "attack_type": 1, "severity": 1},
                )
            )
            if _plan_doc:
                if isinstance(_plan_doc.get("source_features"), dict) and _plan_doc["source_features"]:
                    _resolved_features = _plan_doc["source_features"]
                    _feat_source = "plan"
                _plan_src_ip = str(_plan_doc.get("src_ip", "") or "")
        except Exception as _rf_exc:
            logger.debug(f"feedback feature resolution failed: {_rf_exc}")

    doc = {
        "feedback_id":  _uuid.uuid4().hex,
        "verdict":      verdict,
        "model":        str(payload.get("model", "")),          # network|user|system|malware|fusion
        "alert_type":   str(payload.get("alert_type", "")),
        "attack_type":  str(payload.get("attack_type", "")),
        "severity":     str(payload.get("severity", "")),
        "endpoint_id":  str(payload.get("endpoint_id", "")),
        "reference_id": _ref,                                   # alert / plan / incident id
        "src_ip":       str(payload.get("src_ip", "") or _plan_src_ip),
        "score":        payload.get("score"),
        "features":     _resolved_features,                     # feature snapshot for retraining
        "feature_source": _feat_source,                         # payload | plan | none
        "reason":       str(payload.get("reason", ""))[:500],
        "analyst":      username,
        "ip":           ip,
        "created_at":   _now(),
        "ts_dt":        _now_dt(),
        "used_in_training": False,
    }
    if MONGO_OK and _db is not None:
        try:
            await asyncio.to_thread(lambda: _db["feedback"].insert_one({**doc}))
        except Exception as _fe:
            logger.error(f"feedback insert failed: {_fe}")
            raise HTTPException(status_code=503, detail="feedback store unavailable")
    _audit = {
        "user": username, "action": "alert_feedback", "timestamp": _now(),
        "status": "success", "ip": ip,
        "detail": f"{verdict} on {doc['model'] or doc['alert_type'] or 'alert'}"
                  + (f" ({doc['attack_type']})" if doc['attack_type'] else ""),
    }
    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(lambda: _db["audit_logs"].insert_one({**_audit})))
    await sio.emit("audit_event", _audit)
    await sio.emit("feedback_recorded", {
        k: doc[k] for k in
        ("feedback_id", "verdict", "model", "attack_type", "endpoint_id", "analyst", "created_at")
    })
    return {"status": "ok", "feedback_id": doc["feedback_id"], "verdict": verdict}


@app.get("/feedback", dependencies=[Depends(_require_key_or_jwt)])
async def list_feedback(limit: int = 100, skip: int = 0, verdict: str = ""):
    """List recorded analyst feedback, newest first (for review + retraining export)."""
    if not (MONGO_OK and _db is not None):
        return {"feedback": [], "total": 0, "counts": {}}
    limit = max(1, min(int(limit), 500))
    skip = max(0, int(skip))
    query: dict = {}
    if verdict:
        query["verdict"] = verdict.lower().strip()
    try:
        total = await asyncio.to_thread(lambda: _db["feedback"].count_documents(query))
        docs = await asyncio.to_thread(lambda: list(
            _db["feedback"].find(query, {"_id": 0}).sort("_id", DESCENDING).skip(skip).limit(limit)
        ))
        counts = {
            v: await asyncio.to_thread(lambda _v=v: _db["feedback"].count_documents({"verdict": _v}))
            for v in ("false_positive", "true_positive", "benign")
        }
    except Exception as _le:
        logger.error(f"feedback list failed: {_le}")
        return {"feedback": [], "total": 0, "counts": {}}
    return {"feedback": docs, "total": total, "counts": counts}


# ---------------------------------------------------------------------------
# Background malware file-watcher loop
# ---------------------------------------------------------------------------
# Directories scanned on each tick (mirrors WATCH_PATHS in malware_analysis_agent.py)
_MALWARE_WATCH_PATHS = [
    r"C:\Users",
    r"C:\Temp",
    r"C:\Windows\Temp",
    r"C:\ProgramData",
    r"C:\Downloads",
]
_MALWARE_WATCH_EXTS = {".exe", ".dll", ".sys", ".scr"}
_MALWARE_SCAN_INTERVAL = int(os.getenv("MALWARE_SCAN_INTERVAL", "120"))  # seconds

# Directory names that are huge, noisy, and not realistic malware drop zones for
# this watcher. Pruning them keeps the periodic filesystem walk fast. Without this
# the walk of C:\Users (AppData, node_modules, caches, …) can take tens of seconds.
_MALWARE_WALK_PRUNE_DIRS = {
    "node_modules", "appdata", "application data", "$recycle.bin",
    "windows", "site-packages", "__pycache__", "venv", "env",
    ".cache", "cache", "temporary internet files", ".git", ".svn",
}
# Hard cap on PE files collected per cycle so a pathological tree can't blow up.
_MALWARE_WALK_MAX_FILES = 20000

# {file_path: mtime} — tracks already-scanned files so only new/changed ones are processed
_malware_seen: dict = {}

# {file_path: dict} — confirmed malicious files from any watcher scan cycle.
# Entries are re-emitted every _MALWARE_DIRECT_COOLDOWN seconds so a frontend
# that connects AFTER the initial scan still receives Alert Stream entries.
_malware_confirmed: dict = {}   # file_path → {"fusion": FusionResult, "result": dict, "ts": str, "shap": any}

# Never scan the XDR install tree itself (the repo + its parent deployment folder).
# Otherwise the watcher flags our own bundled tools/installers (e.g. npcap-*.exe)
# as malware — a noisy false positive from the system scanning itself.
_XDR_SKIP_ROOTS: tuple = tuple(
    str(p).lower() for p in {
        Path(__file__).resolve().parent.parent,          # cyber-sentinal-xdr-main (repo root)
        Path(__file__).resolve().parent.parent.parent,   # deployment folder (contains installers)
    }
)


def _scan_for_new_malware_files() -> list[str]:
    """Synchronous walk of the watch paths for new/modified PE files.

    Runs in a worker thread (via asyncio.to_thread) so the potentially huge
    filesystem walk NEVER blocks the async event loop — a blocking rglob over
    C:\\Users previously froze the loop for tens of seconds each cycle, which
    timed out the endpoint agent and the dashboard. Prunes big noise subtrees
    (AppData, node_modules, caches) and caps the number of PE files per cycle.
    """
    new_files: list[str] = []
    examined = 0
    for watch_dir in _MALWARE_WATCH_PATHS:
        if not os.path.isdir(watch_dir):
            continue
        try:
            for root, dirs, files in os.walk(watch_dir):
                # Skip the XDR install tree entirely (don't flag our own tools).
                if _XDR_SKIP_ROOTS and root.lower().startswith(_XDR_SKIP_ROOTS):
                    dirs[:] = []
                    continue
                # Prune noisy / huge subtrees in-place so os.walk never descends them.
                dirs[:] = [
                    d for d in dirs
                    if d.lower() not in _MALWARE_WALK_PRUNE_DIRS and not d.startswith(".")
                ]
                for fname in files:
                    if os.path.splitext(fname)[1].lower() not in _MALWARE_WATCH_EXTS:
                        continue
                    fpath = os.path.join(root, fname)
                    try:
                        mtime = os.path.getmtime(fpath)
                    except OSError:
                        continue
                    if _malware_seen.get(fpath) != mtime:
                        _malware_seen[fpath] = mtime
                        new_files.append(fpath)
                    examined += 1
                    if examined >= _MALWARE_WALK_MAX_FILES:
                        return new_files
        except Exception as walk_err:
            logger.debug(f"Malware watcher walk error in {watch_dir}: {walk_err}")
    return new_files


async def _malware_scan_loop():
    """
    Periodically walk WATCH_PATHS for new or modified PE files and score each
    one through MalwareAnalysisAgent.  Emits malware_scan (every file) and
    malware_alert (MALWARE hits only) Socket.IO events, exactly like /scan/malware.
    """
    logger.info(
        f"Malware file-watcher started — paths: {_MALWARE_WATCH_PATHS}, "
        f"interval: {_MALWARE_SCAN_INTERVAL}s"
    )
    while True:
        try:
            if _malware_agent and _malware_agent._model_loaded:
                # ── Re-emit previously-confirmed malicious files ──────────────
                # This ensures a frontend that connects AFTER the initial scan
                # cycle still receives a network_anomaly Alert Stream entry.
                # _maybe_emit_malware_fusion_alert's 60 s cooldown governs the
                # actual emit rate; the loop just gives it the opportunity.
                for _cf_path, _cf_data in list(_malware_confirmed.items()):
                    try:
                        await _maybe_emit_malware_fusion_alert(
                            _cf_data["fusion"],
                            _cf_data["result"],
                            "local",
                            _cf_data["ts"],
                            _cf_data["shap"],
                        )
                    except Exception as _cf_err:
                        logger.debug("[MALWARE] re-emit confirmed malicious failed for %s: %s", _cf_path, _cf_err)

                # Run the (potentially large) filesystem walk in a worker thread so
                # it never blocks the async event loop / starves the endpoint agent.
                new_files = await asyncio.to_thread(_scan_for_new_malware_files)

                if new_files:
                    logger.info(f"Malware watcher: scanning {len(new_files)} new/modified files")
                    for file_path in new_files:
                        try:
                            result = await asyncio.to_thread(_malware_agent.predict, file_path)
                            ts = _now()
                            shap_explanation = _maybe_explain_malware(result.get("features_scaled"))
                            result_doc = {**result, "host": "local", "ts": ts, "source": "file_watcher", "shap_explanation": shap_explanation}
                            result_doc.pop("features_scaled", None)
                            _save("malware_scans", result_doc)
                            _save("malware_events", result_doc)
                            if result.get("label") in ("malicious", "suspicious") and not result.get("trusted", False):
                                malware_score = result.get("score", 0.0)
                                async with _scores_lock:
                                    _latest_scores["malware"] = {"score": max(_latest_scores["malware"]["score"], malware_score), "ts": time.monotonic()}
                                _scores = _get_current_scores()
                                fusion = _fusion_agent.fuse(
                                    network_score=_scores["network"],
                                    user_score=_scores["user"],
                                    system_score=_scores["system"],
                                    malware_score=malware_score,
                                ) if _fusion_agent else None
                                alert_doc = {
                                    **result_doc,
                                    "fusion": fusion.to_dict() if fusion else None,
                                }
                                _save("alerts", alert_doc)
                                _save("predictions", {**alert_doc, "model": "malware"})
                                _watcher_malware_payload = _strip_mongo({
                                    **alert_doc,
                                    "file_size": result.get("file_size", 0),
                                    "fusion": {
                                        "threat_score": round(float(fusion.threat_score), 4) if fusion else 0.0,
                                        "severity": fusion.severity if fusion else "LOW",
                                        "attack_type": "Malware Activity",
                                    },
                                })
                                await sio.emit("malware_alert", _watcher_malware_payload)
                                if _graph_engine:
                                    _mal_ev_watcher = {**_watcher_malware_payload, "endpoint_id": "server"}
                                    try:
                                        g_nodes, g_edges = _graph_engine.process_malware_alert(_mal_ev_watcher)
                                        await _emit_graph_update(g_nodes, g_edges)
                                    except Exception as _ge:
                                        logger.debug(f"[GRAPH] malware_alert (watcher) hook error: {_ge}")
                                    asyncio.create_task(asyncio.to_thread(
                                        _graph_engine.ingest_to_incident, "malware", _mal_ev_watcher
                                    ))
                                if fusion and fusion.should_respond:
                                    shap_fusion = _explain_fusion(fusion)
                                    fused_alert_doc = {**fusion.to_dict(), "source": "malware_watcher", "ts": ts, "shap": shap_fusion, "ts_dt": _now_dt()}
                                    # Exclude ts_dt (datetime) so sio.emit can JSON-serialise
                                    _watcher_fusion_payload = {k: v for k, v in fused_alert_doc.items() if k not in ("_id", "ts_dt")}
                                    await sio.emit("fusion_alert", _watcher_fusion_payload)
                                    _save("fused_alerts", fused_alert_doc)
                                    # Dual-write HIGH/CRITICAL to uncapped permanent evidence store
                                    if fusion.severity in ("HIGH", "CRITICAL"):
                                        _save("critical_alerts", fused_alert_doc)
                                    if _graph_engine:
                                        try:
                                            g_nodes, g_edges = _graph_engine.process_fusion_alert(_watcher_fusion_payload)
                                            await _emit_graph_update(g_nodes, g_edges)
                                        except Exception as _ge:
                                            logger.debug(f"[GRAPH] fusion_alert (malware/watcher) hook error: {_ge}")
                                        asyncio.create_task(asyncio.to_thread(
                                            _graph_engine.ingest_to_incident, "fusion", _watcher_fusion_payload
                                        ))
                                if result.get("label") == "malicious" and not result.get("trusted", False):
                                    _save("commands", {
                                        "host": "local",
                                        "actions": ["quarantine_file"],
                                        "params": {"file_path": result.get("file_path", "")},
                                        "status": "pending",
                                        "trigger": "malware_direct",
                                        "score": result.get("score"),
                                        "ts": _now(),
                                    })
                                if result.get("label") == "malicious" and not result.get("trusted", False):
                                    try:
                                        fe_event = {
                                            "source": "malware",
                                            "timestamp": ts,
                                            "host": "local",
                                            "severity": "CRITICAL",
                                            "confidence": result.get("score", 0.0),
                                            "prediction": result.get("file_path", "malware_detected"),
                                            "label": "malicious",
                                            "trusted": False,
                                        }
                                        fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
                                        await _emit_soc_alert_if_correlated(fe_out, ts)
                                    except Exception as _fe_exc:
                                        logger.debug(f"fusion_engine.ingest_event (malware_watcher) skipped: {_fe_exc}")
                                # Guarantee Alert Stream entry for HIGH/CRITICAL malicious files.
                                await _maybe_emit_malware_fusion_alert(
                                    fusion, result, "local", ts, shap_explanation
                                )
                                # Register in confirmed-malicious cache so that
                                # the re-emit block at the top of each cycle can
                                # keep the Alert Stream updated for late-connecting
                                # or reconnecting frontend clients.
                                if (
                                    result.get("label") == "malicious"
                                    and not result.get("trusted", False)
                                    and fusion is not None
                                ):
                                    _malware_confirmed[file_path] = {
                                        "fusion":  fusion,
                                        "result":  result,
                                        "ts":      ts,
                                        "shap":    shap_explanation,
                                    }
                            await sio.emit("malware_scan", _strip_mongo({**result_doc, "file_size": result.get("file_size", 0)}))
                        except Exception as file_err:
                            logger.debug(f"Malware watcher file error {file_path}: {file_err}")
        except asyncio.CancelledError:
            logger.info("Malware scan loop cancelled")
            raise
        except Exception as e:
            logger.error(f"[malware_watcher] loop iteration failed: {e}", exc_info=True)
            await asyncio.sleep(5)
            continue

        await asyncio.sleep(_MALWARE_SCAN_INTERVAL)


# ---------------------------------------------------------------------------
# Background monitoring loop
# ---------------------------------------------------------------------------
async def _monitoring_loop():
    global _cycle_count, _zero_flow_cycles
    logger.info("Network monitoring loop started")
    while True:
        try:
            if _network_agent:
                result = await asyncio.to_thread(_network_agent.detect)
                flow_count = result.get("clean_flow_count", 0) + len(result.get("rule_hits", []))
                if flow_count == 0:
                    _zero_flow_cycles += 1
                    # Log a diagnostic warning every 30 consecutive zero-flow cycles
                    # (~5 minutes at default 10s cycle) so the operator knows Suricata
                    # is not producing data rather than silently wondering why the
                    # Network section is empty.
                    if _zero_flow_cycles % 30 == 0:
                        import os as _os
                        eve_path = r"C:\SuricataLogs\eve.json"
                        eve_exists = _os.path.exists(eve_path)
                        eve_size   = _os.path.getsize(eve_path) if eve_exists else -1
                        logger.warning(
                            "[NETWORK] 0 flows for %d consecutive cycles. "
                            "Suricata eve.json: exists=%s size=%d bytes path=%s — "
                            "check interface GUID, C:\\SuricataLogs\\ directory, and Suricata process.",
                            _zero_flow_cycles, eve_exists, eve_size, eve_path,
                        )
                else:
                    if _zero_flow_cycles > 0:
                        logger.info("[NETWORK] Flow capture resumed after %d idle cycles.", _zero_flow_cycles)
                    _zero_flow_cycles = 0
                await _process_network_result(result)
            _cycle_count += 1
            if _cycle_count % 100 == 0:
                await asyncio.to_thread(_periodic_trim)
        except asyncio.CancelledError:
            logger.info("Monitoring loop cancelled")
            raise
        except Exception as e:
            logger.error(f"[network_monitor] loop iteration failed: {e}", exc_info=True)
            await asyncio.sleep(5)
            continue
        import os as _os
        _eve = r"C:\SuricataLogs\eve.json"
        await sio.emit("monitoring_status", {
            "network_active":      _network_agent is not None,
            "user_active":         _user_agent is not None,
            "system_active":       _system_agent is not None and _system_agent._running,
            "system_model_loaded": _system_agent is not None and _system_agent.status().get("model_loaded", False),
            "malware_active":      _malware_agent is not None and _malware_agent._model_loaded,
            "sysmon_active":       _sysmon_agent is not None and _sysmon_agent._model_loaded,
            "malware_watcher":     _malware_scan_task is not None and not _malware_scan_task.done(),
            "cycle":               _cycle_count,
            "zero_flow_cycles":    _zero_flow_cycles,
            "suricata_eve_exists": _os.path.exists(_eve),
            "suricata_eve_bytes":  _os.path.getsize(_eve) if _os.path.exists(_eve) else 0,
            "ts":                  _now(),
        })
        await asyncio.sleep(settings.monitoring_cycle_seconds)


# ---------------------------------------------------------------------------
# Result processing helpers
# ---------------------------------------------------------------------------
async def _process_network_result(result: dict):
    global _latest_scores
    ts = _now()

    for hit in result.get("rule_hits", []):
        hit["ts"] = ts
        # Rule hits represent confirmed attacks — treat as high-confidence network score
        rule_network_score = 1.0
        async with _scores_lock:
            _latest_scores["network"] = {"score": rule_network_score, "ts": time.monotonic()}
        _scores = _get_current_scores()
        fusion = _fusion_agent.fuse(
            network_score=rule_network_score,
            user_score=_scores["user"],
            system_score=_scores["system"],
            malware_score=_scores["malware"],
            endpoint_id=hit.get("src_ip", "global"),
        ) if _fusion_agent else None
        if fusion:
            logger.info(
                f"[FUSION] Threat detected: severity={fusion.severity} "
                f"score={fusion.threat_score:.3f} endpoint={fusion.endpoint_id}"
            )
        shap_doc = _maybe_explain(hit.get("features"), hit.get("attack_type"))

        event = {**hit, "fusion": fusion.to_dict() if fusion else None, "shap": shap_doc}
        _save("alerts", event)
        if shap_doc:
            _save("shap_explanations", {**shap_doc, "alert_ts": ts})
        await sio.emit("network", _strip_mongo(event))
        if fusion and fusion.should_respond:
            shap_fusion = _explain_fusion(fusion)
            _rule_fusion_payload = _strip_mongo({
                **fusion.to_dict(),
                "source": "network",
                "ts": ts,
                "shap": shap_fusion,
                "endpoint_id": fusion.endpoint_id or "global",
                "confidence": round(fusion.threat_score, 4),
                "attack_type": fusion.attack_type,
                "contributing_signals": fusion.contributing_models,
                "contributing_reasons": fusion.contributing_reasons,
            })
            await sio.emit("fusion_alert", _rule_fusion_payload)
            await _maybe_generate_network_response_plan(
                endpoint_id="server_host",
                severity=fusion.severity,
                attack_type=hit.get("attack_type", "Network Attack"),
                fusion=fusion,
                ts=ts,
                shap_fusion=shap_fusion,
                features=hit.get("features"),
                src_ip=hit.get("src_ip", ""),
            )
            if _graph_engine:
                try:
                    g_nodes, g_edges = _graph_engine.process_fusion_alert(_rule_fusion_payload)
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] fusion_alert (rule_hit) hook error: {_ge}")
                asyncio.create_task(asyncio.to_thread(
                    _graph_engine.ingest_to_incident, "fusion", _rule_fusion_payload
                ))
        try:
            fe_event = {
                "source": "network",
                "timestamp": ts,
                "host": hit.get("src_ip", "unknown"),
                "severity": hit.get("severity", "HIGH"),
                "confidence": rule_network_score,
                "prediction": hit.get("rule", "rule_hit"),
                "features": hit.get("features", {}),
            }
            fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
            await _emit_soc_alert_if_correlated(fe_out, ts)
        except Exception as _fe_exc:
            logger.debug(f"fusion_engine.ingest_event (rule_hit) skipped: {_fe_exc}")

    for ml in result.get("ml_results", []):
        ml["ts"] = ts
        is_attack = ml.get("prediction") == "ATTACK"
        network_score = ml.get("confidence", 0) / 100.0 if is_attack else 0.0
        # Gate: suppress ML detections that fall below the operator-configured threshold
        if is_attack and network_score < _network_anomaly_threshold:
            logger.debug(
                "[NETWORK] ML attack suppressed by threshold: "
                "score=%.3f threshold=%.2f attack_type=%s",
                network_score, _network_anomaly_threshold, ml.get("attack_type", "?"),
            )
            is_attack = False
            network_score = 0.0
        if is_attack:
            async with _scores_lock:
                _latest_scores["network"] = {"score": network_score, "ts": time.monotonic()}
        _scores = _get_current_scores()
        fusion = _fusion_agent.fuse(
            network_score=network_score,
            user_score=_scores["user"],
            system_score=_scores["system"],
            malware_score=_scores["malware"],
            endpoint_id=ml.get("src_ip", "global"),
        ) if (_fusion_agent and is_attack) else None
        if fusion:
            logger.info(
                f"[FUSION] Threat detected: severity={fusion.severity} "
                f"score={fusion.threat_score:.3f} endpoint={fusion.endpoint_id}"
            )
        shap_doc = _maybe_explain(ml.get("features"), ml.get("attack_type")) if is_attack else None

        event = {**ml, "fusion": fusion.to_dict() if fusion else None, "shap": shap_doc}
        # Always emit to dashboard; only persist attacks to MongoDB
        if is_attack:
            _save("predictions", event)
            if ml.get("severity") in ("HIGH", "CRITICAL"):
                _save("alerts", event)
            if shap_doc:
                _save("shap_explanations", {**shap_doc, "alert_ts": ts})
        await sio.emit("network", _strip_mongo(event))
        if fusion and fusion.should_respond:
            shap_fusion = _explain_fusion(fusion)
            _ml_fusion_payload = _strip_mongo({
                **fusion.to_dict(),
                "source": "network",
                "ts": ts,
                "shap": shap_fusion,
                "endpoint_id": fusion.endpoint_id or "global",
                "confidence": round(fusion.threat_score, 4),
                "attack_type": fusion.attack_type,
                "contributing_signals": fusion.contributing_models,
                "contributing_reasons": fusion.contributing_reasons,
            })
            await sio.emit("fusion_alert", _ml_fusion_payload)
            await _maybe_generate_network_response_plan(
                endpoint_id="server_host",
                severity=fusion.severity,
                attack_type=ml.get("attack_type", "Network Attack"),
                fusion=fusion,
                ts=ts,
                shap_fusion=shap_fusion,
                features=ml.get("features"),
                src_ip=ml.get("src_ip", ""),
            )
            if _graph_engine:
                try:
                    g_nodes, g_edges = _graph_engine.process_fusion_alert(_ml_fusion_payload)
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] fusion_alert (ml_result) hook error: {_ge}")
                asyncio.create_task(asyncio.to_thread(
                    _graph_engine.ingest_to_incident, "fusion", _ml_fusion_payload
                ))
        if is_attack and _graph_engine:
            try:
                _net_ev = {
                    **ml,
                    "source_ip":      ml.get("src_ip", ""),
                    "destination_ip": ml.get("dst_ip", ml.get("dest_ip", "")),
                }
                _gn, _ge2 = _graph_engine.process_network_anomaly(_net_ev)
                await _emit_graph_update(_gn, _ge2)
            except Exception as _ge:
                logger.debug(f"[GRAPH] network_anomaly (ml_result) hook error: {_ge}")
            asyncio.create_task(asyncio.to_thread(
                _graph_engine.ingest_to_incident, "network", ml
            ))
        if is_attack:
            try:
                fe_event = {
                    "source": "network",
                    "timestamp": ts,
                    "host": ml.get("src_ip", "unknown"),
                    "severity": ml.get("severity", "MEDIUM"),
                    "confidence": network_score,
                    "prediction": ml.get("attack_type", "ATTACK"),
                    "features": ml.get("features", {}),
                }
                fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
                await _emit_soc_alert_if_correlated(fe_out, ts)
            except Exception as _fe_exc:
                logger.debug(f"fusion_engine.ingest_event (ml_result) skipped: {_fe_exc}")


async def _handle_user_result(result: dict):
    """Called by UserBehaviorAgent after each inference cycle."""
    global _latest_scores
    ts = _now()
    summary = result.get("summary", {})
    logger.info(
        f"UserBehavior cycle: {summary.get('total_users', 0)} users, "
        f"{summary.get('anomaly', 0)} anomalies, "
        f"{result.get('events_count', 0)} events processed"
    )

    # Winlogbeat health check: the agent injects status="winlogbeat_offline" when
    # no events and no log files were found.  Emit a structured Socket.IO event so
    # the frontend can show "Winlogbeat offline" instead of staying silent.
    # The fallback raw-count check handles the case where the result was produced
    # by a caller that did not go through _tick() (e.g. /predict/user HTTP endpoint).
    _wb_offline = (
        result.get("status") == "winlogbeat_offline"
        or (result.get("events_count", 0) == 0 and result.get("log_files_count", 0) == 0)
    )
    if _wb_offline:
        _offline_reason = result.get(
            "reason",
            "Winlogbeat not configured — install and configure Winlogbeat "
            "to enable user behavior scoring",
        )
        await sio.emit("user_behavior_summary", {
            "status": "winlogbeat_offline",
            "online": False,
            "score": 0.0,
            "reason": _offline_reason,
            "total_users": 0,
            "normal_users": 0,
            "anomaly_users": 0,
            "avg_score": 0.0,
            "cycle_ts": ts,
            "ts": ts,
        })
        logger.warning(
            "UserBehavior: Winlogbeat offline — no events and no log files found. "
            "C:\\XDR_Logs\\ is empty or Winlogbeat is not running. "
            "Set START_WINLOGBEAT=true in .env to auto-start it."
        )
        return

    for row in result.get("rows", []):
        is_anomaly = row.get("prediction_label") == "ANOMALY"
        raw_score = float(row.get("anomaly_score", 0.0))
        # xdr_runtime.py already maps model scores to [0,1];
        # pass through directly — do NOT apply a second transformation.
        user_score = raw_score if is_anomaly else 0.0

        # Derive a severity tier from the anomaly score so that not every
        # anomaly is emitted as CRITICAL.  Thresholds:
        #   score > 0.85 → CRITICAL
        #   score > 0.70 → HIGH
        #   score > 0.50 → MEDIUM  (below 0.50 is suppressed entirely below)
        if raw_score > 0.85:
            user_severity = "CRITICAL"
        elif raw_score > 0.70:
            user_severity = "HIGH"
        else:
            user_severity = "MEDIUM"

        if is_anomaly:
            async with _scores_lock:
                _latest_scores["user"] = {"score": max(_latest_scores["user"]["score"], user_score), "ts": time.monotonic()}
        _scores = _get_current_scores()
        fusion = _fusion_agent.fuse(
            network_score=_scores["network"],
            user_score=user_score,
            system_score=_scores["system"],
            malware_score=_scores["malware"],
            endpoint_id=row.get("user", "global"),
        ) if (_fusion_agent and is_anomaly) else None
        if fusion:
            logger.info(
                f"[FUSION] Threat detected: severity={fusion.severity} "
                f"score={fusion.threat_score:.3f} endpoint={fusion.endpoint_id}"
            )
        display_score = round(raw_score, 4)
        fusion_saved = False
        event = {
            **row,
            "anomaly_score": display_score,
            "severity": user_severity,
            "ts": ts,
            "source": "user_behavior",
            "fusion": fusion.to_dict() if fusion else None,
        }
        # Only persist and emit anomalies with user_score >= _user_behavior_threshold;
        # lower scores are informational noise and would flood the dashboard.
        # shap_reasons is populated below when user_score meets threshold; pre-initialise
        # so the fusion and fe_ingest blocks below can safely reference it.
        shap_reasons: list = []
        if is_anomaly and user_score >= _user_behavior_threshold:
            logger.warning(
                f"USER ANOMALY: user={row.get('user')} score={display_score} "
                f"severity={user_severity} "
                f"files={row.get('files_accessed', 0)} reason={row.get('anomaly_reason', '')}"
            )
            # Run SHAP sensitivity explanation — never blocks the alert pipeline
            shap_reasons = await _maybe_explain_user(row, ts)
            if shap_reasons:
                event["shap_explanation"] = shap_reasons
            _save("alerts", event)
            fusion_saved = True
            _user_anomaly_payload = _strip_mongo(event)
            await sio.emit("user_anomaly", _user_anomaly_payload)
        elif is_anomaly:
            logger.debug(
                f"[USER] Low-confidence anomaly suppressed: user={row.get('user')} "
                f"score={display_score:.4f} (threshold={_user_behavior_threshold})"
            )
        if is_anomaly and user_score >= _user_behavior_threshold and _graph_engine:
            try:
                g_nodes, g_edges = _graph_engine.process_user_anomaly({
                    **_user_anomaly_payload,
                    "user": row.get("user", "unknown"),
                })
                await _emit_graph_update(g_nodes, g_edges)
            except Exception as _ge:
                logger.debug(f"[GRAPH] user_anomaly hook error: {_ge}")
            asyncio.create_task(asyncio.to_thread(
                _graph_engine.ingest_to_incident, "user", _user_anomaly_payload
            ))
        if fusion and fusion.should_respond and user_score >= _user_behavior_threshold:
            shap_fusion = _explain_fusion(fusion)
            fusion_event = {
                **fusion.to_dict(),
                "source": "user_behavior",
                "ts": ts,
                "shap": shap_fusion,
                "endpoint_id": fusion.endpoint_id or "global",
                "confidence": round(fusion.threat_score, 4),
                "attack_type": fusion.attack_type,
                "contributing_signals": fusion.contributing_models,
                "contributing_reasons": fusion.contributing_reasons,
            }
            if not fusion_saved:
                _save("alerts", fusion_event)
            _user_fusion_payload = _strip_mongo(fusion_event)
            await sio.emit("fusion_alert", _user_fusion_payload)
            if _graph_engine:
                try:
                    g_nodes, g_edges = _graph_engine.process_fusion_alert(_user_fusion_payload)
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] fusion_alert (user) hook error: {_ge}")
                asyncio.create_task(asyncio.to_thread(
                    _graph_engine.ingest_to_incident, "fusion", _user_fusion_payload
                ))
            # Generate a response plan so the ResponseModal has SHAP data to render.
            # Mirror the pattern used by _maybe_generate_network_response_plan:
            # pass shap_reasons (already computed above) as shap_explanation so the
            # plan carries the user-specific feature attributions.
            await _maybe_generate_user_response_plan(
                endpoint_id=fusion.endpoint_id or "server_host",
                severity=fusion.severity,
                user=row.get("user", "unknown"),
                fusion=fusion,
                shap_reasons=shap_reasons,
                ts=ts,
            )
        if is_anomaly:
            try:
                # Use the score-derived severity rather than defaulting to HIGH
                # for every anomaly regardless of its confidence level.
                fe_severity = fusion.severity if fusion else user_severity
                fe_event = {
                    "source": "user",
                    "timestamp": ts,
                    "host": row.get("user", "unknown"),
                    "severity": fe_severity,
                    "confidence": user_score,
                    "prediction": row.get("anomaly_reason", "user_anomaly"),
                    # Carry shap_reasons so _emit_soc_alert_if_correlated can
                    # include them when a multi-source plan is generated.
                    "shap_explanation": shap_reasons,
                }
                fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
                # Propagate user SHAP into fe_out so the correlated plan also
                # gets user-specific SHAP data if no other source has SHAP.
                if shap_reasons and not fe_out.get("shap_explanation"):
                    fe_out["shap_explanation"] = shap_reasons
                await _emit_soc_alert_if_correlated(fe_out, ts)
            except Exception as _fe_exc:
                logger.debug(f"fusion_engine.ingest_event (user) skipped: {_fe_exc}")

    raw_summary = result.get("summary", {})

    # Build a compact per-user list from all rows (anomalous AND normal) so
    # the frontend can show every processed user in the User Behavior Log table,
    # even when no anomaly crosses the 0.80 emission threshold.
    _all_rows = result.get("rows", [])
    _user_rows_for_summary: list[dict] = []
    for _r in _all_rows[:50]:   # cap at 50 to avoid oversized socket frames
        _is_anom = _r.get("prediction_label") == "ANOMALY"
        _raw_sc  = float(_r.get("anomaly_score", 0.0))
        if _raw_sc > 0.85:
            _sev = "CRITICAL"
        elif _raw_sc > 0.70:
            _sev = "HIGH"
        elif _raw_sc > 0.50:
            _sev = "MEDIUM"
        else:
            _sev = "LOW"
        _user_rows_for_summary.append({
            "user":               _r.get("user", "unknown"),
            "prediction_label":   "ANOMALY" if _is_anom else "NORMAL",
            "anomaly_score":      round(_raw_sc, 4),
            "severity":           _sev,
            "after_hours_logins": int(_r.get("after_hours_logins", 0)),
            "usb_connects":       int(_r.get("usb_connects", 0) if not isinstance(_r.get("usb_connects"), str) else 0),
            "files_accessed":     int(_r.get("files_accessed", 0) if not isinstance(_r.get("files_accessed"), str) else 0),
            "emails_sent":        int(_r.get("emails_sent", 0) if not isinstance(_r.get("emails_sent"), str) else 0),
            "total_logins":       int(_r.get("total_logins", 0)),
            "anomaly_reason":     str(_r.get("anomaly_reason", "")),
            "source":             "user_behavior",
            "ts":                 ts,
        })

    summary_doc = {
        "total_users":   raw_summary.get("total_users", 0),
        "normal_users":  raw_summary.get("normal", 0),
        "anomaly_users": raw_summary.get("anomaly", 0),
        "avg_score":     raw_summary.get("avg_score", 0.0),
        "cycle_ts":      ts,
        "ts":            ts,
        "users":         _user_rows_for_summary,
    }
    await sio.emit("user_behavior_summary", summary_doc)
    # Persist the summary without the full per-user list to keep MongoDB compact
    _save("user_behavior_cycles", {k: v for k, v in summary_doc.items() if k != "users"})


_SYSTEM_ALERT_COOLDOWN = 30.0   # seconds between consecutive anomaly saves/alerts

# Sysmon alert rate-limit — prevents EventID 3 port-scan flooding from emitting
# hundreds of socket events per minute.  Only one sysmon_alert is emitted per
# _SYSMON_EMIT_COOLDOWN seconds regardless of how many events arrive.
_last_sysmon_emit_time: float = 0.0
_SYSMON_EMIT_COOLDOWN: float = 5.0   # minimum seconds between consecutive sysmon_alert emits

async def _handle_system_result(result: dict):
    """Called by SystemMonitorAgent after each inference cycle."""
    global _latest_system_score, _latest_scores, _last_system_alert_t
    ts = _now()
    score = float(result.get("anomaly_score", 0.0))
    severity = result.get("severity", "LOW")
    logger.debug(f"[SYSTEM] result: score={score:.4f} severity={severity} buffer={result.get('buffer_fill','?')}")
    is_anomaly = result.get("is_genuinely_anomalous", False) or (score >= _system_anomaly_threshold and severity in ("HIGH", "CRITICAL"))
    if result.get("behavioral_is_anomaly") and result.get("behavioral_score", 0) > score:
        logger.info(f"[SYSTEM] Behavioral detector dominant: type={result.get('behavioral_attack_type')} bscore={result.get('behavioral_score'):.4f}")

    _latest_system_score = score
    combined_system = max(_latest_system_score, _latest_sysmon_score)
    async with _scores_lock:
        _latest_scores["system"] = {"score": combined_system, "ts": time.monotonic()}

    now_t = time.monotonic()
    alert_allowed = is_anomaly and (now_t - _last_system_alert_t) >= _SYSTEM_ALERT_COOLDOWN

    _scores = _get_current_scores()
    # Always pass endpoint_id="server_host" so fusion_alert and response plans
    # are routed to the server entry in the endpoint registry, not a remote endpoint.
    fusion = _fusion_agent.fuse(
        network_score=_scores["network"],
        user_score=_scores["user"],
        system_score=combined_system,
        malware_score=_scores["malware"],
        endpoint_id="server_host",
    ) if (_fusion_agent and alert_allowed) else None
    fusion_saved = False
    event = {
        **result,
        "ts": ts,
        "endpoint_id": "server_host",
        "source": "system_monitor",
        "fusion": fusion.to_dict() if fusion else None,
    }

    # Populate feature-metric reasons for ALL events so the System Telemetry
    # Logs column never shows "—".  Anomaly events will override these with
    # SHAP reconstruction-error reasons via the _maybe_explain_system block below.
    _feature_reasons = _generate_system_feature_reasons(result)
    if _feature_reasons and not event.get("shap_reasons"):
        event["shap_reasons"] = _feature_reasons
        event["shap_explanation"] = _feature_reasons

    if alert_allowed:
        _last_system_alert_t = now_t
        logger.warning(f"SYSTEM ANOMALY: score={score:.4f} severity={severity}")
        # Run SHAP reconstruction-error explanation asynchronously
        shap_reasons = await _maybe_explain_system(result)
        if shap_reasons:
            event["shap_reasons"] = shap_reasons
            event["shap_explanation"] = shap_reasons  # alias for frontend compat
        _save("alerts", event)
        fusion_saved = True
        await sio.emit("system_anomaly", _strip_mongo(event))
        try:
            _behavioral_type = result.get("behavioral_attack_type", "")
            _use_behavioral = (
                result.get("behavioral_is_anomaly")
                and _behavioral_type
                and _behavioral_type != "Background"
            )
            fe_event = {
                "source": "system",
                "timestamp": ts,
                "host": "server_host",
                "endpoint_id": "server_host",
                "severity": severity,
                "confidence": score,
                "prediction": _behavioral_type if _use_behavioral else f"system_anomaly_{severity.lower()}",
                "behavioral_attack_type": _behavioral_type,
                "is_genuinely_anomalous": result.get("is_genuinely_anomalous", False),
            }
            fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
            fe_out["endpoint_id"] = "server_host"
            await _emit_soc_alert_if_correlated(fe_out, ts)
        except Exception as _fe_exc:
            logger.debug(f"fusion_engine.ingest_event (system) skipped: {_fe_exc}")
    else:
        # Always emit all results so the score gauge stays live on the dashboard
        await sio.emit("system_anomaly", _strip_mongo(event))

    if fusion and fusion.should_respond:
        shap_fusion = _explain_fusion(fusion)
        fusion_event = {
            **fusion.to_dict(),
            "endpoint_id": "server_host",
            "source": "system_monitor",
            "ts": ts,
            "shap": shap_fusion,
        }
        if not fusion_saved:
            _save("alerts", fusion_event)
        # Persist to fused_alerts + critical_alerts (same as network pipeline)
        _fa_sys = {**fusion_event, "ts_dt": _now_dt()}
        _save("fused_alerts", _fa_sys)
        if fusion.severity in ("HIGH", "CRITICAL"):
            _save("critical_alerts", _fa_sys)
        _sys_fusion_payload = _strip_mongo(fusion_event)
        await sio.emit("fusion_alert", _sys_fusion_payload)
        if _graph_engine:
            try:
                g_nodes, g_edges = _graph_engine.process_fusion_alert(_sys_fusion_payload)
                await _emit_graph_update(g_nodes, g_edges)
            except Exception as _ge:
                logger.debug(f"[GRAPH] fusion_alert (system) hook error: {_ge}")


async def _handle_sysmon_result(result: dict):
    """Called by SysmonBehaviorAgent on each behavioral alert."""
    global _latest_sysmon_score, _latest_scores, _last_sysmon_emit_time
    ts = _now()
    score = float(result.get("anomaly_score", 0.0))
    severity = result.get("severity", "LOW")
    logger.debug(f"[SYSMON] result received: score={score:.4f} severity={severity} proc={result.get('process_name','?')} pid={result.get('pid','?')}")
    is_anomaly = score >= 0.35

    _latest_sysmon_score = score
    combined_system = max(_latest_system_score, _latest_sysmon_score)
    async with _scores_lock:
        _latest_scores["system"] = {"score": combined_system, "ts": time.monotonic()}
    _scores = _get_current_scores()
    # endpoint_id="server_host" so sysmon fusion events route to the server entry,
    # not a remote endpoint, and never appear in the EndpointView alert table.
    fusion = _fusion_agent.fuse(
        network_score=_scores["network"],
        user_score=_scores["user"],
        system_score=combined_system,
        malware_score=_scores["malware"],
        endpoint_id="server_host",
    ) if (_fusion_agent and is_anomaly) else None
    fusion_saved = False
    event = {
        **result,
        "ts": ts,
        "ts_dt": _now_dt(),   # required for TTL index on sysmon_alerts
        "endpoint_id": "server_host",
        "source": "sysmon_behavior",
        "fusion": fusion.to_dict() if fusion else None,
    }

    if is_anomaly:
        logger.warning(
            f"SYSMON ANOMALY: proc={result.get('process_name','?')} "
            f"label={result.get('label','?')} score={score:.4f} severity={severity}"
        )
        # Run Sysmon SHAP indicator analysis — pure heuristic, always fast (<1 ms)
        shap_explanation = await _maybe_explain_sysmon(result)
        if shap_explanation:
            event["shap_reasons"]    = shap_explanation.get("reason", [])
            event["shap_mitre"]      = shap_explanation.get("mitre_hints", [])
            event["shap_indicators"] = shap_explanation.get("indicators", [])
            event["shap_explanation"] = shap_explanation  # full doc for ResponseModal
        _save("alerts", event)
        _save("sysmon_alerts", event)
        fusion_saved = True
        try:
            fe_event = {
                "source": "system",
                "timestamp": ts,
                "host": "server_host",
                "endpoint_id": "server_host",
                "severity": severity,
                "confidence": score,
                "prediction": result.get("label", "sysmon_anomaly"),
            }
            fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
            fe_out["endpoint_id"] = "server_host"
            await _emit_soc_alert_if_correlated(fe_out, ts)
        except Exception as _fe_exc:
            logger.debug(f"fusion_engine.ingest_event (sysmon) skipped: {_fe_exc}")

    # Rate-limit sysmon_alert emissions — high-frequency EventID 3 (network connection)
    # events from a port-scan can produce hundreds of callbacks per minute.
    _now_t = time.monotonic()
    _sysmon_emit_allowed = (_now_t - _last_sysmon_emit_time) >= _SYSMON_EMIT_COOLDOWN
    if _sysmon_emit_allowed:
        _last_sysmon_emit_time = _now_t
        await sio.emit("sysmon_behavior_alert", _strip_mongo(event))
    else:
        logger.debug(
            "[SYSMON] Suppressed duplicate emit (cooldown %.1fs) proc=%s score=%.3f",
            _SYSMON_EMIT_COOLDOWN, result.get("process_name", "?"), score,
        )
    if fusion and fusion.should_respond:
        shap_fusion = _explain_fusion(fusion)
        fusion_event = {
            **fusion.to_dict(),
            "endpoint_id": "server_host",
            "source": "sysmon_behavior",
            "ts": ts,
            "shap": shap_fusion,
        }
        if not fusion_saved:
            _save("alerts", fusion_event)
        # Persist to fused_alerts + critical_alerts (same as network pipeline)
        _fa_sysmon = {**fusion_event, "ts_dt": _now_dt()}
        _save("fused_alerts", _fa_sysmon)
        if fusion.severity in ("HIGH", "CRITICAL"):
            _save("critical_alerts", _fa_sysmon)
        _sysmon_fusion_payload = _strip_mongo(fusion_event)
        await sio.emit("fusion_alert", _sysmon_fusion_payload)
        if _graph_engine:
            try:
                g_nodes, g_edges = _graph_engine.process_fusion_alert(_sysmon_fusion_payload)
                await _emit_graph_update(g_nodes, g_edges)
            except Exception as _ge:
                logger.debug(f"[GRAPH] fusion_alert (sysmon) hook error: {_ge}")
            asyncio.create_task(asyncio.to_thread(
                _graph_engine.ingest_to_incident, "fusion", _sysmon_fusion_payload
            ))

    # Sysmon behavioral graph node — always record even when no fusion alert fires
    if is_anomaly and _graph_engine:
        try:
            _gs_nodes, _gs_edges = _graph_engine.process_sysmon_alert({
                **result,
                "endpoint_id": "server_host",
                "severity": severity,
            })
            await _emit_graph_update(_gs_nodes, _gs_edges)
        except Exception as _ge:
            logger.debug(f"[GRAPH] sysmon_alert hook error: {_ge}")
        asyncio.create_task(asyncio.to_thread(
            _graph_engine.ingest_to_incident, "sysmon", {
                **result, "endpoint_id": "server_host", "severity": severity,
            }
        ))


async def _handle_sysmon_telemetry(entry: dict):
    """Called by SysmonBehaviorAgent for every parsed Sysmon event (raw log feed).
    When this callback fires from the SysmonFileReader (Winlogbeat source), it sets
    _sysmon_winlogbeat_active=True so the PS forwarder loop stops to prevent
    double-processing of the same events.

    Also appends the raw event dict to the system monitor's Sysmon ring buffer so
    the behavioral detector can score recent events alongside psutil data on each
    SystemMonitorAgent tick.
    """
    global _sysmon_winlogbeat_active
    if not _sysmon_winlogbeat_active:
        _sysmon_winlogbeat_active = True
        logger.info(
            "[SYSMON] Winlogbeat file source active — PS forwarder will be disabled "
            "to prevent duplicate event processing"
        )
    logger.debug(f"[SYSMON] telemetry: event_id={entry.get('event_id','?')} proc={entry.get('process_name','?')} pid={entry.get('pid','?')}")
    # Feed the raw event into the SystemMonitorAgent ring buffer so the behavioral
    # detector (detector.pkl) can score this event in the next psutil tick.
    _system_sysmon_ring.append(entry)
    await sio.emit("sysmon_log", _strip_mongo(entry))


def _maybe_explain(features: Optional[dict], attack_type: Optional[str]) -> Optional[dict]:
    if _shap_agent and features:
        try:
            return _shap_agent.explain(features, attack_type)
        except Exception as e:
            logger.debug(f"SHAP explain skipped: {e}")
    return None


def _maybe_explain_malware(features_scaled) -> Optional[dict]:
    if _shap_agent and features_scaled is not None:
        try:
            return _shap_agent.explain(features_scaled, model="malware")
        except Exception as e:
            logger.debug(f"Malware SHAP explain skipped: {e}")
    return None


def _generate_system_feature_reasons(result: dict) -> list:
    """Generate human-readable metric descriptions for every system event.

    Purely deterministic — no ML required.  Used to populate shap_reasons on
    normal/MEDIUM events where _maybe_explain_system never fires, ensuring the
    System Telemetry Logs column never shows "—".
    """
    snapshot = result.get("features_snapshot", [])
    names = result.get("feature_names", [])
    if not snapshot or not names or len(snapshot) != len(names):
        return []

    LABELS = {
        "cpu_percent":           ("CPU",        [(85, "critical"), (70, "high"), (50, "elevated"), (0, "normal")]),
        "mem_percent":           ("Memory",     [(95, "critical"), (85, "high"), (75, "elevated"), (0, "normal")]),
        "disk_read_bytes_norm":  ("Disk Read",  [(50, "high"), (10, "elevated"), (0, "normal")]),
        "disk_write_bytes_norm": ("Disk Write", [(50, "high"), (10, "elevated"), (0, "normal")]),
        "net_bytes_sent_norm":   ("Net Send",   [(100, "high"), (20, "elevated"), (0, "normal")]),
        "net_bytes_recv_norm":   ("Net Recv",   [(100, "high"), (20, "elevated"), (0, "normal")]),
        "num_processes":         ("Processes",  [(300, "high"), (200, "elevated"), (0, "normal")]),
        "swap_percent":          ("Swap",       [(80, "high"), (50, "elevated"), (0, "normal")]),
    }

    feat_dict = dict(zip(names, snapshot))
    reasons: list = []

    for feat, (label, thresholds) in LABELS.items():
        val = feat_dict.get(feat)
        if val is None:
            continue
        level = "normal"
        for threshold, lvl in thresholds:
            if val >= threshold:
                level = lvl
                break
        unit = "%" if "percent" in feat else " MB"
        reasons.append(f"{label}: {val:.1f}{unit} ({level})")

    # Prepend behavioral detector reason when it fired
    if result.get("behavioral_is_anomaly") and result.get("behavioral_attack_type"):
        btype = result["behavioral_attack_type"]
        bconf = result.get("behavioral_confidence", 0.0)
        if btype and btype != "Background":
            reasons.insert(0, f"Behavioral: {btype} ({bconf:.0%} confidence)")

    return reasons[:6]


async def _maybe_explain_system(result: dict) -> list:
    """
    Run reconstruction-error SHAP attribution for a system anomaly.

    Reads the last complete feature window from _system_agent, calls
    explain_system() in a thread (to avoid blocking the event loop), and
    persists the explanation to MongoDB.

    Returns:
        List of human-readable reason strings (may be empty).
    """
    if _shap_agent is None or _system_agent is None:
        return []
    try:
        window = _system_agent.get_last_window()
        if window is None or len(window) < 2:
            return []

        # Capture refs to avoid race conditions if agent is replaced
        _model = _system_agent._model
        _scaler = _system_agent._scaler
        _feat_names = _system_agent.feature_names

        if _model is None:
            return []

        explanation = await asyncio.to_thread(
            _shap_agent.explain_system,
            window,
            _model,
            _scaler,
            _feat_names,
        )

        if explanation and MONGO_OK:
            await asyncio.to_thread(
                _db["shap_explanations"].insert_one,
                {
                    "source": "system",
                    "method": "reconstruction_error",
                    "timestamp": result.get("ts"),
                    "severity": result.get("severity"),
                    "anomaly_score": result.get("anomaly_score"),
                    "explanation": explanation,
                    "alert_ts": result.get("ts"),
                },
            )

        return explanation.get("reason", [])
    except Exception as exc:
        logger.debug(f"System SHAP explanation failed: {exc}")
        return []


async def _maybe_explain_sysmon(result: dict) -> dict:
    """
    Run heuristic indicator analysis for a Sysmon behavioral alert via SHAPAgent.

    Calls SHAPAgent.explain_sysmon() in a thread (non-blocking), persists the
    explanation to the shap_explanations MongoDB collection, and returns the
    full explanation dict so the caller can attach reason + mitre_hints to the
    emitted socket event.

    Returns an empty dict on any failure so callers can safely use .get()
    without a None guard.
    """
    if _shap_agent is None:
        return {}
    try:
        explanation = await asyncio.to_thread(
            _shap_agent.explain_sysmon,
            result,
            float(result.get("anomaly_score", 0.0)),
        )
        if explanation and MONGO_OK:
            await asyncio.to_thread(
                _db["shap_explanations"].insert_one,
                {
                    "source": "sysmon",
                    "method": "sysmon_indicator_analysis",
                    "timestamp": result.get("ts"),
                    "severity": result.get("severity"),
                    "process_name": result.get("process_name"),
                    "anomaly_score": result.get("anomaly_score"),
                    "explanation": explanation,
                    "alert_ts": result.get("ts"),
                },
            )
        return explanation or {}
    except Exception as exc:
        logger.debug(f"Sysmon SHAP explanation failed: {exc}")
        return {}


async def _maybe_explain_user(row: dict, ts: str) -> list:
    """
    Run sensitivity-based SHAP-style attribution for a user behavior anomaly.

    Uses SHAPAgent.explain_user() which performs leave-one-out sensitivity
    analysis on the OC-SVM / XGBoost user model.  The call is dispatched to
    a thread pool to avoid blocking the event loop.

    The explanation is also persisted to the shap_explanations MongoDB
    collection so it can be retrieved by GET /shap.

    Args:
        row: A single user row dict as produced by xdr_runtime (contains all
             feature columns plus prediction_label, anomaly_score, etc.).
        ts:  ISO timestamp string from _now() for the current inference cycle.

    Returns:
        List of human-readable reason strings (may be empty on failure).
    """
    if _shap_agent is None:
        return []
    try:
        import json as _json
        from pathlib import Path as _Path

        # ── Resolve feature columns ──────────────────────────────────────
        feat_col_path = _Path(settings.user_model_dir) / "feature_columns.json"
        try:
            with open(feat_col_path, "r") as _f:
                feature_columns: list = _json.load(_f)
        except Exception as _fc_err:
            logger.debug("_maybe_explain_user: could not load feature_columns.json — %s", _fc_err)
            feature_columns = []

        # ── Build feature_values dict from the row ───────────────────────
        # row already contains all the aggregated feature values for this user.
        feature_values: dict = {
            col: float(row.get(col, 0.0)) for col in feature_columns
        }

        decision_score = float(row.get("anomaly_score", 0.0))

        # ── Paths for the user model artifacts ───────────────────────────
        user_model_path  = str(_Path(settings.user_model_dir) / "user_model.pkl")
        user_scaler_path = str(_Path(settings.user_model_dir) / "user_scaler.pkl")

        reasons: list = await asyncio.to_thread(
            _shap_agent.explain_user,
            feature_values,
            decision_score,
            feature_columns,
            5,                  # top_n
            user_model_path,
            user_scaler_path,
        )

        # ── Persist to shap_explanations ─────────────────────────────────
        if reasons and MONGO_OK:
            await asyncio.to_thread(
                _db["shap_explanations"].insert_one,
                {
                    "source": "user",
                    "method": "sensitivity_leave_one_out",
                    "timestamp": ts,
                    "user": row.get("user"),
                    "anomaly_score": decision_score,
                    "prediction_label": row.get("prediction_label"),
                    "reason": reasons,
                    "feature_values": feature_values,
                    "alert_ts": ts,
                },
            )

        return reasons
    except Exception as exc:
        logger.debug("User SHAP explanation failed: %s", exc)
        return []


def _get_current_scores() -> dict:
    """Return per-model scores, zeroing any entry older than 300 seconds."""
    now = time.monotonic()
    return {k: (v["score"] if now - v["ts"] < 300 else 0.0) for k, v in _latest_scores.items()}


def _explain_fusion(fusion) -> Optional[dict]:
    if _shap_agent and fusion is not None:
        try:
            return _shap_agent.explain_fusion(fusion.to_dict())
        except Exception as e:
            logger.debug(f"Fusion SHAP explain skipped: {e}")
    return None


async def _emit_soc_alert_if_correlated(fe_out: dict, ts: str) -> None:
    """
    Emit a 'soc_alert' Socket.IO event and persist to MongoDB when the
    correlation engine detects a multi-domain attack chain.

    Also always persists individual events to 'raw_events'. HIGH/CRITICAL
    final decisions go to 'high_severity_alerts'.
    """
    correlation = fe_out.get("correlation", {})
    final = fe_out.get("final_decision", {})

    # Always store raw correlated snapshot
    _save("raw_events", {
        "alerts": fe_out.get("alerts", []),
        "correlation": correlation,
        "final_decision": final,
        "ts": ts,
    })

    if not correlation.get("attack_detected", False):
        return

    severity = final.get("severity", "LOW")
    threat_score = final.get("threat_score", 0.0)
    logger.info(f"[FUSION] Threat detected: severity={severity} score={threat_score:.3f}")

    # Align emitted severity with score thresholds (HIGH ≥ 0.70, CRITICAL ≥ 0.85).
    # The CorrelationEngine may assign HIGH/CRITICAL via pattern-matching alone;
    # downgrade or suppress when the numeric score doesn't support it.
    if severity == "CRITICAL" and threat_score < 0.85:
        logger.info(
            "[FUSION] Alert suppressed — score=%.3f below CRITICAL threshold 0.85 "
            "(was %s, attack=%s)",
            threat_score, severity, final.get("primary_threat", ""),
        )
        return
    elif severity == "HIGH" and threat_score < 0.70:
        logger.info(
            "[FUSION] Alert suppressed — score=%.3f below HIGH threshold 0.70 "
            "(attack=%s)",
            threat_score, final.get("primary_threat", ""),
        )
        return

    doc = {
        "alerts":           fe_out.get("alerts", []),
        "correlation":      correlation,
        "final_decision":   final,
        "timestamp":        ts,
        "host":             ",".join(correlation.get("involved_hosts", [])),
        "final_severity":   severity,
        "confidence":       final.get("threat_score", 0.0),
        "mitre_id":         correlation.get("mitre_id", ""),
        "attack_type":      correlation.get("attack_type", ""),
        "involved_sources": correlation.get("involved_sources", []),
    }

    # Deduplicate: same attack_type + same sources within 30 s → skip
    import time as _time_mod
    _dedup_key = (
        correlation.get("attack_type", "")
        + ":"
        + ":".join(sorted(correlation.get("involved_sources", [])))
    )
    _now_mono = _time_mod.monotonic()
    if _now_mono - _soc_alert_dedup.get(_dedup_key, 0.0) < _SOC_DEDUP_WINDOW:
        logger.debug(
            "[FUSION] soc_alert deduplicated — key=%s last_emit=%.1fs ago",
            _dedup_key, _now_mono - _soc_alert_dedup.get(_dedup_key, 0.0),
        )
        return
    _soc_alert_dedup[_dedup_key] = _now_mono

    _save("correlated_alerts", doc)

    if severity in ("HIGH", "CRITICAL"):
        _save("high_severity_alerts", doc)

    await sio.emit("soc_alert", _strip_mongo(doc))
    logger.info(
        f"soc_alert emitted: {correlation.get('attack_type','')} "
        f"[{correlation.get('mitre_id','')}] severity={severity} "
        f"sources={correlation.get('involved_sources',[])} "
        f"chain={correlation.get('attack_chain', False)}"
    )

    # Trigger SOAR response actions based on response_suggestions
    response_suggestions = correlation.get("response_suggestions", [])
    hosts = correlation.get("involved_hosts", [])
    if final.get("should_respond") and response_suggestions and hosts:
        for host in hosts:
            soar_doc = {
                "host": host,
                "actions": response_suggestions,
                "status": "pending",
                "trigger": "correlation_engine",
                "attack_type": correlation.get("attack_type", ""),
                "mitre_id": correlation.get("mitre_id", ""),
                "confidence": final.get("threat_score", 0.0),
                "ts": ts,
            }
            _save("commands", soar_doc)
            logger.warning(
                f"SOAR auto-response: host={host} actions={response_suggestions} "
                f"trigger=correlation_engine"
            )

    # ---------------------------------------------------------------------------
    # EDR Orchestration — auto-generate response plan for HIGH/CRITICAL events
    # ---------------------------------------------------------------------------
    if severity in ("HIGH", "CRITICAL"):
        try:
            _involved_hosts = correlation.get("involved_hosts", [])
            # Prefer explicit endpoint_id passed via fe_out over hostname
            _ep_id = (
                fe_out.get("endpoint_id")
                or (_involved_hosts[0] if _involved_hosts else "server_host")
            )
            # Cooldown: skip if a plan was generated for this endpoint < 120 s ago
            import time as _time
            _now_mono = _time.monotonic()
            if _now_mono - _last_rp_ts.get(_ep_id, 0.0) < _RP_COOLDOWN:
                return
            _last_rp_ts[_ep_id] = _now_mono

            # Build SHAP from a fresh FusionResult so explain_fusion receives
            # the expected "components" key (final_decision dict lacks it).
            _corr_shap: list = []
            if _shap_agent and _fusion_agent:
                try:
                    _scores = _get_current_scores()
                    _fusion_for_shap = _fusion_agent.fuse(
                        network_score=_scores.get("network", 0.0),
                        user_score=_scores.get("user", 0.0),
                        system_score=_scores.get("system", 0.0),
                        malware_score=_scores.get("malware", 0.0),
                    )
                    _corr_shap = _shap_agent.explain_fusion(
                        _fusion_for_shap.to_dict()
                    ).get("top_features", [])
                except Exception as _shap_exc:
                    logger.debug(
                        "[RESPONSE] Fusion SHAP generation failed (will use score fallback): %s",
                        _shap_exc,
                    )

            # Fallback: build score-contribution SHAP items when explain_fusion is
            # unavailable (SHAPAgent not loaded, exception, or all-zero scores).
            # Covers Ransomware Behavior and other correlated events that have no
            # per-feature network/malware SHAP but do have meaningful model scores.
            if not _corr_shap:
                _scores_fb = _get_current_scores()
                _weights_fb = {"network": 0.35, "user": 0.30, "system": 0.15, "malware": 0.20}
                _label_fb = {
                    "network": "Network detection score",
                    "user":    "User behavior score",
                    "system":  "System anomaly score",
                    "malware": "Malware detection score",
                }
                _corr_shap = sorted(
                    [
                        {
                            "feature":       _label_fb[_k],
                            "shap_value":    round(_scores_fb.get(_k, 0.0) * _weights_fb[_k], 4),
                            "feature_value": round(_scores_fb.get(_k, 0.0), 4),
                            "direction":     "increases_risk",
                        }
                        for _k in ("malware", "system", "network", "user")
                        if _scores_fb.get(_k, 0.0) > 0.0
                    ],
                    key=lambda _x: _x["shap_value"],
                    reverse=True,
                )
            # Extract attacker src_ip from any alert in this fe_out batch
            _src_ip = ""
            for _alert in fe_out.get("alerts", []):
                _candidate = str(_alert.get("src_ip", _alert.get("host", ""))).strip()
                if _candidate and re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", _candidate):
                    _src_ip = _candidate
                    break
            _plan = generate_response_plan({
                "endpoint_id":          _ep_id,
                "severity":             severity,
                "attack_type":          correlation.get("attack_type", "Unknown"),
                "contributing_signals": fe_out.get("alerts", []),
                "shap_explanation":     _corr_shap or fe_out.get("shap_explanation", []),
                "threat_score":         final.get("threat_score", 0.0),
                "sources":              correlation.get("involved_sources", []),
                "src_ip":               _src_ip,
            })
            # Stash the raw network flow feature vector (and attacker IP) on the
            # plan so analyst FP/TP feedback on this alert can be resolved
            # server-side into a retrain-ready sample. See POST /feedback and
            # retrain_from_feedback.py. First network alert in the batch wins.
            _src_features: dict = {}
            for _alert in fe_out.get("alerts", []):
                _f = _alert.get("features")
                if isinstance(_f, dict) and _f:
                    _src_features = _f
                    break
            if _src_features:
                _plan["source_features"] = _src_features
            _plan["src_ip"] = _src_ip
            asyncio.create_task(_save_response_plan(_plan))
            if _plan.get("auto_execute") and _auto_response_enabled:
                asyncio.create_task(_auto_execute_server_plan(_plan))
            await sio.emit("response_required", _strip_mongo(_plan))
            logger.info(
                f"[RESPONSE] Auto-plan generated: plan_id={_plan['plan_id']} "
                f"endpoint={_ep_id} severity={severity} "
                f"attack_type={correlation.get('attack_type','Unknown')}"
            )
        except Exception as _rp_exc:
            logger.debug(f"[RESPONSE] Auto-plan generation skipped: {_rp_exc}")


async def _maybe_generate_network_response_plan(
    endpoint_id: str,
    severity: str,
    attack_type: str,
    fusion,  # FusionResult object
    ts: str,
    shap_fusion=None,
    features: dict | None = None,
    src_ip: str = "",
) -> None:
    """Generate and emit a response plan directly for HIGH/CRITICAL network attacks
    without requiring multi-source correlation."""
    if severity not in ("HIGH", "CRITICAL"):
        return
    import time as _time
    _now_mono = _time.monotonic()
    if _now_mono - _last_rp_ts.get(endpoint_id, 0.0) < _RP_COOLDOWN:
        return
    _last_rp_ts[endpoint_id] = _now_mono
    try:
        # Resolve the attacker IP: explicit arg → fusion.endpoint_id (if IP-like).
        _resolved_src_ip = str(src_ip or "").strip()
        if not re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", _resolved_src_ip):
            _fe_id = str(getattr(fusion, "endpoint_id", "") or "")
            _resolved_src_ip = _fe_id if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", _fe_id) else ""
        _plan = generate_response_plan({
            "endpoint_id":          endpoint_id,
            "severity":             severity,
            "attack_type":          attack_type or "Network Attack",
            "contributing_signals": getattr(fusion, "contributing_models", ["network"]),
            "shap_explanation":     (
                shap_fusion.get("top_features", shap_fusion.get("reason", []))
                if isinstance(shap_fusion, dict) else []
            ) if shap_fusion else [],
            "threat_score":         getattr(fusion, "threat_score", 0.0),
            "sources":              ["network"],
            "src_ip":               _resolved_src_ip,
        })
        # Stash the raw flow feature vector + attacker IP on the plan so the PDF
        # incident report can surface network evidence + IOCs (and feedback can
        # resolve retrain-ready features). Mirrors the correlated-alert path.
        if isinstance(features, dict) and features:
            _plan["source_features"] = features
        _plan["src_ip"] = _resolved_src_ip
        asyncio.create_task(_save_response_plan(_plan))
        if _plan.get("auto_execute") and _auto_response_enabled:
            asyncio.create_task(_auto_execute_server_plan(_plan))
        await sio.emit("response_required", _strip_mongo(_plan))
        logger.info(
            f"[RESPONSE] Direct plan for network attack: plan_id={_plan['plan_id']} "
            f"endpoint={endpoint_id} severity={severity} attack_type={attack_type}"
        )
    except Exception as _exc:
        logger.debug(f"[RESPONSE] Direct plan generation failed: {_exc}")


async def _maybe_generate_user_response_plan(
    endpoint_id: str,
    severity: str,
    user: str,
    fusion,  # FusionResult object
    shap_reasons: list,
    ts: str,
) -> None:
    """Generate and emit a response plan directly for HIGH/CRITICAL user behavior
    anomalies, carrying the user SHAP sensitivity reasons into plan.shap_explanation
    so the ResponseModal can render them.

    Mirrors _maybe_generate_network_response_plan — uses the same cooldown guard
    so a burst of user anomaly rows doesn't produce duplicate plans.
    """
    if severity not in ("HIGH", "CRITICAL"):
        return
    import time as _time
    _now_mono = _time.monotonic()
    # Use a separate cooldown namespace for user plans to avoid collision with
    # network plans on the same endpoint_id.
    _user_ep_key = f"user:{endpoint_id}"
    if _now_mono - _last_rp_ts.get(_user_ep_key, 0.0) < _RP_COOLDOWN:
        return
    _last_rp_ts[_user_ep_key] = _now_mono
    try:
        # Convert plain-string reasons to the structured dict format that
        # ResponseModal's useMemo expects.  The modal already handles string arrays
        # (synthetic shap_value fallback), but structured dicts give more useful
        # bar-chart rendering.  We normalise here so both code paths are consistent.
        shap_dicts: list = []
        for i, reason in enumerate(shap_reasons or []):
            if isinstance(reason, dict):
                # Already structured — pass through unchanged.
                shap_dicts.append(reason)
            else:
                # Plain string → synthetic importance decaying from 1.0.
                shap_dicts.append({
                    "feature": str(reason),
                    "shap_value": round(max(0.1, 1.0 - i * 0.15), 3),
                    "feature_value": 0,
                    "importance": round(max(0.05, 1.0 - i * 0.15), 3),
                    "direction": "increases_risk",
                })

        _plan = generate_response_plan({
            "endpoint_id":          endpoint_id,
            "severity":             severity,
            "attack_type":          "Insider Threat",
            "contributing_signals": getattr(fusion, "contributing_models", ["user"]),
            "shap_explanation":     shap_dicts,
            "threat_score":         getattr(fusion, "threat_score", 0.0),
            "sources":              ["user"],
            "src_ip":               "",
            "user":                 user,
        })
        asyncio.create_task(_save_response_plan(_plan))
        if _plan.get("auto_execute") and _auto_response_enabled:
            asyncio.create_task(_auto_execute_server_plan(_plan))
        await sio.emit("response_required", _strip_mongo(_plan))
        logger.info(
            "[RESPONSE] User behavior plan: plan_id=%s endpoint=%s severity=%s user=%s",
            _plan["plan_id"], endpoint_id, severity, user,
        )
    except Exception as _exc:
        logger.debug("[RESPONSE] User response plan generation failed: %s", _exc)


async def _maybe_emit_malware_fusion_alert(
    fusion,            # FusionResult from FusionEngineAgent.fuse()
    result: dict,      # raw MalwareAnalysisAgent output dict
    host: str,
    ts: str,
    shap_explanation: list,
) -> None:
    """
    Emit a ``network_anomaly`` event (so malware hits appear in the Alert Stream
    / AlertsView flows list) and ensure a properly-labelled ``fusion_alert`` event
    is also emitted for HIGH/CRITICAL single-source malware detections.

    Without this, a malware-only detection with no concurrent network/user/system
    signals never reaches the Alert Stream because:
      - ``_emit_soc_alert_if_correlated`` returns early when
        ``correlation.attack_detected == False`` (requires multi-source).
      - The frontend ``fusion_alert`` handler only updates the gauge; it does NOT
        push entries into the ``flows`` array that feeds the Alert Stream table.

    Cooldown: the same file path is suppressed for 60 s to prevent the file-
    watcher from flooding the UI when mtime hasn't changed yet.
    """
    if fusion is None:
        return
    if fusion.severity not in ("HIGH", "CRITICAL"):
        return
    if fusion.threat_score < _malware_threshold:
        return
    if result.get("label") != "malicious":
        return

    import time as _time
    _now_mono = _time.monotonic()
    file_path = result.get("file_path", result.get("prediction", "unknown"))
    _dedup_key = f"malware:{file_path}"
    if _now_mono - _malware_direct_emit_ts.get(_dedup_key, 0.0) < _MALWARE_DIRECT_COOLDOWN:
        logger.debug(
            "[MALWARE] Alert Stream emit suppressed (cooldown %.0f s) — file=%s",
            _MALWARE_DIRECT_COOLDOWN, file_path,
        )
        return
    _malware_direct_emit_ts[_dedup_key] = _now_mono

    score_pct = round(fusion.threat_score * 100)
    attack_type = "Malware Activity"

    # ── 1. network_anomaly event ─────────────────────────────────────────────
    # This is the event that feeds setFlows() in NetworkMonitor.tsx and therefore
    # populates the Alert Stream table in AlertsView.
    network_anomaly_payload = {
        "ts":           ts,
        "hostname":     host,
        "endpoint_id":  host,
        "attack_type":  attack_type,
        "confidence":   score_pct,
        "severity":     fusion.severity,
        "prediction":   "ATTACK",
        "source":       "malware",
        "file_path":    file_path,
        "label":        result.get("label", "malicious"),
        "malware_score": result.get("score", 0.0),
        "trust_reason": result.get("trust_reason", ""),
        "shap_explanation": shap_explanation or [],
        "description":  (
            f"Malicious file detected on {host} — "
            f"score {result.get('score', 0.0):.0%}, "
            f"fusion score {fusion.threat_score:.0%}"
        ),
    }
    await sio.emit("network_anomaly", network_anomaly_payload)
    logger.warning(
        "[MALWARE] Alert Stream entry emitted — file=%s severity=%s fusion_score=%.3f",
        file_path, fusion.severity, fusion.threat_score,
    )

    # ── 2. fusion_alert event (with attack_type populated) ──────────────────
    # The existing path emits fusion_alert only when fusion.should_respond is
    # True; that works for 87%+ scores, but the attack_type field is "Unknown"
    # because FusionResult.attack_type defaults to "Unknown" for single-source
    # malware events.  Emit here with the correct label so the gauge and siren
    # carry the right attack_type.
    shap_fusion = _explain_fusion(fusion)
    fused_payload = {
        **fusion.to_dict(),
        "attack_type":      attack_type,
        "source":           "malware",
        "file_path":        file_path,
        "ts":               ts,
        "shap":             shap_fusion,
        "shap_explanation": shap_explanation or [],
        "ts_dt":            _now_dt(),
    }
    # Emit without ts_dt — datetime objects are not JSON-serialisable by
    # python-socketio's default encoder, which would raise TypeError and
    # silently swallow this emit.  ts_dt is kept in fused_payload for MongoDB.
    _fused_emit = {k: v for k, v in fused_payload.items() if k not in ("_id", "ts_dt")}
    await sio.emit("fusion_alert", _fused_emit)
    _save("fused_alerts", fused_payload)
    if fusion.severity in ("HIGH", "CRITICAL"):
        _save("critical_alerts", fused_payload)
    logger.info(
        "[MALWARE] fusion_alert emitted — attack_type=%s severity=%s score=%.3f",
        attack_type, fusion.severity, fusion.threat_score,
    )

    # ── 3. response plan ─────────────────────────────────────────────────────
    # Reuse the network response plan generator — it has the same cooldown guard
    # (_last_rp_ts keyed by endpoint_id) and saves + emits response_required.
    _mal_ep_key = f"malware:{host}"
    _now_rp = _time.monotonic()
    if _now_rp - _last_rp_ts.get(_mal_ep_key, 0.0) >= _RP_COOLDOWN:
        _last_rp_ts[_mal_ep_key] = _now_rp
        try:
            shap_list = shap_fusion.get("top_features", []) if isinstance(shap_fusion, dict) else []
            _plan = generate_response_plan({
                "endpoint_id":          host,
                "severity":             fusion.severity,
                "attack_type":          attack_type,
                "contributing_signals": ["malware"],
                "shap_explanation":     shap_list or shap_explanation or [],
                "threat_score":         fusion.threat_score,
                "sources":              ["malware"],
                "src_ip":               "",
                "file_path":            file_path,
            })
            asyncio.create_task(_save_response_plan(_plan))
            if _plan.get("auto_execute") and _auto_response_enabled:
                asyncio.create_task(_auto_execute_server_plan(_plan))
            await sio.emit("response_required", _strip_mongo(_plan))
            logger.info(
                "[MALWARE] Response plan generated: plan_id=%s endpoint=%s severity=%s",
                _plan["plan_id"], host, fusion.severity,
            )
        except Exception as _exc:
            logger.debug("[MALWARE] Response plan generation failed: %s", _exc)


def _strip_mongo(doc: dict) -> dict:
    """Remove non-serialisable MongoDB fields before emitting via Socket.IO."""
    return {k: v for k, v in doc.items() if k != "_id"}


# ---------------------------------------------------------------------------
# SOAR Forensic Audit Trail helper
# ---------------------------------------------------------------------------

async def _write_soar_audit_event(
    action: str,
    target: str,
    endpoint_id: str,
    success: bool,
    message: str,
    duration_ms: float = 0.0,
    actor: str = "SOAR_AUTO",
) -> None:
    """
    Write a SOAR action audit record to audit_logs and emit audit_event Socket.IO.
    Called via asyncio.create_task() — never raises; all errors are silently logged.
    """
    try:
        ts = _now()
        event_id = str(_uuid.uuid4())
        audit_doc = {
            "id":          event_id,
            "timestamp":   ts,
            "actor":       actor,
            "action":      action,
            "target":      target,
            "endpoint_id": endpoint_id,
            "success":     success,
            "message":     message,
            "duration_ms": round(duration_ms, 2),
            "source":      "soar_executor",
            "user":        actor,
        }
        # Persist to audit_logs (non-blocking DB write inside an already-async context)
        if MONGO_OK and _db is not None:
            try:
                _db["audit_logs"].insert_one({**audit_doc})
            except Exception as _db_exc:
                logger.debug("[SOAR_AUDIT] audit_logs write failed: %s", _db_exc)

        # Emit to frontend Audit Log panel
        socket_payload = {
            "id":        event_id,
            "timestamp": ts,
            "user":      actor,
            "action":    f"{action} → {'OK' if success else 'FAIL'}",
            "ip":        endpoint_id,
            "status":    "success" if success else "failure",
            "detail":    message,
        }
        await sio.emit("audit_event", socket_payload)
    except Exception as exc:
        logger.debug("[SOAR_AUDIT] _write_soar_audit_event failed: %s", exc)


# ---------------------------------------------------------------------------
# /health helper queries
# ---------------------------------------------------------------------------

def _count_active_mitigations() -> int:
    """Count pending SOAR commands in endpoint_commands. Returns 0 on DB unavailable."""
    if not MONGO_OK or _db is None:
        return 0
    try:
        return _db["endpoint_commands"].count_documents({"status": "pending"})
    except Exception:
        return 0


def _count_online_endpoints() -> int:
    """Count endpoints seen this session with last_seen > now-15s."""
    if not MONGO_OK or _db is None:
        return 0
    try:
        cutoff = (datetime.utcnow() - timedelta(seconds=15)).isoformat()
        # An online endpoint (last_seen within 15s) is by definition in this session.
        return _db["endpoint_registry"].count_documents({
            "last_seen": {"$gt": cutoff},
            "endpoint_id": {"$ne": "server_host"},
        })
    except Exception:
        return 0


def _count_offline_endpoints() -> int:
    """Count endpoints seen this session but now offline (last_seen <= now-15s)."""
    if not MONGO_OK or _db is None:
        return 0
    try:
        cutoff = (datetime.utcnow() - timedelta(seconds=15)).isoformat()
        session_start = _backend_session_start.isoformat()
        # Only count endpoints that have connected during this session — stale
        # registry entries from previous sessions are excluded.
        return _db["endpoint_registry"].count_documents({
            "last_seen": {"$lte": cutoff, "$gte": session_start},
            "endpoint_id": {"$ne": "server_host"},
        })
    except Exception:
        return 0


async def _emit_graph_update(nodes: list, edges: list) -> None:
    """Emit graph_update Socket.IO event with changed nodes/edges."""
    if not nodes and not edges:
        return
    # Filter out empty dicts that can result from MongoDB-unavailable no-ops
    clean_nodes = [n for n in nodes if n]
    clean_edges = [e for e in edges if e]
    if not clean_nodes and not clean_edges:
        return

    def _fix(obj):
        if isinstance(obj, dict):
            return {k: _fix(v) for k, v in obj.items() if k != "_id"}
        if hasattr(obj, "isoformat"):
            return obj.isoformat()
        return obj

    payload = _fix({"nodes": clean_nodes, "edges": clean_edges})
    try:
        await sio.emit("graph_update", payload)
    except Exception as exc:
        logger.debug(f"[GRAPH] graph_update emit failed: {exc}")


# ---------------------------------------------------------------------------
# EDR Orchestration — response plan persistence helper
# ---------------------------------------------------------------------------

async def _save_response_plan(plan: dict) -> None:
    """
    Persist a response plan to MongoDB (response_plans collection).
    Ensures the plan document has a 'status' field set to 'open' on creation.
    Called via asyncio.create_task() so it never blocks the hot path.
    """
    try:
        plan_to_save = {**plan}
        plan_to_save.setdefault("status", "open")
        _save("response_plans", plan_to_save)
    except Exception as exc:
        logger.debug(f"[RESPONSE] _save_response_plan failed: {exc}")


async def _auto_execute_server_plan(plan: dict) -> None:
    """
    Execute auto-approved SOAR actions from a response plan.

    Behaviour by endpoint_id:
      - "server_host": execute locally via _server_soar_executor; write results
        back to endpoint_commands so the PDF and plan lifecycle reflect reality.
      - Any other endpoint_id: queue commands to endpoint_commands for the
        remote endpoint agent to pick up via GET /endpoint/commands/{id};
        do NOT execute locally (the server has no OS-level path to the remote host).

    In both cases every non-advisory action is written to endpoint_commands
    with plan_id set BEFORE execution, so the PDF query always finds them.
    Advisory actions are acknowledged to response_advisory_logs.
    """
    plan_id = plan.get("plan_id", "unknown")
    endpoint_id = plan.get("endpoint_id", "unknown")
    is_server = (endpoint_id == "server_host")
    actions = plan.get("recommended_actions", [])
    now_iso = _now()

    logger.info(
        "[AUTO-SOAR] Processing plan plan_id=%s endpoint_id=%s total_actions=%d is_server=%s",
        plan_id, endpoint_id, len(actions), is_server,
    )

    # ------------------------------------------------------------------ #
    # Step 1 — Persist every action to MongoDB BEFORE any execution.     #
    # This guarantees the PDF query (by plan_id) always finds records.   #
    # Advisory actions go to response_advisory_logs; executable ones to  #
    # endpoint_commands with status="pending".                           #
    # cmd_records: list of (ObjectId|None, action_str, target_str, is_advisory_bool)
    # ------------------------------------------------------------------ #
    cmd_records: list = []

    for action in actions:
        act = action.get("action", "") or ""
        target = action.get("target", "") or ""

        if act in _ADVISORY_ACTIONS:
            # Advisory: acknowledge server-side immediately
            if MONGO_OK and _db is not None:
                try:
                    await asyncio.to_thread(
                        lambda _a=act, _t=target: _db["response_advisory_logs"].insert_one({
                            "endpoint_id": endpoint_id,
                            "action":      _a,
                            "target":      _t,
                            "plan_id":     plan_id,
                            "issued_by":   "auto_response",
                            "created_at":  now_iso,
                            "status":      "acknowledged",
                        })
                    )
                except Exception as _adv_err:
                    logger.warning("[AUTO-SOAR] advisory log insert failed: %s", _adv_err)
            cmd_records.append((None, act, target, True))
            continue

        # Executable action — insert to endpoint_commands.
        # server_host commands are inserted as "sent" immediately so the
        # _server_soar_loop (which polls for "pending") cannot double-execute them.
        # Remote endpoint commands are inserted as "pending" so the endpoint agent
        # can fetch them via GET /endpoint/commands/{endpoint_id}.
        cmd_doc = {
            "endpoint_id": endpoint_id,
            "action":      act,
            "target":      target,
            "payload":     {},
            "issued_by":   "auto_response",
            "status":      "sent" if is_server else "pending",
            "result_log":  [],
            "created_at":  now_iso,
            "sent_at":     now_iso if is_server else None,
            "executed_at": None,
            "plan_id":     plan_id,
        }
        cmd_oid = None
        if MONGO_OK and _db is not None:
            try:
                _ins = await asyncio.to_thread(
                    lambda _d=cmd_doc: _db["endpoint_commands"].insert_one({**_d})
                )
                cmd_oid = _ins.inserted_id
            except Exception as _ins_err:
                logger.warning("[AUTO-SOAR] endpoint_commands insert failed: %s", _ins_err)
        cmd_records.append((cmd_oid, act, target, False))

    # Advance plan to "executing" now that commands are queued
    if MONGO_OK and _db is not None:
        try:
            await asyncio.to_thread(
                lambda: _db["response_plans"].update_one(
                    {"plan_id": plan_id},
                    {"$set": {"status": "executing", "executing_at": now_iso}},
                )
            )
        except Exception as _plan_upd_err:
            logger.warning("[AUTO-SOAR] plan status → executing failed: %s", _plan_upd_err)

    # ------------------------------------------------------------------ #
    # Step 2 — Execute (server_host) or leave pending (remote endpoint)  #
    # ------------------------------------------------------------------ #
    if is_server:
        for cmd_oid, act, target, is_adv in cmd_records:
            if is_adv or cmd_oid is None:
                continue

            try:
                success, message = await _server_soar_executor(act, target, {})
                final_status = "completed" if success else "failed"
                logger.info(
                    "[AUTO-SOAR] %s → %s target=%r: %s",
                    act, final_status, target, message,
                )
            except Exception as _exc:
                success, message = False, str(_exc)
                final_status = "failed"
                logger.warning("[AUTO-SOAR] %s raised: %s", act, _exc)

            _exec_ts = _now()
            if MONGO_OK and _db is not None:
                try:
                    await asyncio.to_thread(
                        lambda _oid=cmd_oid, _s=final_status, _m=message, _ts=_exec_ts: (
                            _db["endpoint_commands"].update_one(
                                {"_id": _oid},
                                {"$set": {
                                    "status":         _s,
                                    "result_message": _m,
                                    "executed_at":    _ts,
                                    "completed_at":   _ts,
                                }},
                            )
                        )
                    )
                except Exception as _cmd_upd_err:
                    logger.warning("[AUTO-SOAR] command status update failed: %s", _cmd_upd_err)

            # Notify frontend so endpoint cards reflect the result immediately
            await sio.emit("command_result", {
                "endpoint_id":    endpoint_id,
                "action":         act,
                "status":         final_status,
                "success":        success,
                "result_message": message,
                "target":         target,
                "timestamp":      _exec_ts,
            })
    else:
        _exec_count = sum(1 for _, _, _, _is_adv in cmd_records if not _is_adv)
        logger.info(
            "[AUTO-SOAR] %d command(s) queued to endpoint_commands for "
            "remote endpoint_id=%s — awaiting pickup by endpoint agent "
            "via GET /endpoint/commands/%s",
            _exec_count, endpoint_id, endpoint_id,
        )

    # --- Auto-generate incident report ---
    attack_type = plan.get("attack_type", "Unknown")
    severity    = plan.get("severity", "HIGH")

    report_meta: dict = {}
    if MONGO_OK and _db is not None:
        try:
            incident_id = f"auto_{plan_id[:8]}_{int(time.time())}"
            # Build minimal alert and plan dicts for the PDF generator
            _alert_doc = {
                "incident_id": incident_id,
                "endpoint_id": endpoint_id,
                "attack_type": attack_type,
                "severity":    severity,
                "threat_score": plan.get("threat_score", 0.0),
                "shap_explanation": plan.get("shap_explanation", []),
                "src_ip":      plan.get("src_ip", ""),
                "timestamp":   _now(),
            }
            _endpoint_info = {"hostname": endpoint_id, "ip_address": "N/A"}
            _execution_results = list(
                _db["endpoint_commands"]
                .find({"plan_id": plan_id}, {"_id": 0})
                .sort("created_at", DESCENDING)
                .limit(50)
            ) if _db is not None else []
            pdf_path = await asyncio.to_thread(
                generate_incident_report,
                incident_id,
                _alert_doc,
                plan,
                _execution_results,
                "Auto-Response System",
                _endpoint_info,
                "system",
            )
            if pdf_path:
                _db["incident_reports"].insert_one({
                    "incident_id":    incident_id,
                    "plan_id":        plan_id,
                    "endpoint_id":    endpoint_id,
                    "severity":       severity,
                    "attack_type":    attack_type,
                    "pdf_path":       str(pdf_path),
                    "generated_by":   "auto_response",
                    "generated_at":   _now(),
                    "ts_dt":          _now_dt(),
                })
                report_meta = {"incident_id": incident_id, "pdf_path": str(pdf_path)}
                logger.info("[AUTO-SOAR] Incident report generated: %s", incident_id)
        except Exception as _rpe:
            logger.warning("[AUTO-SOAR] Report generation failed: %s", _rpe)

    # --- Notify frontend ---
    await sio.emit("auto_response_completed", {
        "plan_id":       plan_id,
        "endpoint_id":   endpoint_id,
        "attack_type":   attack_type,
        "severity":      severity,
        "timestamp":     _now(),
        "actions_taken": [
            a.get("action") for a in plan.get("recommended_actions", [])
            if a.get("action") not in _ADVISORY_ACTIONS
        ],
        "report": report_meta,
    })
    # Also emit report_generated so the reports panel refreshes
    if report_meta:
        await sio.emit("report_generated", {
            "incident_id": report_meta["incident_id"],
            "auto":        True,
        })


# ---------------------------------------------------------------------------
# Per-endpoint fusion helpers — Gap 2+5
# ---------------------------------------------------------------------------

def _get_or_create_endpoint_engine(endpoint_id: str):
    """
    Return (creating if absent) the FusionDecisionEngine for *endpoint_id*.
    Each engine has its own EventBuffer and CorrelationEngine so events from
    different endpoints never contaminate each other.
    """
    if endpoint_id not in _endpoint_engines:
        from fusion_engine import EventBuffer, CorrelationEngine, FusionDecisionEngine  # noqa: PLC0415
        _endpoint_engines[endpoint_id] = FusionDecisionEngine(
            EventBuffer(), CorrelationEngine()
        )
        logger.debug(f"Created per-endpoint FusionDecisionEngine for endpoint_id={endpoint_id!r}")
    return _endpoint_engines[endpoint_id]


def _suricata_flows_to_dicts(flow_events: list) -> list:
    """Convert Suricata eve.json flow records to flow dicts for detect_from_flows()."""
    out = []
    for ev in flow_events:
        try:
            fl = ev.get("flow", {})
            # Compute duration from age field or start/end timestamps
            age = float(fl.get("age", 0))
            if age <= 0:
                try:
                    from datetime import datetime as _dt
                    start = _dt.fromisoformat(fl["start"].replace("+0000", "+00:00"))
                    end   = _dt.fromisoformat(fl["end"].replace("+0000", "+00:00"))
                    age   = max(1.0, (end - start).total_seconds())
                except Exception:
                    age = 1.0
            duration = max(1.0, age)

            proto = str(ev.get("proto", "TCP")).upper()
            out.append({
                "src_ip":           ev.get("src_ip", ""),
                "dest_ip":          ev.get("dest_ip", ""),
                "dest_port":        int(ev.get("dest_port", 0)),
                "bytes_sent":       float(fl.get("bytes_toserver", 0)),
                "bytes_received":   float(fl.get("bytes_toclient", 0)),
                "packets_sent":     float(fl.get("pkts_toserver", 0)),
                "packets_received": float(fl.get("pkts_toclient", 0)),
                "duration":         duration,
                "syn_flag":         0,
                "fin_flag":         1 if fl.get("reason") in ("fin", "timeout") else 0,
                "rst_flag":         1 if fl.get("reason") == "rst" else 0,
                "ack_flag":         1 if fl.get("state") == "established" else 0,
            })
        except Exception:
            continue
    return out


async def _score_endpoint_telemetry_with_ai(
    payload: "EndpointTelemetry",
    hostname: str,
) -> dict:
    """
    Run all four AI detection agents on endpoint telemetry concurrently.
    Returns a unified dict with network_score, system_score, malware_score, user_score
    all in [0.0, 1.0]. Failures in any agent produce 0.0 for that score.
    """
    async def _zero() -> dict:
        return {}

    _user_data = payload.user
    logger.debug(
        "[endpoint AI] user_data keys: %s",
        list(_user_data.keys()) if isinstance(_user_data, dict) else type(_user_data),
    )
    coros = [
        asyncio.to_thread(
            _network_agent.detect_from_endpoint_network, payload.network, hostname
        ) if _network_agent else _zero(),
        asyncio.to_thread(
            _system_agent.predict_from_metrics, payload.system
        ) if _system_agent else _zero(),
        asyncio.to_thread(
            _malware_agent.assess_process_metadata, payload.malware
        ) if _malware_agent else _zero(),
        asyncio.to_thread(
            _user_agent.score_session_telemetry, _user_data
        ) if _user_agent else _zero(),
    ]
    raw = await asyncio.gather(*coros, return_exceptions=True)
    net_res, sys_res, mal_res, usr_res = raw
    if isinstance(usr_res, Exception):
        logger.warning("[endpoint AI] score_session_telemetry raised: %s", usr_res)

    def _extract(res: object, key: str) -> float:
        if isinstance(res, Exception):
            logger.debug(f"_score_endpoint_telemetry_with_ai: agent error: {res}")
            return 0.0
        if isinstance(res, dict):
            return float(res.get(key, 0.0))
        return 0.0

    network_score = _extract(net_res, "network_score")
    system_score  = _extract(sys_res, "system_score")
    malware_score = _extract(mal_res, "malware_score")
    user_score    = _extract(usr_res, "user_score")

    logger.info(
        "[ENDPOINT_AI] host=%s net=%.3f sys=%.3f mal=%.3f usr=%.3f",
        hostname, network_score, system_score, malware_score, user_score,
    )

    # --- Suricata flow processing (runs after primary scoring) ---------------
    _suricata_net_score = 0.0
    _suricata_data = payload.suricata
    if _network_agent and _suricata_data:
        _sur_flows = _suricata_data.get("flow_events", [])
        _sur_alerts = _suricata_data.get("alert_events", [])
        if _sur_flows:
            try:
                _flow_dicts = _suricata_flows_to_dicts(_sur_flows)
                if _flow_dicts:
                    _sur_result = await asyncio.to_thread(
                        _network_agent.detect_from_flows, _flow_dicts
                    )
                    _sur_ml = _sur_result.get("ml_results", [])
                    _atk_scores = [
                        r.get("confidence", 50.0) / 100.0
                        for r in _sur_ml if r.get("prediction") == "ATTACK"
                    ]
                    if _atk_scores:
                        _suricata_net_score = max(_atk_scores)
                    elif _sur_ml:
                        _suricata_net_score = 0.05
            except Exception as _se:
                logger.debug("[ENDPOINT_SURICATA_FLOW] error: %s", _se)
        # High-severity Suricata IDS alerts directly boost the score
        for _alert_ev in _sur_alerts:
            _sev = int(_alert_ev.get("alert", {}).get("severity", 4))
            if _sev <= 1:
                _suricata_net_score = max(_suricata_net_score, 0.85)
            elif _sev == 2:
                _suricata_net_score = max(_suricata_net_score, 0.60)
    # Take the best of psutil-based and Suricata-based network scores
    network_score = max(network_score, _suricata_net_score)

    # --- Sysmon behavioral event processing ----------------------------------
    _sysmon_data = payload.sysmon_events
    if _sysmon_agent and _sysmon_data:
        _sysmon_evs = _sysmon_data.get("events", [])
        if _sysmon_evs:
            try:
                # _handle_event is synchronous and fast; run all events in a thread
                def _feed_sysmon_events(events):
                    for ev in events:
                        _sysmon_agent._handle_event(ev)
                await asyncio.to_thread(_feed_sysmon_events, _sysmon_evs)
            except Exception as _sye:
                logger.debug("[ENDPOINT_SYSMON] error: %s", _sye)

    # --- Winlogbeat OC-SVM user scoring (upgrades session heuristic) ---------
    _wb_data = payload.winlogbeat_events
    if _user_agent and _wb_data:
        _wb_evs = _wb_data.get("events", [])
        if _wb_evs:
            try:
                _wb_result = await _user_agent.run_once_from_events(_wb_evs)
                # Extract the max anomaly score across all users in the result
                _wb_rows = _wb_result.get("rows", [])
                if _wb_rows:
                    _wb_max_score = max(
                        float(r.get("anomaly_score", 0.0)) for r in _wb_rows
                    )
                    # OC-SVM score wins if it's higher than the session heuristic
                    if _wb_max_score > user_score:
                        user_score = _wb_max_score
                        logger.debug(
                            "[ENDPOINT_WB] OC-SVM upgraded user_score %.3f → %.3f",
                            _extract(usr_res, "user_score"), user_score,
                        )
            except Exception as _wbe:
                logger.debug("[ENDPOINT_WINLOGBEAT] error: %s", _wbe)

    return {
        "network_score":      network_score,
        "system_score":       system_score,
        "malware_score":      malware_score,
        "user_score":         user_score,
        "suricata_net_score": _suricata_net_score,
        "network_detail": net_res if not isinstance(net_res, Exception) else {},
        "system_detail":  sys_res if not isinstance(sys_res, Exception) else {},
        "malware_detail": mal_res if not isinstance(mal_res, Exception) else {},
        "user_detail":    usr_res if not isinstance(usr_res, Exception) else {},
    }


async def _endpoint_fuse(endpoint_id: str, signals: dict) -> Optional[dict]:
    """
    Run per-endpoint fusion for *endpoint_id* using *signals* and return
    a compact result dict, or None if the engine is unavailable.

    Also feeds *signals* into the global ``_fe`` instance for cross-endpoint
    APT correlation — the global instance is unchanged.

    Returns
    -------
    dict | None
        {
            "endpoint_id": str,
            "threat_score": float,
            "severity": str,
            "sources": list[str],
            "attack_type": str,
            "shap_explanation": dict | None,  # only for HIGH / CRITICAL
        }
    """
    try:
        engine = _get_or_create_endpoint_engine(endpoint_id)
    except Exception as exc:
        logger.debug(f"_endpoint_fuse: could not get engine for {endpoint_id!r}: {exc}")
        return None

    try:
        fe_out = await asyncio.to_thread(engine.ingest_event, signals)
    except Exception as exc:
        logger.debug(f"_endpoint_fuse: engine error for {endpoint_id!r}: {exc}")
        return None

    if not fe_out:
        return None

    final = fe_out.get("final_decision", {})
    correlation = fe_out.get("correlation", {})

    threat_score = float(final.get("threat_score", 0.0))
    severity = str(final.get("severity", "LOW"))
    sources = list(correlation.get("involved_sources", []))
    attack_type = str(correlation.get("attack_type", ""))

    result: dict = {
        "endpoint_id": endpoint_id,
        "threat_score": threat_score,
        "severity": severity,
        "sources": sources,
        "attack_type": attack_type,
        "shap_explanation": None,
    }

    # SHAP explanation for HIGH / CRITICAL (Gap 4)
    if severity in ("HIGH", "CRITICAL") and _shap_agent is not None:
        try:
            shap_exp = await asyncio.to_thread(_shap_agent.explain_fusion, final)
            result["shap_explanation"] = shap_exp
            # Persist to shap_explanations with endpoint_id tag
            _save("shap_explanations", {**shap_exp, "endpoint_id": endpoint_id, "alert_ts": _now()})
        except Exception as exc:
            logger.debug(f"_endpoint_fuse: SHAP explain failed for {endpoint_id!r}: {exc}")

    # Feed into global _fe for cross-endpoint APT correlation (existing behaviour preserved)
    try:
        global_out = await asyncio.to_thread(_fe.ingest_event, signals)
        ts = _now()
        await _emit_soc_alert_if_correlated(global_out, ts)
    except Exception as exc:
        logger.debug(f"_endpoint_fuse: global _fe feed failed for {endpoint_id!r}: {exc}")

    return result


# ---------------------------------------------------------------------------
# Server-host SOAR executor — executes SOAR actions locally on the server machine
# ---------------------------------------------------------------------------

async def _server_soar_executor(action: str, target: str, parameters: dict) -> tuple:
    """Execute a SOAR action locally on the server host.  Returns (success, message).

    All subprocess calls use:
      - Full absolute paths to Windows system executables (no PATH dependency)
      - shell=False (security requirement — never shell=True)
      - CREATE_NO_WINDOW flag so no console or UAC dialogs appear
      - Explicit returncode checks with stdout+stderr logged on failure
    """
    import re as _re
    import shutil as _shutil

    # Safety net: this executor only ever runs for endpoint_id="server_host", so a
    # power action reaching here would shut down / sleep the SOC box itself. The
    # /endpoint/command endpoint already blocks this, but refuse defensively too.
    if action in ("shutdown_host", "sleep_host"):
        return True, (
            f"ADVISORY: {action} is not executed on the SOC server host "
            "(would take the dashboard offline); target a remote endpoint instead."
        )

    # Full paths to Windows executables — immune to PATH manipulation in service contexts.
    _NETSH_EXE    = r"C:\Windows\System32\netsh.exe"
    _NET_EXE      = r"C:\Windows\System32\net.exe"
    _SCHTASKS_EXE = r"C:\Windows\System32\schtasks.exe"

    # Suppress console windows — critical for silent SOAR execution with no UAC prompts.
    _NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    # Helper: run a subprocess via asyncio without a console window.
    async def _run_async(cmd: list) -> tuple:
        """Run cmd, return (returncode, stdout_str, stderr_str)."""
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            creationflags=_NO_WIN,
        )
        stdout_b, stderr_b = await proc.communicate()
        return (
            proc.returncode,
            stdout_b.decode(errors="replace").strip(),
            stderr_b.decode(errors="replace").strip(),
        )

    try:
        _STRICT_IPV4_RE = r"^((25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(25[0-5]|2[0-4]\d|[01]?\d\d?)$"

        if action == "block_ip":
            if not _re.match(_STRICT_IPV4_RE, target or ""):
                return False, f"Invalid IP address: {target!r}"
            # Use underscore-based rule name for unblock lookup consistency.
            rule_name = f"XDR_BLOCK_{target}"
            errors: list[str] = []
            for direction in ("in", "out"):
                cmd = [
                    _NETSH_EXE, "advfirewall", "firewall", "add", "rule",
                    f"name={rule_name}", f"dir={direction}", "action=block",
                    f"remoteip={target}", "protocol=any", "enable=yes",
                ]
                rc, stdout, stderr = await _run_async(cmd)
                if rc != 0:
                    err_detail = stderr or stdout or f"rc={rc}"
                    errors.append(f"{direction}: {err_detail}")
                    logger.warning(
                        "[SERVER_SOAR] block_ip %s dir=%s failed rc=%d: %s",
                        target, direction, rc, err_detail,
                    )
                else:
                    logger.debug("[SERVER_SOAR] block_ip %s dir=%s OK", target, direction)
            if not errors:
                return True, f"Blocked IP {target} via Windows Firewall rule {rule_name} (in + out)"
            # Fallback: try PowerShell New-NetFirewallRule
            logger.warning("[SERVER_SOAR] block_ip netsh failed; trying PowerShell fallback for %s", target)
            ps_errors: list[str] = []
            for direction in ("Inbound", "Outbound"):
                ps_cmd = [
                    "powershell", "-NonInteractive", "-Command",
                    (
                        f"New-NetFirewallRule -DisplayName '{rule_name}_{direction}' "
                        f"-Direction {direction} -Action Block "
                        f"-RemoteAddress {target} -Protocol Any -Enabled True"
                    ),
                ]
                try:
                    ps_rc, ps_out, ps_err = await _run_async(ps_cmd)
                    if ps_rc != 0:
                        ps_errors.append(f"{direction}: {ps_err or ps_out or f'rc={ps_rc}'}")
                    else:
                        logger.debug("[SERVER_SOAR] block_ip PS fallback %s dir=%s OK", target, direction)
                except Exception as _pse:
                    ps_errors.append(f"{direction}: {_pse}")
            if not ps_errors:
                return True, f"Blocked IP {target} via PowerShell New-NetFirewallRule (in + out)"
            return False, f"block_ip failed (netsh: {'; '.join(errors)}) (PS: {'; '.join(ps_errors)})"

        elif action == "unblock_ip":
            if not _re.match(_STRICT_IPV4_RE, target or ""):
                return False, f"Invalid IP address: {target!r}"
            rule_name = f"XDR_BLOCK_{target}"
            cmd = [
                _NETSH_EXE, "advfirewall", "firewall", "delete", "rule",
                f"name={rule_name}",
            ]
            rc, stdout, stderr = await _run_async(cmd)
            if rc == 0:
                return True, f"Unblocked IP {target} — removed firewall rule {rule_name}"
            err_detail = stderr or stdout or f"rc={rc}"
            logger.warning("[SERVER_SOAR] unblock_ip %s failed rc=%d: %s", target, rc, err_detail)
            return False, f"netsh unblock_ip failed: {err_detail}"

        elif action == "kill_process":
            import psutil as _psutil
            killed: list[str] = []
            access_denied: list[str] = []
            _taskkill_exe = r"C:\Windows\System32\taskkill.exe"
            try:
                pid = int(target)
                proc_obj = _psutil.Process(pid)
                try:
                    proc_obj.kill()
                    killed.append(f"PID {pid}")
                except _psutil.AccessDenied:
                    # Fallback: taskkill /F /PID
                    logger.warning("[SERVER_SOAR] kill_process psutil AccessDenied PID=%s, trying taskkill", pid)
                    try:
                        tk_rc, tk_out, tk_err = await _run_async([_taskkill_exe, "/F", "/PID", str(pid)])
                        if tk_rc == 0:
                            killed.append(f"PID {pid} (via taskkill)")
                        else:
                            access_denied.append(f"PID {pid}: {tk_err or tk_out}")
                    except Exception as _tke:
                        access_denied.append(f"PID {pid}: {_tke}")
            except (ValueError, _psutil.NoSuchProcess):
                # target is a process name
                for proc_obj in _psutil.process_iter(["pid", "name"]):
                    if proc_obj.info["name"] and target.lower() in proc_obj.info["name"].lower():
                        try:
                            proc_obj.kill()
                            killed.append(f"{proc_obj.info['name']} (PID {proc_obj.info['pid']})")
                        except _psutil.AccessDenied:
                            access_denied.append(
                                f"{proc_obj.info['name']} PID={proc_obj.info['pid']}"
                            )
                            logger.warning(
                                "[SERVER_SOAR] kill_process AccessDenied on %s PID=%s",
                                proc_obj.info["name"], proc_obj.info["pid"],
                            )
                        except Exception as _e:
                            logger.warning(
                                "[SERVER_SOAR] kill_process error on PID %s: %s",
                                proc_obj.info.get("pid"), _e,
                            )
            except _psutil.AccessDenied as _e:
                logger.warning("[SERVER_SOAR] kill_process AccessDenied PID=%s: %s", target, _e)
                # Fallback: taskkill /F /PID
                try:
                    tk_rc, tk_out, tk_err = await _run_async([_taskkill_exe, "/F", "/PID", target])
                    if tk_rc == 0:
                        killed.append(f"PID {target} (via taskkill)")
                    else:
                        return False, f"Access denied + taskkill failed: {tk_err or tk_out}"
                except Exception as _tke:
                    return False, f"Access denied killing PID {target} — taskkill also failed: {_tke}"
            # For name-based kills where psutil missed all due to access denied: try taskkill /F /IM
            if not killed and access_denied and not target.isdigit():
                logger.warning("[SERVER_SOAR] kill_process trying taskkill /F /IM for %r", target)
                try:
                    tk_rc, tk_out, tk_err = await _run_async([_taskkill_exe, "/F", "/IM", target])
                    if tk_rc == 0:
                        killed.append(f"{target} (via taskkill /IM)")
                        access_denied.clear()
                    else:
                        logger.warning("[SERVER_SOAR] taskkill /IM %r failed: %s", target, tk_err or tk_out)
                except Exception as _tke:
                    logger.warning("[SERVER_SOAR] taskkill /IM exception: %s", _tke)
            if killed:
                msg = f"Killed process(es): {', '.join(killed)}"
                if access_denied:
                    msg += f" (access denied for: {', '.join(access_denied)})"
                return True, msg
            if access_denied:
                return False, f"Access denied for all matching processes: {', '.join(access_denied)}"
            return False, f"No process found matching {target!r}"

        elif action == "quarantine_file":
            target_path = target.strip()
            if not os.path.isabs(target_path):
                return False, f"Quarantine requires absolute path, got: {target_path!r}"
            if not os.path.exists(target_path):
                return False, f"File not found: {target_path!r}"
            quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
            os.makedirs(quarantine_dir, exist_ok=True)
            dest = os.path.join(quarantine_dir, os.path.basename(target_path))
            try:
                _shutil.move(target_path, dest)
            except Exception as _e:
                logger.error("[SERVER_SOAR] quarantine_file move failed: %s", _e)
                return False, f"quarantine_file failed: {_e}"
            return True, f"Quarantined {target_path} -> {dest}"

        elif action == "lock_account":
            if not target or not target.strip():
                return False, "lock_account requires a target username"
            username = target.strip()
            # --- SELF-LOCK / bad-target guard (industry-standard safety) ---
            # Never disable the operator's own account on the SOC/server host,
            # and never try to lock an endpoint-id (server_host / UUID) that was
            # passed in place of a real username.
            _current_user = (os.environ.get("USERNAME") or "").strip()
            if username.lower() in ("server_host", "unknown") or \
               _re.match(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-", username):
                return True, (f"ADVISORY: lock_account target {username!r} is an endpoint "
                              "id, not a username — no account locked. Resolve the flagged "
                              "user first.")
            if _current_user and username.lower() == _current_user.lower():
                return True, (f"ADVISORY: refused to lock operator account {username!r} on "
                              "the SOC/server host (self-lock protection).")
            if not _re.match(r"^[\w\-\. ]{1,20}$", username):
                return False, f"lock_account: invalid username format: {username!r}"
            if platform.system() != "Windows":
                return False, "lock_account is only supported on Windows"
            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [_NET_EXE, "user", username, "/active:no"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=_NO_WIN,
                )
                if proc.returncode == 0:
                    return True, f"Account locked: {username!r}"
                err_detail = (proc.stderr or proc.stdout or "").strip()
                logger.warning(
                    "[SERVER_SOAR] lock_account %r failed rc=%d: %s",
                    username, proc.returncode, err_detail,
                )
                return False, f"net user lock failed for {username!r}: {err_detail}"
            except subprocess.TimeoutExpired:
                return False, f"lock_account timed out for {username!r}"
            except Exception as exc:
                return False, f"lock_account error: {exc}"

        elif action == "unlock_account":
            if not target or not target.strip():
                return False, "unlock_account requires a target username"
            username = target.strip()
            if not _re.match(r"^[\w\-\. ]{1,20}$", username):
                return False, f"unlock_account: invalid username format: {username!r}"
            if platform.system() != "Windows":
                return False, "unlock_account is only supported on Windows"
            try:
                proc = await asyncio.to_thread(
                    subprocess.run,
                    [_NET_EXE, "user", username, "/active:yes"],
                    capture_output=True, text=True, timeout=15,
                    creationflags=_NO_WIN,
                )
                if proc.returncode == 0:
                    return True, f"Account unlocked: {username!r}"
                err_detail = (proc.stderr or proc.stdout or "").strip()
                logger.warning(
                    "[SERVER_SOAR] unlock_account %r failed rc=%d: %s",
                    username, proc.returncode, err_detail,
                )
                return False, f"net user unlock failed for {username!r}: {err_detail}"
            except subprocess.TimeoutExpired:
                return False, f"unlock_account timed out for {username!r}"
            except Exception as exc:
                return False, f"unlock_account error: {exc}"

        elif action == "scan_filesystem":
            import os as _os_scan
            suspicious_exts = {".exe", ".dll", ".ps1", ".bat", ".vbs", ".scr"}
            cutoff_mtime = time.time() - 3600  # files modified in the last hour
            found: list[dict] = []
            try:
                roots = getattr(settings, "scan_allowed_roots", [r"C:\Users", r"C:\Temp", r"C:\Windows\Temp"])
                for root_path in roots:
                    try:
                        for dirpath, _dirs, files in _os_scan.walk(root_path):
                            for fname in files:
                                try:
                                    ext = _os_scan.path.splitext(fname)[1].lower()
                                    if ext not in suspicious_exts:
                                        continue
                                    full_path = _os_scan.path.join(dirpath, fname)
                                    try:
                                        mtime = _os_scan.path.getmtime(full_path)
                                    except OSError:
                                        continue
                                    if mtime >= cutoff_mtime:
                                        found.append({"path": full_path, "mtime": mtime})
                                except Exception:
                                    continue
                    except Exception:
                        continue
                # Sort by mtime descending (newest first), keep top 10 for the message
                found.sort(key=lambda f: f["mtime"], reverse=True)
                top10 = [f["path"] for f in found[:10]]
                return True, f"Filesystem scan complete: {len(found)} suspicious file(s) found in last 3600s. Top files: {top10}"
            except Exception as exc:
                return False, f"scan_filesystem error: {exc}"

        elif action == "monitor_persistence":
            results_mp: list = []
            try:
                # 1. Registry Run keys — check both HKCU and HKLM
                try:
                    import winreg as _winreg  # type: ignore[import]
                    for _hive, _hive_name in [
                        (_winreg.HKEY_CURRENT_USER,  "HKCU"),
                        (_winreg.HKEY_LOCAL_MACHINE, "HKLM"),
                    ]:
                        try:
                            _key_path = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
                            _hk = _winreg.OpenKey(_hive, _key_path)
                            _idx = 0
                            while True:
                                try:
                                    _name, _val, _ = _winreg.EnumValue(_hk, _idx)
                                    results_mp.append(
                                        f"{_hive_name}\\Run: {_name}={str(_val)[:60]}"
                                    )
                                    _idx += 1
                                except OSError:
                                    break
                            _winreg.CloseKey(_hk)
                        except PermissionError:
                            # HKLM requires Administrator — degrade gracefully with a note
                            results_mp.append(
                                f"{_hive_name}\\Run: Access denied (requires elevation)"
                            )
                        except OSError:
                            pass  # key does not exist on this system
                except ImportError:
                    results_mp.append("winreg not available on this platform")

                # 2. Startup folder item count
                import glob as _glob_mp
                _startup_dir = os.path.expandvars(
                    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup"
                )
                try:
                    _startup_items = (
                        _glob_mp.glob(os.path.join(_startup_dir, "*"))
                        if os.path.isdir(_startup_dir)
                        else []
                    )
                    results_mp.append(
                        f"Startup folder ({_startup_dir}): {len(_startup_items)} item(s)"
                    )
                except Exception:
                    results_mp.append("Startup folder: could not enumerate")

                # 3. Scheduled tasks — best-effort, never raises
                try:
                    _schtasks_proc = await asyncio.to_thread(
                        subprocess.run,
                        [_SCHTASKS_EXE, "/query", "/fo", "CSV"],
                        capture_output=True, text=True, timeout=15,
                        creationflags=_NO_WIN,
                    )
                    _task_lines = [
                        l for l in (_schtasks_proc.stdout or "").splitlines()
                        if l.strip() and not l.startswith('"TaskName"')
                    ]
                    results_mp.append(f"Scheduled tasks: {len(_task_lines)} entries")
                except subprocess.TimeoutExpired:
                    results_mp.append("Scheduled tasks: query timed out")
                except Exception as _sch_exc:
                    results_mp.append(f"Scheduled tasks: query error ({_sch_exc})")

                msg = (
                    f"Persistence check complete: {len(results_mp)} item(s) found"
                )
                return True, msg + " | " + "; ".join(results_mp[:10])
            except Exception as exc:
                # Always succeed so the plan doesn't flip to FAILED
                return True, f"monitor_persistence completed with error: {exc}"

        elif action == "isolate_host":
            flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "isolation_flag.txt")
            try:
                with open(flag_path, "w") as _f:
                    _f.write(f"ISOLATED by XDR SOAR at {datetime.utcnow().isoformat()}\n")
            except OSError as _fe:
                logger.warning("[SERVER_SOAR] isolate_host: could not write flag: %s", _fe)
            # Build ordered list of interface names to try:
            # 1. Caller-supplied via parameters
            # 2. Config / env var (settings.soar_isolate_interface)
            # 3. Auto-detect from psutil (first UP non-loopback adapter)
            # 4. Common Windows default names as last resort
            _cfg_iface = parameters.get("interface", "") or settings.soar_isolate_interface or ""
            _ifaces_to_try: list[str] = []
            if _cfg_iface:
                _ifaces_to_try.append(_cfg_iface)
            # Auto-detect via psutil
            try:
                import psutil as _psutil_iface
                _stats = _psutil_iface.net_if_stats()
                for _iname, _istats in _stats.items():
                    if _istats.isup and _iname.lower() not in ("lo", "loopback"):
                        if _iname not in _ifaces_to_try:
                            _ifaces_to_try.append(_iname)
            except Exception:
                pass
            # Append common fallback names (avoid duplicates)
            for _fb in ("Ethernet", "Wi-Fi", "Wireless Network Connection", "Local Area Connection"):
                if _fb not in _ifaces_to_try:
                    _ifaces_to_try.append(_fb)
            # Try each interface name in order until one succeeds
            _last_err = ""
            for _iface_candidate in _ifaces_to_try:
                rc, stdout, stderr = await _run_async(
                    [_NETSH_EXE, "interface", "set", "interface", _iface_candidate, "disable"]
                )
                if rc == 0:
                    logger.warning(
                        "[SERVER_SOAR] isolate_host: interface %r disabled successfully", _iface_candidate
                    )
                    return True, f"Host isolation initiated — flag written, interface {_iface_candidate!r} disabled"
                _last_err = stderr or stdout or f"rc={rc}"
                logger.debug(
                    "[SERVER_SOAR] isolate_host: interface %r failed (rc=%d): %s — trying next",
                    _iface_candidate, rc, _last_err,
                )
            # All interface names failed — isolation flag is still written
            logger.warning(
                "[SERVER_SOAR] isolate_host: all interface names failed. Last error: %s", _last_err
            )
            return True, (
                f"Host isolation flag written but netsh failed for all interface names "
                f"(tried: {_ifaces_to_try}). Last error: {_last_err}. "
                f"Set XDR_ISOLATE_INTERFACE env var to the correct interface name."
            )

        elif action == "restore_quarantine_file":
            if not target or not target.strip():
                return False, "restore_quarantine_file requires a target (original file path before quarantine)"
            target_path = target.strip()
            quarantine_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "quarantine")
            quarantine_file = os.path.join(quarantine_dir, os.path.basename(target_path))
            if not os.path.exists(quarantine_file):
                return False, (
                    f"Quarantine file not found: {quarantine_file!r}. "
                    f"File may not have been quarantined or may have already been restored."
                )
            dest_dir = os.path.dirname(target_path)
            if dest_dir and not os.path.isdir(dest_dir):
                try:
                    os.makedirs(dest_dir, exist_ok=True)
                except OSError as _e:
                    return False, f"restore_quarantine_file: cannot create destination directory {dest_dir!r}: {_e}"
            try:
                _shutil.move(quarantine_file, target_path)
            except Exception as _e:
                return False, f"restore_quarantine_file move failed: {_e}"
            return True, f"Restored quarantined file {quarantine_file!r} -> {target_path!r}"

        elif action == "unisolate_host":
            flag_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "isolation_flag.txt")
            # Build the same ordered interface list as isolate_host
            _cfg_iface_u = parameters.get("interface", "") or settings.soar_isolate_interface or ""
            _ifaces_to_try_u: list[str] = []
            if _cfg_iface_u:
                _ifaces_to_try_u.append(_cfg_iface_u)
            try:
                import psutil as _psutil_iface_u
                _stats_u = _psutil_iface_u.net_if_stats()
                for _iname_u, _istats_u in _stats_u.items():
                    # include DOWN interfaces too — we want to re-enable the isolated one
                    if _iname_u.lower() not in ("lo", "loopback"):
                        if _iname_u not in _ifaces_to_try_u:
                            _ifaces_to_try_u.append(_iname_u)
            except Exception:
                pass
            for _fb_u in ("Ethernet", "Wi-Fi", "Wireless Network Connection", "Local Area Connection"):
                if _fb_u not in _ifaces_to_try_u:
                    _ifaces_to_try_u.append(_fb_u)
            _last_err_u = ""
            for _iface_u in _ifaces_to_try_u:
                rc, stdout, stderr = await _run_async(
                    [_NETSH_EXE, "interface", "set", "interface", _iface_u, "enable"]
                )
                if rc == 0:
                    # Remove isolation flag file if it exists
                    try:
                        if os.path.exists(flag_path):
                            os.remove(flag_path)
                    except OSError as _e:
                        logger.warning("[SERVER_SOAR] unisolate_host: could not remove flag file: %s", _e)
                    logger.info("[SERVER_SOAR] unisolate_host: interface %r re-enabled", _iface_u)
                    return True, f"Host unisolated — interface {_iface_u!r} re-enabled, isolation flag removed"
                _last_err_u = stderr or stdout or f"rc={rc}"
                logger.debug(
                    "[SERVER_SOAR] unisolate_host: interface %r failed (rc=%d): %s — trying next",
                    _iface_u, rc, _last_err_u,
                )
            logger.warning("[SERVER_SOAR] unisolate_host: all interface names failed. Last: %s", _last_err_u)
            return False, (
                f"netsh failed to enable any interface (tried: {_ifaces_to_try_u}). "
                f"Last error: {_last_err_u}. "
                f"Set XDR_ISOLATE_INTERFACE env var to the correct interface name."
            )

        elif action in (
            "alert_admin", "update_software", "patch_openssl",
            "rotate_certificates", "check_exposed_secrets", "force_logout",
            "review_account", "review_logs", "invalidate_sessions",
            "log_event", "log_user_session", "restrict_access", "rate_limit_traffic",
            "collect_forensics",
        ):
            # Advisory-only actions: no OS-level change is performed on the server host.
            # Log the acknowledgement and return success so the plan lifecycle completes.
            logger.info("[SERVER_SOAR] Advisory action acknowledged: %s target=%r", action, target)
            return True, f"Advisory action acknowledged: {action}"

        else:
            return False, f"Unknown SOAR action: {action!r}"

    except Exception as exc:
        logger.error("[SERVER_SOAR] Unhandled exception in action=%r: %s", action, exc, exc_info=True)
        return False, f"Server SOAR executor error: {exc}"


async def _server_soar_loop() -> None:
    """
    Poll endpoint_commands for server_host pending commands every 5 seconds,
    execute them locally via _server_soar_executor, then ACK to MongoDB
    and emit command_result Socket.IO event.
    """
    logger.info("Server SOAR executor loop started (polling endpoint_commands for server_host)")
    while True:
        try:
            await asyncio.sleep(5.0)
            if not MONGO_OK or _db is None:
                continue

            def _fetch_pending():
                return list(
                    _db["endpoint_commands"].find(
                        {"endpoint_id": "server_host", "status": "pending"},
                        sort=[("created_at", 1)],
                        limit=10,
                    )
                )

            pending = await asyncio.to_thread(_fetch_pending)

            for cmd_doc in pending:
                cmd_id  = str(cmd_doc["_id"])
                action  = cmd_doc.get("action", "")
                target  = cmd_doc.get("target", "")
                params  = cmd_doc.get("parameters") or {}

                # Mark as sent immediately to prevent double-execution
                await asyncio.to_thread(
                    lambda cid=cmd_id: _db["endpoint_commands"].update_one(
                        {"_id": cmd_doc["_id"]},
                        {"$set": {"status": "sent", "sent_at": datetime.utcnow().isoformat()}},
                    )
                )

                logger.info(
                    f"[SERVER_SOAR] Executing action={action} target={target!r} cmd_id={cmd_id}"
                )

                _soar_t0 = time.monotonic()
                success, message = await _server_soar_executor(action, target, params)
                _soar_duration_ms = (time.monotonic() - _soar_t0) * 1000.0

                # Forensic audit trail — non-blocking fire-and-forget
                asyncio.create_task(_write_soar_audit_event(
                    action=action,
                    target=target,
                    endpoint_id="server_host",
                    success=success,
                    message=message,
                    duration_ms=_soar_duration_ms,
                    actor="SOAR_AUTO",
                ))

                final_status = "completed" if success else "failed"
                _exec_ts = datetime.utcnow().isoformat()
                await asyncio.to_thread(
                    lambda cid=cmd_id, s=final_status, m=message, ts=_exec_ts: _db["endpoint_commands"].update_one(
                        {"_id": cmd_doc["_id"]},
                        {"$set": {
                            "status": s,
                            "result_message": m,
                            "executed_at": ts,
                            "completed_at": ts,
                        }},
                    )
                )

                result_event = {
                    "command_id":    cmd_id,
                    "endpoint_id":   "server_host",
                    "action":        action,
                    "status":        "completed" if success else "failed",
                    "success":       success,
                    "message":       message,
                    "result_message": message,
                    "target":        target,
                    "timestamp":     datetime.utcnow().isoformat(),
                }
                await sio.emit("command_result", result_event)
                logger.info(
                    f"[SERVER_SOAR] Done action={action} success={success} message={message!r}"
                )

                # Post-execution registry updates
                if action == "isolate_host" and success:
                    await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].update_one(
                            {"endpoint_id": "server_host"},
                            {"$set": {"status": "isolated"}},
                        )
                    )
                    _updated = await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].find_one(
                            {"endpoint_id": "server_host"}, {"_id": 0}
                        )
                    )
                    if _updated and not _updated.get("is_server"):
                        await sio.emit("endpoint_update", _strip_mongo(_updated))

                elif action == "block_ip" and success and target:
                    await asyncio.to_thread(
                        lambda t=target: _db["endpoint_registry"].update_one(
                            {"endpoint_id": "server_host"},
                            {"$addToSet": {"blocked_ips": t}},
                        )
                    )
                    _updated = await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].find_one(
                            {"endpoint_id": "server_host"}, {"_id": 0}
                        )
                    )
                    if _updated and not _updated.get("is_server"):
                        await sio.emit("endpoint_update", _strip_mongo(_updated))

                elif action == "unblock_ip" and success and target:
                    await asyncio.to_thread(
                        lambda t=target: _db["endpoint_registry"].update_one(
                            {"endpoint_id": "server_host"},
                            {"$pull": {"blocked_ips": t}},
                        )
                    )
                    _updated = await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].find_one(
                            {"endpoint_id": "server_host"}, {"_id": 0}
                        )
                    )
                    if _updated and not _updated.get("is_server"):
                        await sio.emit("endpoint_update", _strip_mongo(_updated))

                elif action == "unisolate_host" and success:
                    await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].update_one(
                            {"endpoint_id": "server_host"},
                            {"$set": {"status": "online"}},
                        )
                    )
                    _updated = await asyncio.to_thread(
                        lambda: _db["endpoint_registry"].find_one(
                            {"endpoint_id": "server_host"}, {"_id": 0}
                        )
                    )
                    if _updated and not _updated.get("is_server"):
                        await sio.emit("endpoint_update", _strip_mongo(_updated))

        except asyncio.CancelledError:
            logger.info("Server SOAR loop cancelled")
            raise
        except Exception as exc:
            logger.error(f"[server_soar_executor] loop iteration failed: {exc}", exc_info=True)
            await asyncio.sleep(5)
            continue


# ---------------------------------------------------------------------------
# Endpoint heartbeat background loop
# ---------------------------------------------------------------------------
async def _endpoint_heartbeat_loop() -> None:
    """
    Every 10 seconds, query endpoint_registry for endpoints whose last_seen
    timestamp is more than 35 seconds in the past and whose status is 'online'.
    Marks them 'offline' in MongoDB and emits an 'endpoint_offline' Socket.IO event.

    The 35-second stale threshold provides a 30-second buffer beyond the 5-second
    endpoint agent telemetry interval, preventing spurious offline events caused by
    normal inter-telemetry gaps.
    """
    logger.info("Endpoint heartbeat monitor started (interval=10s, stale_threshold=35s)")
    while True:
        try:
            await asyncio.sleep(10.0)
            if not MONGO_OK or _db is None:
                continue
            # Any endpoint whose last_seen is older than 35s is considered stale.
            # 35s = 5s telemetry interval + 30s grace buffer for network jitter and
            # processing delays.  We compare datetime objects (not ISO strings) to
            # avoid locale/format edge cases.
            cutoff_dt = datetime.utcnow() - timedelta(seconds=35)

            def _find_and_mark_offline():
                session_start_iso = _backend_session_start.isoformat()
                now_dt = datetime.utcnow()
                stale_docs = list(
                    _db["endpoint_registry"].find({
                        "status": "online",
                        "endpoint_id": {"$ne": "server_host"},
                    })
                )
                marked = []
                for doc in stale_docs:
                    last_seen_raw = doc.get("last_seen", "")
                    try:
                        # Strip trailing 'Z' and parse; Atlas stores as UTC ISO strings
                        ls_str = last_seen_raw.rstrip("Z").replace("+00:00", "")
                        ls_dt = datetime.fromisoformat(ls_str)
                    except Exception:
                        continue
                    # Skip entries from before this backend session (already cleaned
                    # up on startup — processing them again would emit spurious
                    # endpoint_offline events for endpoints that never connected).
                    if ls_str < session_start_iso:
                        continue
                    # Mark offline if stale (last_seen > 35s ago) OR has a future
                    # timestamp (clock drift on endpoint agent — future timestamps
                    # never expire naturally via the cutoff_dt comparison alone).
                    is_stale = ls_dt < cutoff_dt
                    is_future = ls_dt > now_dt + timedelta(seconds=60)
                    if not is_stale and not is_future:
                        continue
                    _db["endpoint_registry"].update_one(
                        {"endpoint_id": doc["endpoint_id"]},
                        {"$set": {"status": "offline"}},
                    )
                    marked.append({
                        "endpoint_id": doc.get("endpoint_id", ""),
                        "hostname":    doc.get("hostname", ""),
                        "last_seen":   last_seen_raw,
                    })
                return marked

            stale_endpoints = await asyncio.to_thread(_find_and_mark_offline)
            for ep in stale_endpoints:
                logger.info(
                    f"Endpoint offline: endpoint_id={ep['endpoint_id']} "
                    f"hostname={ep['hostname']} last_seen={ep['last_seen']}"
                )
                # Update the attack-graph node for this endpoint to offline/LOW
                if _graph_engine is not None:
                    try:
                        _graph_engine.mark_endpoint_offline(ep.get("endpoint_id", ""))
                    except Exception as _ge:
                        logger.debug(f"[heartbeat] mark_endpoint_offline failed: {_ge}")
                await sio.emit("endpoint_offline", ep)
                # Notify frontend to prune the endpoint node from the live graph
                await sio.emit("graph_update_remove", {
                    "remove_node_ids": [f"ep-{ep.get('endpoint_id', '')}"]
                })
        except asyncio.CancelledError:
            logger.info("Endpoint heartbeat monitor cancelled")
            raise
        except Exception as exc:
            logger.error(f"[endpoint_heartbeat] loop iteration failed: {exc}", exc_info=True)
            await asyncio.sleep(5)
            continue


# ---------------------------------------------------------------------------
# Endpoint Telemetry & Response Command — REST endpoints
# ---------------------------------------------------------------------------

_ENDPOINT_VALID_ACTIONS = frozenset({
    "kill_process", "block_ip", "unblock_ip",
    "isolate_host", "unisolate_host", "quarantine_file", "restore_quarantine_file",
    "lock_account", "unlock_account",
    "scan_filesystem", "monitor_persistence",
    "shutdown_host", "sleep_host",
})
# Power-state actions are destructive and irreversible from the SOC (a shut-down
# machine can only be powered back on physically).  They must NEVER target the
# backend/SOC host itself, or clicking one would take the dashboard offline.
_POWER_ACTIONS = frozenset({"shutdown_host", "sleep_host"})
# Advisory actions are generated by the response engine but must NOT be forwarded
# to the endpoint agent — they are logged/acknowledged server-side only.
_ADVISORY_ACTIONS = frozenset({
    "log_user_session",
    "restrict_access", "rate_limit_traffic",
    "log_event",
    # Heartbleed / software-patch advisories
    "patch_openssl", "rotate_certificates", "check_exposed_secrets", "update_software",
    # No-SOAR-executor advisory strings used by response engine
    "alert_admin", "force_logout", "review_account", "review_logs",
    # Session management — handled server-side by the auth system, not the endpoint agent
    "invalidate_sessions",
    # Forensic data collection — logged server-side, never executed by endpoint agent
    "collect_forensics",
})
_ENDPOINT_INGEST_RATE_LIMIT_SECONDS = 2.0

# Per-endpoint guard: at most one background ML-scoring task per endpoint at a
# time. Heavy scoring (RandomForest over up to 50 flows + LightGBM + user/system
# models) can exceed the 5-s telemetry cadence; without this guard the tasks pile
# up and ingest latency compounds until the agent times out. Overlapping ticks are
# dropped (telemetry is still persisted) instead of queued.
_endpoint_scoring_inflight: set = set()


def _scoring_task_done(task, endpoint_id: str) -> None:
    """Done-callback for the background scoring task: always clear the in-flight
    flag (so the next tick can score), and surface any failure to the log."""
    _endpoint_scoring_inflight.discard(endpoint_id)
    try:
        if not task.cancelled():
            exc = task.exception()
            if exc is not None:
                logger.error("[ENDPOINT_AI] background scoring failed: %s", exc)
    except Exception:
        pass

# ---------------------------------------------------------------------------
# Contact form rate-limiter — 3 submissions per IP per hour (in-memory)
# Keyed by client IP, value is a list of monotonic timestamps.
# ---------------------------------------------------------------------------
_contact_rate: dict[str, list] = {}   # {ip: [monotonic_time, ...]}
_CONTACT_RATE_LIMIT = 3       # max submissions per window
_CONTACT_RATE_WINDOW = 3600   # 1 hour in seconds


@app.post("/endpoint/ingest", dependencies=[Depends(_require_key)])
async def endpoint_ingest(payload: EndpointTelemetry):
    """
    Receive telemetry from an endpoint agent.
    Rate-limited to 1 request per 2 seconds per endpoint_id.
    Upserts the registry, stores the log, and emits Socket.IO events.
    """
    ep = payload.endpoint
    now_mono = time.monotonic()

    logger.debug(
        f"[endpoint/ingest] endpoint_id={payload.endpoint.endpoint_id} "
        f"network_keys={len(payload.network)} system_keys={len(payload.system)} "
        f"user_keys={len(payload.user)} malware_keys={len(payload.malware)}"
    )

    # Debug: log the top-level keys present in the incoming payload
    _payload_dict = payload.model_dump()
    logger.debug(f"Ingest payload keys: {list(_payload_dict.keys()) if isinstance(_payload_dict, dict) else type(_payload_dict)}")

    # --- Rate limit: 1 ingest per 2 s per endpoint_id ---
    last_seen_mono = _endpoint_ingest_rate.get(ep.endpoint_id, 0.0)
    if now_mono - last_seen_mono < _ENDPOINT_INGEST_RATE_LIMIT_SECONDS:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit: endpoint_id={ep.endpoint_id!r} — max 1 ingest per "
                   f"{_ENDPOINT_INGEST_RATE_LIMIT_SECONDS}s",
        )
    _endpoint_ingest_rate[ep.endpoint_id] = now_mono

    # Anti-replay: warn if timestamp is more than 5 minutes stale or in the future.
    # Do NOT reject — this preserves backward compatibility with out-of-sync clocks.
    # Stale timestamps are replaced with server time; telemetry is always processed.
    try:
        _ep_ts = payload.timestamp
        if _ep_ts is not None:
            _ep_ts_utc = _ep_ts.replace(tzinfo=timezone.utc) if _ep_ts.tzinfo is None else _ep_ts
            _ts_drift_s = abs((datetime.now(timezone.utc) - _ep_ts_utc).total_seconds())
            if _ts_drift_s > 300:
                _now_mono = time.monotonic()
                _last_warn = _stale_ts_last_warn.get(ep.endpoint_id, 0.0)
                if _now_mono - _last_warn >= 300.0:   # warn at most once per 5 min per endpoint
                    _stale_ts_last_warn[ep.endpoint_id] = _now_mono
                    logger.warning(
                        "[endpoint/ingest] Stale timestamp from %s: %s (drift=%.0fs) — using server time",
                        ep.endpoint_id, _ep_ts, _ts_drift_s,
                    )
                # Override with server time so MongoDB documents sort correctly.
                # The endpoint is real; only its clock is wrong. Never drop telemetry.
                payload.timestamp = datetime.utcnow()
    except Exception:
        pass

    logger.info(f"[ENDPOINT] Telemetry received: {ep.endpoint_id} host={ep.hostname}")

    now_iso = _now()

    # Skip all processing (registry, logs, AI scoring) when monitoring is not active.
    # This prevents stale `last_seen` updates from blocking the heartbeat from
    # marking the endpoint offline after /stop-monitoring is called.
    if not _monitoring_active:
        return {"status": "ok", "endpoint_id": ep.endpoint_id, "scored": False}

    # 1. Upsert endpoint_registry
    # Always update operational fields; only update identity fields when non-empty
    # to prevent empty defaults from overwriting previously-discovered good values
    # (e.g. ip_address "192.168.1.10" must not be erased by a "" on next tick).
    _reg_always = {
        "endpoint_id":   ep.endpoint_id,
        "last_seen":     now_iso,
        "status":        "online",
        "agent_version": ep.agent_version,
    }
    if ep.hostname:    _reg_always["hostname"]    = ep.hostname
    if ep.ip_address:  _reg_always["ip_address"]  = ep.ip_address
    if ep.os:          _reg_always["os"]           = ep.os
    if ep.os_version:  _reg_always["os_version"]   = ep.os_version
    if ep.username:    _reg_always["username"]      = ep.username
    if MONGO_OK and _db is not None:
        try:
            upsert_result = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].update_one(
                    {"endpoint_id": ep.endpoint_id},
                    {"$set": _reg_always},
                    upsert=True,
                )
            )
            if upsert_result.upserted_id:
                logger.info(f"[ENDPOINT] Registered: {ep.hostname} id={ep.endpoint_id}")
        except Exception as _reg_err:
            logger.error(f"endpoint_registry upsert failed: {_reg_err}")

    # 2. Insert into endpoint_logs
    log_doc = {
        "endpoint_id": ep.endpoint_id,
        "hostname":    ep.hostname,
        "ip_address":  ep.ip_address,
        "timestamp":   payload.timestamp,
        "received_at": now_iso,
        "network":     payload.network,
        "system":      payload.system,
        "user":        payload.user,
        "malware":     payload.malware,
        "ts_dt":       _now_dt(),   # required for TTL index
    }
    _save("endpoint_logs", log_doc)

    # 2b. Attack graph topology — baseline endpoint/user/IP nodes (non-blocking)
    if _graph_engine:
        try:
            _telem_dict = {
                "endpoint_id": ep.endpoint_id,
                "hostname":    ep.hostname,
                "ip_address":  ep.ip_address,
                "os_info":     {"system": ep.os},
                "system":      payload.system,
                "user":        payload.user,
                "network":     payload.network,
            }
            g_nodes, g_edges = _graph_engine.process_endpoint_telemetry(_telem_dict)
            asyncio.create_task(_emit_graph_update(g_nodes, g_edges))
        except Exception as _ge:
            logger.debug(f"[GRAPH] endpoint_telemetry hook error: {_ge}")

    # 3. Lightweight async analysis — do NOT block the response
    async def _analyze():
        system = payload.system
        network = payload.network
        malware_info = payload.malware

        cpu = system.get("cpu_percent", 0)
        mem = system.get("memory_percent", 0)
        suspicious_files = malware_info.get("suspicious", [])
        suspicious_ports = network.get("suspicious_ports", [])

        if cpu > 85 or mem > 90:
            alert = {
                "endpoint_id": ep.endpoint_id,
                "hostname":    ep.hostname,
                "severity":    "HIGH",
                "reason":      f"High resource usage: cpu={cpu}% mem={mem}%",
                "timestamp":   now_iso,
            }
            _save("alerts", {**alert, "source": "endpoint_telemetry"})
            await sio.emit("endpoint_alert", alert)

        if suspicious_files:
            alert = {
                "endpoint_id": ep.endpoint_id,
                "hostname":    ep.hostname,
                "severity":    "MEDIUM",
                "reason":      f"Suspicious files detected: {suspicious_files[:5]}",
                "timestamp":   now_iso,
            }
            _save("alerts", {**alert, "source": "endpoint_telemetry"})
            await sio.emit("endpoint_alert", alert)

        if suspicious_ports:
            alert = {
                "endpoint_id": ep.endpoint_id,
                "hostname":    ep.hostname,
                "severity":    "MEDIUM",
                "reason":      f"Suspicious ports observed: {suspicious_ports[:10]}",
                "timestamp":   now_iso,
            }
            _save("alerts", {**alert, "source": "endpoint_telemetry"})
            await sio.emit("endpoint_alert", alert)

    asyncio.create_task(_analyze())

    # 4. Decouple heavy ML scoring from the HTTP response.
    #    ACK the agent immediately, then run scoring + fusion in the background
    #    (guarded so ticks can't pile up). This eliminates the ingest timeouts /
    #    "backend unreachable" / connection-reset errors the agent used to log:
    #    scoring latency no longer holds the /endpoint/ingest response open.
    if ep.endpoint_id in _endpoint_scoring_inflight:
        # Previous scoring for this endpoint is still running — drop this tick's
        # scoring (telemetry is already persisted above) to prevent backlog.
        return {"status": "ok", "endpoint_id": ep.endpoint_id, "scored": False}
    _endpoint_scoring_inflight.add(ep.endpoint_id)
    _score_task = asyncio.create_task(_endpoint_score_and_fuse(payload, ep, now_iso))
    _score_task.add_done_callback(
        lambda _t, _eid=ep.endpoint_id: _scoring_task_done(_t, _eid)
    )
    return {"status": "ok", "endpoint_id": ep.endpoint_id, "scored": True}


async def _endpoint_score_and_fuse(payload, ep, now_iso) -> None:
    """Heavy per-endpoint ML scoring + fusion, run as a background task so the
    /endpoint/ingest HTTP response returns immediately (no agent-side timeouts).
    Emits the same Socket.IO events (fusion_alert, user_anomaly, network, …) as
    before — only their timing relative to the ACK changed. The in-flight guard
    in the handler ensures at most one of these runs per endpoint at a time."""
    cpu_val    = payload.system.get("cpu_percent", 0)
    mem_val    = payload.system.get("memory_percent", 0)
    system_data = payload.system
    network_data = payload.network

    ai_scores = await _score_endpoint_telemetry_with_ai(payload, ep.hostname)
    network_score = ai_scores["network_score"]
    system_score  = ai_scores["system_score"]
    malware_score = ai_scores["malware_score"]
    user_score    = ai_scores["user_score"]

    # Update global score cache so the dashboard threat gauge reflects endpoint contributions
    async with _scores_lock:
        if network_score > 0.0:
            _latest_scores["network"] = {"score": network_score, "ts": time.monotonic()}
        if system_score > 0.0:
            _latest_scores["system"]  = {"score": system_score,  "ts": time.monotonic()}
        if malware_score > 0.0:
            _latest_scores["malware"] = {"score": malware_score, "ts": time.monotonic()}
        if user_score > 0.0:
            _latest_scores["user"]    = {"score": user_score,    "ts": time.monotonic()}

    # Derive a meaningful attack_type from the dominant detection model
    _net_detail = ai_scores.get("network_detail", {})
    _mal_detail = ai_scores.get("malware_detail", {})
    _usr_detail = ai_scores.get("user_detail", {})
    _sys_detail = ai_scores.get("system_detail", {})

    if network_score > 0 and network_score >= max(system_score, malware_score, user_score):
        _ml_results = _net_detail.get("ml_results", [])
        _atk_types = [r.get("attack_type", "") for r in _ml_results if r.get("prediction") == "ATTACK" and r.get("attack_type")]
        _endpoint_attack_type = _atk_types[0] if _atk_types else "Network Attack"
    elif malware_score > 0 and malware_score >= max(network_score, system_score, user_score):
        _ep_label = _mal_detail.get("label", "suspicious")
        _endpoint_attack_type = "Malware Activity" if _ep_label == "malicious" else "Suspicious Process Activity"
    elif user_score > 0 and user_score >= max(network_score, system_score, malware_score):
        _endpoint_attack_type = "Insider Threat Indicator"
    elif system_score > 0:
        _sys_sev = _sys_detail.get("severity", "MEDIUM")
        _endpoint_attack_type = "Critical System Anomaly" if _sys_sev in ("HIGH", "CRITICAL") else "System Anomaly"
    else:
        _endpoint_attack_type = "Multi-Domain Threat"

    # Emit system_anomaly for endpoint if genuinely anomalous
    if _sys_detail.get("is_genuinely_anomalous"):
        await sio.emit("system_anomaly", {
            "hostname":               ep.hostname,
            "endpoint_id":            ep.endpoint_id,
            "source":                 "endpoint",
            "cpu_percent":            cpu_val,
            "memory_percent":         mem_val,
            "score":                  system_score,
            "anomaly_score":          system_score,
            "severity":               _sys_detail.get("severity", "MEDIUM"),
            "is_genuinely_anomalous": True,
            "ts":                     now_iso,
        })

    # Always emit user_anomaly for endpoint sessions so User Behavior view stays populated.
    # prediction_label reflects the 0.70 anomaly threshold in score_session_telemetry(),
    # stabilised with hysteresis (kills the per-tick flicker) and gated by snooze.
    _raw_anomaly = bool(_usr_detail.get("anomaly", False))
    _ub_now = time.time()
    _ub_st = _ep_user_state.setdefault(ep.endpoint_id, {})
    _snoozed = _ub_now < _ub_st.get("snooze_until", 0.0)
    if _snoozed:
        _ep_is_anomaly = False                       # silenced by analyst snooze
    elif _raw_anomaly:
        _ub_st["anomaly_until"] = _ub_now + _USER_ANOMALY_STICKY
        _ep_is_anomaly = True
    else:
        _ep_is_anomaly = _ub_now < _ub_st.get("anomaly_until", 0.0)   # sticky hold
    _snooze_remaining = max(0, int(_ub_st.get("snooze_until", 0.0) - _ub_now))
    # When an analyst snoozes this endpoint's insider-threat alarm, the user
    # signal must be neutralised across the WHOLE fusion pipeline — not just the
    # user_anomaly badge — otherwise fusion re-fires every 5-s tick and the
    # siren, "Insider Threat Indicator" correlated alert and auto-response plan
    # keep popping for a user the analyst already acknowledged. Network / system /
    # malware signals are unaffected, so a genuine multi-domain attack still fires.
    _fusion_user_score = 0.0 if _snoozed else user_score
    await sio.emit("user_anomaly", {
        "user":             ep.username,
        "hostname":         ep.hostname,
        "endpoint_id":      ep.endpoint_id,
        "source":           "endpoint",
        "anomaly_score":    user_score,
        "prediction_label": "ANOMALY" if _ep_is_anomaly else "NORMAL",
        "snoozed":          _snoozed,
        "snooze_remaining_s": _snooze_remaining,
        "user_score":           round(float(_usr_detail.get("user_score", user_score)), 4),
        "concurrent_sessions":  int(_usr_detail.get("session_count", _usr_detail.get("concurrent_sessions", 0))),
        "unusual_hour":         1.0 if (_usr_detail.get("unusual_hours_detected") or _usr_detail.get("unusual_hour")) else 0.0,
        "has_remote_session":   1.0 if (int(_usr_detail.get("remote_sessions", 0)) > 0 or _usr_detail.get("has_remote_session")) else 0.0,
        "is_machine_account":   1.0 if str(_usr_detail.get("current_user", ep.username or "")).endswith("$") else 0.0,
        # legacy keys kept for backward compat
        "session_count":        int(_usr_detail.get("session_count", 1)),
        "unusual_hours":        _usr_detail.get("unusual_hours_detected", False),
        "remote_sessions":      int(_usr_detail.get("remote_sessions", 0)),
        "flags":            _usr_detail.get("flags", []),
        "ts":               now_iso,
    })

    # Run unified fusion with the same FusionEngineAgent used by the server-side pipeline
    fusion: Optional[object] = None
    if _fusion_agent:
        fusion = _fusion_agent.fuse(
            network_score=network_score,
            user_score=_fusion_user_score,
            system_score=system_score,
            malware_score=malware_score,
            endpoint_id=ep.endpoint_id,
        )
        logger.info(
            "[ENDPOINT_FUSION] host=%s endpoint=%s severity=%s score=%.3f",
            ep.hostname, ep.endpoint_id, fusion.severity, fusion.threat_score,
        )

    fusion_result: Optional[dict] = fusion.to_dict() if fusion else None

    # Persist to fused_alerts (same collection as server-side fusion)
    if fusion_result:
        _fa_doc = {
            **fusion_result,
            "endpoint_id": ep.endpoint_id,
            "hostname":    ep.hostname,
            "source":      "endpoint_telemetry",
            "ts":          now_iso,
            "ts_dt":       _now_dt(),
        }
        _save("fused_alerts", _fa_doc)
        # Dual-write HIGH/CRITICAL to uncapped permanent evidence store
        if fusion_result.get("severity") in ("HIGH", "CRITICAL"):
            _save("critical_alerts", _fa_doc)

    # Emit fusion_alert for HIGH/CRITICAL so alerts appear in AlertsTable + ResponseModal
    if fusion and fusion.should_respond:
        shap_fusion = _explain_fusion(fusion)
        await sio.emit("fusion_alert", _strip_mongo({
            **fusion_result,
            "source":              "endpoint_telemetry",
            "ts":                  now_iso,
            "shap":                shap_fusion,
            "endpoint_id":         ep.endpoint_id,
            "hostname":            ep.hostname,
            "confidence":          round(fusion.threat_score, 4),
            "attack_type":         _endpoint_attack_type,
            "contributing_signals": fusion.contributing_models,
            "contributing_reasons": fusion.contributing_reasons,
        }))
        # Also trigger response planning (same hook as network pipeline)
        asyncio.create_task(
            _emit_soc_alert_if_correlated(
                {
                    "final_decision": {
                        "threat_score":  fusion.threat_score,
                        "severity":      fusion.severity,
                        "should_respond": True,
                    },
                    "correlation": {
                        "attack_detected":  True,
                        "involved_sources": fusion.contributing_models,
                        "attack_type":      _endpoint_attack_type,
                        "involved_hosts":   [ep.hostname],
                    },
                    "endpoint_id":    ep.endpoint_id,
                    "shap_explanation": shap_fusion if isinstance(shap_fusion, list) else (shap_fusion.get("reason", []) if isinstance(shap_fusion, dict) else []),
                },
                now_iso,
            )
        )

    # Emit endpoint_fusion_alert for backward compatibility (EndpointView panel)
    if fusion_result and fusion_result.get("severity") in ("HIGH", "CRITICAL"):
        await sio.emit("endpoint_fusion_alert", _strip_mongo({
            **fusion_result,
            "endpoint_id": ep.endpoint_id,
            "hostname":    ep.hostname,
        }))

    # Feed global correlation engine only for confirmed HIGH/CRITICAL threats.
    # Gating at 0.70 prevents system-only cpu=100% events from cross-contaminating
    # the server-pipeline correlation window and causing false CRITICAL alerts.
    _ep_fusion_sev = fusion_result.get("severity", "LOW") if fusion_result else "LOW"
    max_score = max(network_score, system_score, malware_score, _fusion_user_score)
    if max_score >= 0.70 and _ep_fusion_sev in ("HIGH", "CRITICAL"):
        most_significant_source = (
            "network" if network_score >= max(system_score, malware_score, _fusion_user_score)
            else "system" if system_score >= max(malware_score, _fusion_user_score)
            else "malware" if malware_score >= _fusion_user_score
            else "user"
        )
        try:
            fe_event = {
                "source":     most_significant_source,
                "timestamp":  now_iso,
                "host":       ep.hostname,
                "severity":   _ep_fusion_sev,
                "confidence": max_score,
                "prediction": fusion_result.get("attack_type", "endpoint_telemetry") if fusion_result else "endpoint_telemetry",
                "endpoint_id": ep.endpoint_id,
            }
            fe_out = await asyncio.to_thread(_fe.ingest_event, fe_event)
            fe_out["endpoint_id"] = ep.endpoint_id   # attach UUID for response plan routing
            await _emit_soc_alert_if_correlated(fe_out, now_iso)
        except Exception as _fe_exc:
            logger.debug(f"endpoint_ingest: global _fe feed failed: {_fe_exc}")

    # Surface individual network flows from endpoint connections (ALL predictions)
    net_detail = ai_scores.get("network_detail", {})
    for ml in net_detail.get("ml_results", [])[:15]:   # cap: 15 flows per 5-s cycle
        is_ep_attack = ml.get("prediction") == "ATTACK"
        ml["endpoint_id"] = ep.endpoint_id
        ml["hostname"]    = ep.hostname
        ml["ts"]          = now_iso
        ml["source"]      = "endpoint_network"
        # Build a RawFlowPayload-compatible dict so the frontend "network" handler
        # can call mapRawToFlow() on it and show it in the Network View table.
        raw_flow = {
            "cycle":                  0,
            "timestamp":              now_iso,
            "ts":                     now_iso,
            "source_ip":              ml.get("src_ip", ep.ip_address or ep.hostname or ""),
            "destination_ip":         ml.get("dest_ip", ml.get("dst_ip", "")),
            "source_port":            int(ml.get("src_port", 0) or 0),
            "destination_port":       int(ml.get("dest_port", 0) or 0),
            "network_transport":      ml.get("protocol", "TCP"),
            "network_protocol":       ml.get("protocol", "TCP"),
            "network_direction":      "outbound",
            "bytes_sent":             int(ml.get("bytes_sent", 0) or 0),
            "bytes_received":         int(ml.get("bytes_received", 0) or 0),
            "packets_sent":           int(ml.get("packets_sent", 0) or 0),
            "packets_received":       int(ml.get("packets_received", 0) or 0),
            "connection_duration":    float(ml.get("duration", 5.0) or 5.0),
            "connection_count":       1,
            "unique_dst_ips":         0,
            "unique_dst_ports":       0,
            "failed_connection_ratio": 0.0,
            "anomaly_score":          float(ml.get("confidence", 0)) / 100.0,
            "confidence":             float(ml.get("confidence", 0)),
            "prediction":             "ANOMALY" if is_ep_attack else "NORMAL",
            "severity":               ml.get("severity", "LOW"),
            "attack_type":            ml.get("attack_type") if is_ep_attack else None,
            "attack_confidence":      float(ml.get("confidence", 0)) if is_ep_attack else None,
            "traffic_label":          ep.hostname,
            "traffic_icon":           "⚠" if is_ep_attack else "📶",
            "traffic_description":    (
                f"Endpoint {ep.hostname}: {ml.get('attack_type', 'network')} traffic"
                if is_ep_attack
                else f"Endpoint {ep.hostname} connection"
            ),
            "traffic_category":       "ATTACK" if is_ep_attack else "NORMAL",
            "endpoint_id":            ep.endpoint_id,
            "hostname":               ep.hostname,
        }
        await sio.emit("network", _strip_mongo(raw_flow))
        if is_ep_attack:
            _save("predictions", ml)
            await sio.emit("network_anomaly", _strip_mongo(ml))
            if _graph_engine:
                try:
                    g_nodes, g_edges = _graph_engine.process_network_anomaly({
                        **ml,
                        "source_ip":      ml.get("src_ip", ""),
                        "destination_ip": ml.get("dst_ip", ml.get("dest_ip", "")),
                    })
                    await _emit_graph_update(g_nodes, g_edges)
                except Exception as _ge:
                    logger.debug(f"[GRAPH] network_anomaly hook error: {_ge}")

    # Write to endpoint_timelines (Gap 3)
    timeline_entry = {
        "endpoint_id": ep.endpoint_id,
        "timestamp": datetime.utcnow().isoformat(),
        "cpu": system_data.get("cpu_percent", 0),
        "memory": system_data.get("memory_percent", 0),
        "connections": len(network_data.get("connections", [])),
        "threat_score": fusion_result.get("threat_score", 0) if fusion_result else 0,
        "severity": fusion_result.get("severity", "LOW") if fusion_result else "LOW",
    }
    _save("endpoint_timelines", timeline_entry)

    # 5. Emit endpoint_update
    # _usr_detail is already extracted above from ai_scores["user_detail"]
    # Guard in case it arrived as a non-dict (exception result)
    if not isinstance(_usr_detail, dict):
        _usr_detail = {}

    # Fetch the registry doc so identity fields preserved by Fix 1 are used when
    # the current payload carries empty strings (e.g. first tick before identity.py
    # has resolved hostname/IP/OS).
    _reg_doc: dict = {}
    if MONGO_OK and _db is not None:
        try:
            _reg_doc = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].find_one(
                    {"endpoint_id": ep.endpoint_id}, {"_id": 0}
                )
            ) or {}
        except Exception:
            pass

    update_event = {
        "endpoint_id": ep.endpoint_id,
        "hostname":    ep.hostname    or _reg_doc.get("hostname",   ep.hostname),
        "ip_address":  ep.ip_address  or _reg_doc.get("ip_address", ""),
        "os":          ep.os          or _reg_doc.get("os",         ""),
        "username":    ep.username    or _reg_doc.get("username",   ""),
        "status":      "online",
        "last_seen":   now_iso,
        "cpu":         cpu_val,
        "memory":      mem_val,
        "user_behavior": {
            "score":               float(_usr_detail.get("user_score", 0.0)),
            "concurrent_sessions": int(_usr_detail.get("session_count", _usr_detail.get("concurrent_sessions", 0))),
            "unusual_hour":        float(_usr_detail.get("unusual_hours_detected", _usr_detail.get("unusual_hour", 0.0))),
            "has_remote_session":  float(_usr_detail.get("remote_sessions", _usr_detail.get("has_remote_session", 0.0))),
            "is_machine_account":  1.0 if str(_usr_detail.get("current_user", "")).endswith("$") else 0.0,
            "current_user":        str(_usr_detail.get("current_user", ep.username or "")),
            "flags":               _usr_detail.get("flags", []),
            "severity":            _usr_detail.get("severity", (
                "HIGH"   if float(_usr_detail.get("user_score", 0.0)) >= 0.70 else
                "MEDIUM" if float(_usr_detail.get("user_score", 0.0)) >= 0.40 else
                "LOW"
            )),
        },
    }
    logger.info(
        "[endpoint AI] user_behavior for %s: score=%.3f sessions=%d user=%s",
        ep.endpoint_id,
        float(_usr_detail.get("user_score", 0)),
        int(_usr_detail.get("session_count", _usr_detail.get("concurrent_sessions", 0))),
        str(_usr_detail.get("current_user", "")),
    )
    await sio.emit("endpoint_update", update_event)

    return {"status": "ok", "endpoint_id": ep.endpoint_id}


@app.get("/endpoint/commands/{endpoint_id}", dependencies=[Depends(_require_key)])
async def endpoint_get_commands(endpoint_id: str):
    """
    Endpoint agent polls here for pending SOAR commands.
    Returns commands with status 'pending', marks them 'sent'.
    """
    if not MONGO_OK or _db is None:
        return {"commands": []}

    now_iso = _now()

    def _fetch_and_mark():
        docs = list(
            _db["endpoint_commands"].find(
                {"endpoint_id": endpoint_id, "status": "pending"}
            )
        )
        ids = [d["_id"] for d in docs]
        if ids:
            from bson import ObjectId as _ObjId
            _db["endpoint_commands"].update_many(
                {"_id": {"$in": ids}},
                {"$set": {"status": "sent", "sent_at": now_iso}},
            )
        return docs

    try:
        raw_docs = await asyncio.to_thread(_fetch_and_mark)
    except Exception as _cmd_err:
        logger.warning("[endpoint/commands] MongoDB unavailable for %s: %s", endpoint_id, _cmd_err)
        return {"commands": []}

    commands = []
    for d in raw_docs:
        commands.append({
            "command_id": str(d["_id"]),
            "action":     d.get("action", ""),
            "target":     d.get("target", ""),
            "parameters": d.get("parameters", {}),
        })

    return {"commands": commands}


@app.post("/endpoint/command/ack", dependencies=[Depends(_require_key)])
async def endpoint_command_ack(payload: EndpointCommandAck):
    """
    Endpoint agent confirms command execution (success or failure).
    Updates endpoint_commands and emits a command_result Socket.IO event.
    """
    if MONGO_OK and _db is not None:
        from bson import ObjectId as _ObjId
        try:
            new_status = "completed" if payload.success else "failed"
            _ack_ts = payload.executed_at or _now()
            await asyncio.to_thread(
                lambda ts=_ack_ts: _db["endpoint_commands"].update_one(
                    {"_id": _ObjId(payload.command_id)},
                    {
                        "$set": {
                            "status": new_status,
                            "ack_result": {
                                "success":     payload.success,
                                "message":     payload.message,
                                "executed_at": ts,
                            },
                            "executed_at":  ts,
                            "completed_at": ts,
                        }
                    },
                )
            )
        except Exception as _ack_err:
            logger.error(f"endpoint command ack update failed: {_ack_err}")

    # Reflect SOAR state changes back into endpoint_registry
    if payload.success and payload.action and MONGO_OK and _db is not None:
        try:
            # Retrieve the original command to get the target (IP / path / PID)
            from bson import ObjectId as _ObjId2  # noqa: PLC0415
            _cmd_doc = await asyncio.to_thread(
                lambda: _db["endpoint_commands"].find_one(
                    {"_id": _ObjId2(payload.command_id)}, {"target": 1}
                )
            )
            _target = (_cmd_doc or {}).get("target", "")

            if payload.action == "block_ip" and _target:
                await asyncio.to_thread(
                    lambda: _db["endpoint_registry"].update_one(
                        {"endpoint_id": payload.endpoint_id},
                        {"$addToSet": {"blocked_ips": _target}},
                    )
                )
            elif payload.action == "unblock_ip" and _target:
                await asyncio.to_thread(
                    lambda: _db["endpoint_registry"].update_one(
                        {"endpoint_id": payload.endpoint_id},
                        {"$pull": {"blocked_ips": _target}},
                    )
                )
            elif payload.action == "isolate_host":
                await asyncio.to_thread(
                    lambda: _db["endpoint_registry"].update_one(
                        {"endpoint_id": payload.endpoint_id},
                        {"$set": {"status": "isolated"}},
                    )
                )
            elif payload.action == "unisolate_host":
                await asyncio.to_thread(
                    lambda: _db["endpoint_registry"].update_one(
                        {"endpoint_id": payload.endpoint_id},
                        {"$set": {"status": "online"}},
                    )
                )

            # Push updated registry doc to frontend so card refreshes immediately
            _updated_ep = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].find_one(
                    {"endpoint_id": payload.endpoint_id}, {"_id": 0}
                )
            )
            if _updated_ep and not _updated_ep.get("is_server"):
                await sio.emit("endpoint_update", _strip_mongo(_updated_ep))

        except Exception as _ep_reg_err:
            logger.debug("[endpoint/ack] registry update failed: %s", _ep_reg_err)

    # Check if all commands for the associated plan are now complete — update plan lifecycle
    if MONGO_OK and _db is not None:
        try:
            # Retrieve the plan_id linked to this command (if any)
            from bson import ObjectId as _ObjId3  # noqa: PLC0415
            _acked_cmd = await asyncio.to_thread(
                lambda: _db["endpoint_commands"].find_one(
                    {"_id": _ObjId3(payload.command_id)}, {"plan_id": 1}
                )
            )
            _linked_plan_id = (_acked_cmd or {}).get("plan_id", "")
            if _linked_plan_id:
                def _check_plan_completion():
                    all_cmds = list(
                        _db["endpoint_commands"].find(
                            {"plan_id": _linked_plan_id},
                            {"status": 1},
                        )
                    )
                    if not all_cmds:
                        return None
                    statuses = {c.get("status", "") for c in all_cmds}
                    # Plan is contained only when every command is terminal
                    terminal = {"completed", "failed"}
                    if statuses.issubset(terminal | {"sent"}):
                        if all(s in {"completed", "sent"} for s in statuses):
                            # All completed (or still in-flight sent) — optimistically mark contained
                            if "failed" not in statuses:
                                return "contained"
                        return "partial"
                    return None  # still executing

                new_plan_status = await asyncio.to_thread(_check_plan_completion)
                if new_plan_status:
                    _plan_upd_at = _now()
                    await asyncio.to_thread(
                        lambda s=new_plan_status: _db["response_plans"].update_one(
                            {"plan_id": _linked_plan_id, "status": {"$in": ["executing", "open"]}},
                            {"$set": {"status": s, "resolved_at": _plan_upd_at}},
                        )
                    )
                    logger.info(
                        "[RESPONSE] Plan %s status → %s (triggered by ack of cmd %s)",
                        _linked_plan_id, new_plan_status, payload.command_id,
                    )
                    # Playbook versioning: non-blocking audit entry for contained/partial
                    async def _write_contained_audit(
                        _pid=_linked_plan_id,
                        _status=new_plan_status,
                        _cmd_id=payload.command_id,
                        _ep_id=payload.endpoint_id,
                    ) -> None:
                        try:
                            _db["audit_logs"].insert_one({
                                "action":      "response_plan_contained",
                                "plan_id":     _pid,
                                "endpoint_id": _ep_id,
                                "new_status":  _status,
                                "triggered_by_command": _cmd_id,
                                "timestamp":   datetime.now(timezone.utc),
                                "user_id":     "system",
                            })
                        except Exception as _cae:
                            logger.debug("[RESPONSE] audit_log (contained) write failed: %s", _cae)
                    asyncio.create_task(_write_contained_audit())

                    # Bug-1 fix: regenerate the incident-report PDF now that all
                    # remote-endpoint commands have reached a terminal status.
                    # The initial PDF was generated immediately after queuing and
                    # captured every command as "pending"; now we overwrite it with
                    # final completed/failed statuses.
                    # Only do this when an incident_reports doc already exists for
                    # the plan (i.e. an auto-generated report was created earlier).
                    async def _maybe_regen_pdf(
                        _pid=_linked_plan_id,
                    ) -> None:
                        try:
                            # Check whether an auto-generated report exists
                            _ir_doc = await asyncio.to_thread(
                                lambda: _db["incident_reports"].find_one(
                                    {"plan_id": _pid},
                                    {"_id": 0},
                                    sort=[("_id", DESCENDING)],
                                )
                            )
                            if _ir_doc is None:
                                return  # no prior report — nothing to regenerate

                            _reuse_incident_id = _ir_doc["incident_id"]

                            # Re-fetch plan and final command statuses
                            _fresh_plan = await asyncio.to_thread(
                                lambda: _db["response_plans"].find_one(
                                    {"plan_id": _pid}, {"_id": 0}
                                )
                            )
                            if _fresh_plan is None:
                                return

                            _fresh_cmds = await asyncio.to_thread(
                                lambda: list(
                                    _db["endpoint_commands"]
                                    .find({"plan_id": _pid}, {"_id": 0})
                                    .sort("created_at", DESCENDING)
                                    .limit(50)
                                )
                            )

                            _ep_id = _fresh_plan.get("endpoint_id", "unknown")
                            _alert_doc = {
                                "incident_id":      _reuse_incident_id,
                                "endpoint_id":      _ep_id,
                                "attack_type":      _fresh_plan.get("attack_type", "Unknown"),
                                "severity":         _fresh_plan.get("severity", "HIGH"),
                                "threat_score":     _fresh_plan.get("threat_score", 0.0),
                                "shap_explanation": _fresh_plan.get("shap_explanation", []),
                                "src_ip":           _fresh_plan.get("src_ip", ""),
                                "timestamp":        _now(),
                            }
                            _ep_info = {"hostname": _ep_id, "ip_address": "N/A"}

                            new_pdf_path = await asyncio.to_thread(
                                generate_incident_report,
                                _reuse_incident_id,
                                _alert_doc,
                                _fresh_plan,
                                _fresh_cmds,
                                "Auto-Response System",
                                _ep_info,
                                "system",
                            )
                            if new_pdf_path:
                                logger.info(
                                    "[RESPONSE] Regenerated PDF for incident %s after plan %s → %s",
                                    _reuse_incident_id, _pid, new_plan_status,
                                )
                                await sio.emit("report_generated", {
                                    "incident_id": _reuse_incident_id,
                                    "auto":        True,
                                    "regenerated": True,
                                })
                        except Exception as _regen_err:
                            logger.warning(
                                "[RESPONSE] PDF regeneration after plan completion failed: %s",
                                _regen_err,
                            )

                    asyncio.create_task(_maybe_regen_pdf())
        except Exception as _plan_ack_err:
            logger.debug(f"[RESPONSE] plan lifecycle update on ack failed: {_plan_ack_err}")

    result_event = {
        "command_id":  payload.command_id,
        "endpoint_id": payload.endpoint_id,
        "action":      payload.action or "unknown",
        "status":      "completed" if payload.success else "failed",
        "success":     payload.success,
        "message":     payload.message,
        "result_message": payload.message,
        "target":      getattr(payload, "target", "") or "",
    }
    await sio.emit("command_result", result_event)

    # Attack graph: add response_action node for completed SOAR commands
    if _graph_engine and payload.success:
        _resp_cmd = {
            "endpoint_id":    payload.endpoint_id,
            "action":         payload.action or "unknown",
            "command_id":     payload.command_id,
            "status":         "completed",
            "result_message": payload.message or "",
        }
        try:
            g_nodes, g_edges = _graph_engine.process_response_action(_resp_cmd)
            await _emit_graph_update(g_nodes, g_edges)
        except Exception as _ge:
            logger.debug(f"[GRAPH] response_action hook error: {_ge}")
        asyncio.create_task(asyncio.to_thread(
            _graph_engine.ingest_to_incident, "response", _resp_cmd
        ))

    await sio.emit("endpoint_command_status", {
        "endpoint_id": payload.endpoint_id,
        "command_id":  payload.command_id,
        "action":      payload.action or "unknown",
        "status":      "completed" if payload.success else "failed",
        "timestamp":   _now(),
    })

    return {"status": "ok"}


@app.post("/endpoint/command", dependencies=[Depends(_require_key_or_jwt)])
async def endpoint_send_command(payload: SendCommand, request: Request):
    """
    Dashboard or SOAR engine issues a command to a specific endpoint.
    Validates action and endpoint_id existence, inserts into endpoint_commands,
    and emits a command_queued Socket.IO event.

    AuthZ: API key OR a JWT with analyst/admin role. Viewer-role JWTs receive
    HTTP 403 — closes the gap where a signed-in viewer could bypass the hidden
    UI and issue SOAR commands (incl. shutdown_host/sleep_host) directly.
    """
    # Enforce analyst/admin role for JWT callers. API-key callers (trusted
    # automation) return role=None here and are allowed through.
    _jwt_role = _decode_jwt_role(request)
    if _jwt_role is not None and _jwt_role not in ("admin", "analyst"):
        raise HTTPException(
            status_code=403,
            detail=f"Analyst or admin role required to issue endpoint commands. Your role: {_jwt_role}",
        )

    # Validate action
    if payload.action not in _ENDPOINT_VALID_ACTIONS:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action {payload.action!r}. "
                   f"Must be one of: {sorted(_ENDPOINT_VALID_ACTIONS)}",
        )

    # Never allow a power action (shutdown/sleep) to target the SOC/backend host
    # itself — doing so would take the dashboard and detection pipeline offline.
    if payload.action in _POWER_ACTIONS and payload.endpoint_id == "server_host":
        raise HTTPException(
            status_code=400,
            detail=f"Action {payload.action!r} cannot target the SOC server host "
                   f"(server_host). Select a remote endpoint instead.",
        )

    # Validate endpoint exists in registry
    if MONGO_OK and _db is not None:
        try:
            ep_doc = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].find_one(
                    {"endpoint_id": payload.endpoint_id}, {"_id": 0}
                )
            )
        except Exception as _reg_err:
            logger.warning("[endpoint/command] MongoDB unavailable for registry lookup: %s", _reg_err)
            ep_doc = {"endpoint_id": payload.endpoint_id}  # skip 404 check when DB is down
        if ep_doc is None:
            raise HTTPException(
                status_code=404,
                detail=f"endpoint_id={payload.endpoint_id!r} not found in registry",
            )
    else:
        # MongoDB unavailable — allow the command but warn
        logger.warning(
            "MongoDB unavailable: cannot verify endpoint_id for command dispatch"
        )

    now_iso = _now()
    command_doc = {
        "endpoint_id": payload.endpoint_id,
        "action":      payload.action,
        "target":      payload.target,
        "parameters":  payload.parameters,
        "status":      "pending",
        "created_at":  now_iso,
        "issued_by":   payload.issued_by,
    }

    inserted_id = None
    if MONGO_OK and _db is not None:
        try:
            result = await asyncio.to_thread(
                lambda: _db["endpoint_commands"].insert_one({**command_doc})
            )
            inserted_id = str(result.inserted_id)
        except Exception as _ins_err:
            logger.error(f"endpoint_commands insert failed: {_ins_err}")

    command_id = inserted_id or "unavailable"
    logger.info(f"[COMMAND] Sent → endpoint={payload.endpoint_id} action={payload.action}")

    queued_event = {
        "endpoint_id": payload.endpoint_id,
        "command_id":  command_id,
        "action":      payload.action,
        "target":      payload.target,
    }
    await sio.emit("command_queued", queued_event)

    return {"status": "ok", "command_id": command_id}


@app.get("/endpoint/list", dependencies=[Depends(_require_key_or_jwt)])
async def endpoint_list(
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    """
    Return all registered endpoints with computed online/offline status.

    Query params (all optional, backward-compatible):
      status — filter by computed status: online | offline | isolated
               Note: 'isolated' is stored in the registry; online/offline are
               computed from last_seen heartbeat timestamp (>30 s = offline).
      search — case-insensitive substring match on hostname or ip_address
    """
    if not MONGO_OK or _db is None:
        return {"endpoints": [], "total": 0}

    cutoff_dt = datetime.utcnow() - timedelta(seconds=15)

    # Build DB-level pre-filter for fields the registry stores directly.
    # online/offline are computed post-fetch (from last_seen), so those are
    # filtered in Python after the heartbeat computation.
    # Always exclude: the backend host itself, and DEMO-* phantom entries created
    # by demonstration attack scripts — they are not real monitored endpoints.
    db_query: dict = {
        "endpoint_id": {"$ne": "server_host"},
        "hostname": {"$not": {"$regex": "^DEMO-", "$options": "i"}},
    }

    # "isolated" status is stored directly in the registry doc
    if status == "isolated":
        db_query["status"] = "isolated"

    if search is not None and search.strip():
        _s = search.strip()
        db_query["$or"] = [
            {"hostname":   {"$regex": _s, "$options": "i"}},
            {"ip_address": {"$regex": _s, "$options": "i"}},
        ]

    def _fetch():
        return list(_db["endpoint_registry"].find(db_query, {"_id": 0}))

    try:
        docs = await asyncio.to_thread(_fetch)
    except Exception as _db_err:
        logger.warning("[endpoint/list] MongoDB unavailable: %s", _db_err)
        return {"endpoints": [], "total": 0}

    # ISO8601 string for this session's start time — used to hide stale registry
    # entries from previous sessions until the agent reconnects.
    _session_start_iso = _backend_session_start.isoformat()

    endpoints = []
    for doc in docs:
        last_seen_raw = doc.get("last_seen", "")
        # Skip endpoints that have not sent any telemetry since this backend
        # process started — they are phantom entries from a previous session.
        if not last_seen_raw or last_seen_raw.rstrip("Z").replace("+00:00", "") < _session_start_iso:
            continue
        # Compute live online/offline from heartbeat; preserve "isolated" if set
        stored_status = doc.get("status", "offline")
        if stored_status == "isolated":
            computed_status = "isolated"
        else:
            try:
                ls_str = last_seen_raw.rstrip("Z").replace("+00:00", "")
                ls_dt = datetime.fromisoformat(ls_str)
                future_guard = datetime.utcnow() + timedelta(seconds=60)
                computed_status = "offline" if (ls_dt < cutoff_dt or ls_dt > future_guard) else "online"
            except Exception:
                computed_status = "offline"

        # Apply post-compute status filter for online/offline
        if status is not None and status != "isolated" and computed_status != status:
            continue

        endpoints.append({
            "endpoint_id":   doc.get("endpoint_id", ""),
            "hostname":      doc.get("hostname", ""),
            "ip_address":    doc.get("ip_address", ""),
            "os":            doc.get("os", ""),
            "username":      doc.get("username", ""),
            "status":        computed_status,
            "last_seen":     last_seen_raw,
            "agent_version": doc.get("agent_version", ""),
        })

    return {"endpoints": endpoints, "total": len(endpoints)}


@app.post("/endpoint/disconnect", dependencies=[Depends(_require_key)])
async def endpoint_disconnect(body: dict = Body(...)):
    """
    Called by the endpoint agent on clean shutdown (Ctrl+C / service stop).
    Immediately marks the endpoint offline in MongoDB and emits an
    endpoint_offline Socket.IO event so the SOC dashboard updates instantly
    without waiting for the next heartbeat cycle.
    """
    endpoint_id = body.get("endpoint_id", "").strip()
    if not endpoint_id:
        raise HTTPException(400, "endpoint_id required")

    if MONGO_OK and _db is not None:
        def _mark_offline():
            return _db["endpoint_registry"].find_one_and_update(
                {"endpoint_id": endpoint_id},
                {"$set": {"status": "offline"}},
                return_document=True,
            )
        try:
            doc = await asyncio.to_thread(_mark_offline)
        except Exception as _dc_err:
            logger.warning("[endpoint/disconnect] MongoDB unavailable: %s", _dc_err)
            doc = None
    else:
        doc = {"endpoint_id": endpoint_id, "hostname": endpoint_id}

    hostname = doc.get("hostname", endpoint_id) if doc else endpoint_id
    logger.info("[endpoint/disconnect] %s (%s) disconnected cleanly", endpoint_id, hostname)

    await sio.emit("endpoint_offline", {
        "endpoint_id": endpoint_id,
        "hostname":    hostname,
        "reason":      "clean_shutdown",
        "timestamp":   datetime.utcnow().isoformat(),
    })

    return {"status": "ok", "endpoint_id": endpoint_id}


@app.post("/endpoint/honeypot", dependencies=[Depends(_require_key)])
async def endpoint_honeypot(body: dict = Body(...)):
    """
    Receive decoy-port honeypot hits from an endpoint agent. A connection to a
    decoy port is a HIGH-confidence intrusion signal (nothing legitimate ever
    touches it), so each hit is persisted to `honeypot_events`, surfaced to the
    SOC via `honeypot_alert` + `endpoint_alert`, and the attacker IP is made
    available for a Block IP SOAR action. Phase 1 = detect + alert (no auto-block).
    """
    endpoint_id = str(body.get("endpoint_id", "")).strip()
    hostname = str(body.get("hostname", endpoint_id))
    hits = body.get("hits", [])
    if not endpoint_id:
        raise HTTPException(400, "endpoint_id required")
    if not isinstance(hits, list) or not hits:
        return {"status": "ok", "stored": 0}

    now_iso = _now()
    docs = []
    attacker_ips = set()
    for h in hits:
        if not isinstance(h, dict):
            continue
        ip = str(h.get("attacker_ip", "")).strip()
        if ip:
            attacker_ips.add(ip)
        docs.append({
            "endpoint_id":   endpoint_id,
            "hostname":      hostname,
            "decoy_port":    h.get("decoy_port"),
            "service":       str(h.get("service", "")),
            "attacker_ip":   ip,
            "attacker_port": h.get("attacker_port"),
            "data_preview":  str(h.get("data_preview", ""))[:200],
            "count":         int(h.get("count", 1) or 1),
            "timestamp":     str(h.get("timestamp", now_iso)),
            "last_seen":     str(h.get("last_seen", h.get("timestamp", now_iso))),
            "received_at":   now_iso,
            "ts_dt":         _now_dt(),
            "severity":      "HIGH",
        })

    if MONGO_OK and _db is not None and docs:
        try:
            await asyncio.to_thread(lambda: _db["honeypot_events"].insert_many([dict(d) for d in docs]))
            # Stamp the registry so the endpoint card can show recent deception activity.
            await asyncio.to_thread(lambda: _db["endpoint_registry"].update_one(
                {"endpoint_id": endpoint_id},
                {"$set": {"last_honeypot_hit": now_iso},
                 "$inc": {"honeypot_hit_count": len(docs)}},
            ))
        except Exception as _hp_exc:
            logger.warning("[endpoint/honeypot] persist failed: %s", _hp_exc)

    ports = sorted({d["decoy_port"] for d in docs if d.get("decoy_port") is not None})
    logger.warning(
        "[HONEYPOT] %s (%s): %d hit(s) from %d attacker IP(s) on ports %s",
        endpoint_id, hostname, len(docs), len(attacker_ips), ports,
    )

    # Dedicated event for the deception panel. Each hit doc carries a `ts_dt`
    # datetime (for MongoDB TTL); Socket.IO JSON-encodes the payload and a raw
    # datetime is NOT serializable, which previously raised
    # "TypeError: Object of type datetime is not JSON serializable", 500'd this
    # endpoint, and stopped honeypot hits from ever reaching the dashboard. Emit
    # a JSON-safe copy of the hits with `ts_dt` removed (the UI uses the string
    # timestamp / last_seen fields, not ts_dt).
    _socket_hits = [{k: v for k, v in d.items() if k != "ts_dt"} for d in docs]
    await sio.emit("honeypot_alert", _strip_mongo({
        "endpoint_id":   endpoint_id,
        "hostname":      hostname,
        "hits":          _socket_hits,
        "attacker_ips":  sorted(attacker_ips),
        "decoy_ports":   ports,
        "count":         len(docs),
        "timestamp":     now_iso,
    }))

    # Also surface in the existing Endpoint Alerts stream so it is impossible to miss.
    _ips_str = ", ".join(sorted(attacker_ips)) or "unknown"
    await sio.emit("endpoint_alert", {
        "endpoint_id": endpoint_id,
        "hostname":    hostname,
        "severity":    "HIGH",
        "alert_type":  "Honeypot / Deception",
        "attack_type": "Decoy-Port Probe",
        "message":     f"Honeypot triggered — {_ips_str} probed decoy port(s) {ports}",
        "src_ip":      sorted(attacker_ips)[0] if attacker_ips else "",
        "timestamp":   now_iso,
    })

    return {"status": "ok", "stored": len(docs), "attacker_ips": sorted(attacker_ips)}


@app.get("/endpoint/honeypot/{endpoint_id}", dependencies=[Depends(_require_key_or_jwt)])
async def endpoint_honeypot_history(endpoint_id: str, limit: int = 100):
    """Return recent honeypot hits for one endpoint plus a summary, for the SOC
    deception panel. Newest first."""
    limit = max(1, min(int(limit), 500))
    if not MONGO_OK or _db is None:
        return {"endpoint_id": endpoint_id, "events": [], "summary": {}}
    try:
        events = await asyncio.to_thread(lambda: list(
            _db["honeypot_events"]
            .find({"endpoint_id": endpoint_id}, {"_id": 0})
            .sort("_id", DESCENDING)
            .limit(limit)
        ))
    except Exception as _hh_exc:
        logger.warning("[endpoint/honeypot history] query failed: %s", _hh_exc)
        return {"endpoint_id": endpoint_id, "events": [], "summary": {}}

    attackers = sorted({e.get("attacker_ip", "") for e in events if e.get("attacker_ip")})
    ports = sorted({e.get("decoy_port") for e in events if e.get("decoy_port") is not None})
    total_hits = sum(int(e.get("count", 1) or 1) for e in events)
    summary = {
        "total_records":  len(events),
        "total_hits":     total_hits,
        "unique_attackers": len(attackers),
        "attacker_ips":   attackers,
        "decoy_ports":    ports,
        "last_seen":      events[0].get("received_at") if events else None,
    }
    return {"endpoint_id": endpoint_id, "events": events, "summary": summary}


@app.get("/endpoint/{endpoint_id}", dependencies=[Depends(_require_key_or_jwt)])
async def endpoint_detail(endpoint_id: str):
    """
    Return full detail for a single endpoint: registry doc + last 20 logs
    + last 10 commands.
    """
    if not MONGO_OK or _db is None:
        raise HTTPException(503, "MongoDB unavailable")

    def _fetch():
        reg = _db["endpoint_registry"].find_one(
            {"endpoint_id": endpoint_id}, {"_id": 0}
        )
        logs = list(
            _db["endpoint_logs"]
            .find({"endpoint_id": endpoint_id}, {"_id": 0})
            .sort("timestamp", DESCENDING)
            .limit(20)
        )
        cmds = list(
            _db["endpoint_commands"]
            .find({"endpoint_id": endpoint_id})
            .sort("created_at", DESCENDING)
            .limit(10)
        )
        return reg, logs, cmds

    try:
        registry_doc, recent_logs, recent_commands = await asyncio.to_thread(_fetch)
    except Exception as _db_err:
        logger.warning("[endpoint/detail] MongoDB unavailable: %s", _db_err)
        raise HTTPException(503, "Database temporarily unavailable")

    if registry_doc is None:
        raise HTTPException(404, f"endpoint_id={endpoint_id!r} not found")

    # Convert ObjectId to string for commands
    for cmd in recent_commands:
        cmd["command_id"] = str(cmd.pop("_id", ""))

    return {
        "endpoint":          registry_doc,
        "recent_logs":       recent_logs,
        "recent_commands":   recent_commands,
    }


# ---------------------------------------------------------------------------
# Endpoint timeline — Gap 3
# ---------------------------------------------------------------------------

@app.get("/endpoint/timeline/{endpoint_id}", dependencies=[Depends(_require_key_or_jwt)])
async def endpoint_timeline(endpoint_id: str, limit: int = 100):
    """
    Return endpoint time-series telemetry for the threat sparkline.
    Queries endpoint_timelines (cpu, memory, connections, threat_score, severity)
    sorted oldest-first so the sparkline renders chronologically.
    """
    if not MONGO_OK or _db is None:
        return {"timeline": []}

    safe_limit = min(limit, 500)

    def _fetch():
        return list(
            _db["endpoint_timelines"]
            .find({"endpoint_id": endpoint_id}, {"_id": 0})
            .sort("timestamp", ASCENDING)
            .limit(safe_limit)
        )

    try:
        docs = await asyncio.to_thread(_fetch)
    except Exception as _db_err:
        logger.warning("[endpoint/timeline] MongoDB unavailable: %s", _db_err)
        return {"timeline": []}
    return {"timeline": docs}


# ---------------------------------------------------------------------------
# EDR Orchestration — Response Plan & Incident Report endpoints
# ---------------------------------------------------------------------------

def _decode_jwt_role(request: Request) -> Optional[str]:
    """
    Decode the Bearer JWT from the Authorization header and return the 'role'
    claim, or None if the header is absent / token is invalid.
    Never raises.
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return None
        from auth.security import decode_token as _decode_tok  # noqa: PLC0415
        payload = _decode_tok(token, settings.jwt_secret_key, settings.jwt_algorithm)
        return str(payload.get("role", "")) or None
    except Exception:
        return None


def _decode_jwt_username(request: Request) -> Optional[str]:
    """
    Decode the Bearer JWT from the Authorization header and return the 'sub'
    (username / email) claim, or None if the header is absent / token is invalid.
    Never raises.  API-key callers will receive None — callers should substitute
    a sensible default (e.g. "SOC Analyst") when None is returned.
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return None
        from auth.security import decode_token as _decode_tok  # noqa: PLC0415
        payload = _decode_tok(token, settings.jwt_secret_key, settings.jwt_algorithm)
        return str(payload.get("sub", "")) or None
    except Exception:
        return None


def _require_admin_role_if_jwt(request: Request, credentials: str) -> None:
    """
    When the caller authenticated via JWT (not API key), enforce admin role.
    Raises HTTP 403 if a JWT is present but the role is not 'admin'.
    API-key callers bypass this check entirely (they are trusted automation).
    """
    if credentials == "api_key":
        # API key callers are always allowed — they are trusted service accounts
        return
    # JWT path — must be admin
    role = _decode_jwt_role(request)
    if role != "admin":
        raise HTTPException(
            status_code=403,
            detail="Admin role required for this operation",
        )


@app.post("/response/plan")
async def create_response_plan(
    request: Request,
    credentials: str = Depends(_require_key_or_jwt),
):
    """
    Generate and store an intelligent MITRE ATT&CK-mapped response plan
    from a fusion alert body.

    Request body mirrors the generate_response_plan() input:
        {
          "endpoint_id": str,
          "severity": "LOW"|"MEDIUM"|"HIGH"|"CRITICAL",
          "attack_type": str,
          "contributing_signals": list,
          "shap_explanation": list,
          "threat_score": float
        }
    """
    body = await request.json()

    # --- Input validation ---
    _VALID_SEVERITIES = frozenset({"LOW", "MEDIUM", "HIGH", "CRITICAL"})
    raw_severity = str(body.get("severity", "")).strip().upper()
    if raw_severity and raw_severity not in _VALID_SEVERITIES:
        raise HTTPException(
            status_code=422,
            detail=f"Invalid severity {raw_severity!r}. "
                   f"Must be one of: {sorted(_VALID_SEVERITIES)}",
        )
    endpoint_id_val = str(body.get("endpoint_id", "")).strip()
    if not endpoint_id_val:
        raise HTTPException(
            status_code=422,
            detail="endpoint_id is required and must not be empty",
        )
    attack_type_val = str(body.get("attack_type", "")).strip()
    if not attack_type_val:
        raise HTTPException(
            status_code=422,
            detail="attack_type is required and must not be empty",
        )

    plan = generate_response_plan(body)

    # Persist non-blocking
    asyncio.create_task(_save_response_plan(plan))

    await sio.emit("response_plan_ready", _strip_mongo(plan))
    logger.info(
        f"[RESPONSE] Plan created via API: plan_id={plan['plan_id']} "
        f"endpoint={plan['endpoint_id']} severity={plan['severity']}"
    )

    # Audit: response plan created
    _rplan_username = _jwt_sub_from_request(request) or "api_key"
    _rplan_ip = request.client.host if request.client else "unknown"
    _rplan_audit_doc = {
        "user":      _rplan_username,
        "action":    "response_plan_created",
        "timestamp": _now(),
        "ip":        _rplan_ip,
        "detail":    (
            f"Response plan created for {plan['endpoint_id']} — "
            f"{plan['attack_type']} severity={plan['severity']}"
        ),
        "status":    "success",
    }
    asyncio.create_task(sio.emit("audit_event", _rplan_audit_doc))
    if MONGO_OK and _db is not None:
        async def _write_rplan_audit():
            try:
                await asyncio.to_thread(lambda: _db["audit_logs"].insert_one(dict(_rplan_audit_doc)))
            except Exception:
                pass
        asyncio.create_task(_write_rplan_audit())

    return plan


@app.post("/response/execute")
async def execute_response(
    request: Request,
    credentials: str = Depends(_require_key_or_jwt),
):
    """
    Execute a set of SOAR actions on a specific endpoint.
    Admin or analyst JWT role required (API key always allowed).

    Request body:
        {
          "endpoint_id": str,
          "actions": [{"action": str, "target": str}],
          "plan_id": str,           # optional — links commands back to a response plan
          "issued_by": str          # analyst username
        }
    """
    # Analyst or admin role required when using JWT
    if credentials != "api_key":
        role = _decode_jwt_role(request)
        if role not in ("admin", "analyst"):
            raise HTTPException(
                status_code=403,
                detail="Admin or analyst role required to execute response actions",
            )

    body = await request.json()
    endpoint_id = str(body.get("endpoint_id", ""))
    actions = body.get("actions", [])
    plan_id = str(body.get("plan_id", ""))
    issued_by = str(body.get("issued_by", ""))

    if not endpoint_id:
        raise HTTPException(status_code=400, detail="endpoint_id is required")
    if not isinstance(actions, list) or len(actions) == 0:
        raise HTTPException(status_code=400, detail="actions list is required and must not be empty")

    # Split incoming actions into executable (forwarded to endpoint agent)
    # and advisory (logged server-side, never sent to agent).
    executable_action_defs = []
    advisory_action_defs = []
    for a in actions:
        if not isinstance(a, dict):
            continue
        name = a.get("action", "")
        if name in _ADVISORY_ACTIONS:
            advisory_action_defs.append(a)
        else:
            executable_action_defs.append(a)

    # Validate only the executable actions against the hard allowed-set
    invalid = [
        a.get("action", "")
        for a in executable_action_defs
        if a.get("action", "") not in _ENDPOINT_VALID_ACTIONS
    ]
    if invalid:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid action(s): {invalid}. "
                   f"Allowed: {sorted(_ENDPOINT_VALID_ACTIONS)}",
        )

    now_iso = _now()
    command_ids: list = []

    # --- Executable actions → endpoint_commands collection ---
    for action_def in executable_action_defs:
        action = str(action_def.get("action", ""))
        target = str(action_def.get("target", ""))

        command_doc = {
            "endpoint_id":   endpoint_id,
            "action":        action,
            "target":        target,
            "payload":       action_def.get("payload", {}),
            "issued_by":     issued_by,
            "status":        "pending",
            "result_log":    [],
            "created_at":    now_iso,
            "executed_at":   None,
            "plan_id":       plan_id,
        }

        inserted_id: Optional[str] = None
        if MONGO_OK and _db is not None:
            try:
                result = await asyncio.to_thread(
                    lambda doc=command_doc: _db["endpoint_commands"].insert_one({**doc})
                )
                inserted_id = str(result.inserted_id)
            except Exception as _ins_err:
                logger.error(f"[RESPONSE] endpoint_commands insert failed: {_ins_err}")

        command_ids.append(inserted_id or "unavailable")

    # --- Advisory actions → response_advisory_logs collection (acknowledged immediately) ---
    advisory_names: list = []
    for action_def in advisory_action_defs:
        action_name = str(action_def.get("action", ""))
        advisory_names.append(action_name)
        advisory_doc = {
            "endpoint_id": endpoint_id,
            "action":      action_name,
            "target":      str(action_def.get("target", "")),
            "plan_id":     plan_id,
            "issued_by":   issued_by,
            "created_at":  now_iso,
            "status":      "acknowledged",
        }
        if MONGO_OK and _db is not None:
            try:
                await asyncio.to_thread(
                    lambda doc=advisory_doc: _db["response_advisory_logs"].insert_one({**doc})
                )
            except Exception as _adv_err:
                logger.error(f"[RESPONSE] response_advisory_logs insert failed: {_adv_err}")

    # Update response plan status to "executing" now that commands have been queued
    if plan_id and MONGO_OK and _db is not None:
        try:
            await asyncio.to_thread(
                lambda: _db["response_plans"].update_one(
                    {"plan_id": plan_id},
                    {"$set": {"status": "executing", "executing_at": now_iso}},
                )
            )
            logger.info("[RESPONSE] Plan %s status → executing", plan_id)
        except Exception as _plan_upd_err:
            logger.error(f"[RESPONSE] plan status update to executing failed: {_plan_upd_err}")

        # Playbook versioning: write a non-blocking audit entry for the execution event
        if MONGO_OK and _db is not None:
            async def _write_execute_audit() -> None:
                try:
                    _jwt_uid = _decode_jwt_username(request) or issued_by or "system"
                    _req_ip = _get_client_ip(request)
                    _audit_doc = {
                        "action":         "response_plan_executed",
                        "plan_id":        plan_id,
                        "endpoint_id":    endpoint_id,
                        "actions_queued": [a.get("action", "") for a in executable_action_defs],
                        "advisory_actions": advisory_names,
                        "ip":             _req_ip,
                        "timestamp":      datetime.now(timezone.utc),
                        "user_id":        _jwt_uid,
                    }
                    _db["audit_logs"].insert_one(_audit_doc)
                except Exception as _ae:
                    logger.debug("[RESPONSE] audit_log (execute) write failed: %s", _ae)
            asyncio.create_task(_write_execute_audit())

    await sio.emit("response_executed", _strip_mongo({
        "endpoint_id":     endpoint_id,
        "actions":         [a.get("action", "") for a in executable_action_defs],
        "advisory_actions": advisory_names,
        "plan_id":         plan_id,
        "command_ids":     command_ids,
        "issued_by":       issued_by,
        "ts":              now_iso,
    }))

    # Forensic audit trail for analyst-triggered SOAR queuing
    _resp_actor = issued_by or _decode_jwt_username(request) or "analyst"
    for _action_def in executable_action_defs:
        asyncio.create_task(_write_soar_audit_event(
            action=_action_def.get("action", ""),
            target=str(_action_def.get("target", "")),
            endpoint_id=endpoint_id,
            success=True,   # command queued successfully (execution result comes via ACK)
            message=f"Command queued for endpoint {endpoint_id} (plan_id={plan_id})",
            duration_ms=0.0,
            actor=_resp_actor,
        ))

    logger.info(
        f"[RESPONSE] Execute request: endpoint={endpoint_id} "
        f"executable={[a.get('action') for a in executable_action_defs]} "
        f"advisory={advisory_names} "
        f"plan_id={plan_id} issued_by={issued_by}"
    )
    return {
        "success":          True,
        "command_ids":      command_ids,
        "advisory_actions": advisory_names,
        "message":          (
            f"{len(command_ids)} command(s) queued, "
            f"{len(advisory_names)} advisory action(s) logged"
        ),
    }


@app.get("/response/plans")
async def list_response_plans(
    limit: int = 20,
    credentials: str = Depends(_require_key_or_jwt),
):
    """Return the last N response plans from MongoDB, sorted newest-first."""
    limit = max(1, min(limit, 500))

    if not MONGO_OK or _db is None:
        return {"plans": [], "total": 0, "mongo_ok": False}

    try:
        total = _db["response_plans"].count_documents({})
        docs = list(
            _db["response_plans"]
            .find({}, {"_id": 0})
            .sort("created_at", DESCENDING)
            .limit(limit)
        )
    except Exception as exc:
        logger.error(f"[RESPONSE] response_plans query failed: {exc}")
        return {"plans": [], "total": 0, "error": str(exc)}

    return {"plans": docs, "total": total}


@app.post("/reports/generate")
async def create_incident_report(
    request: Request,
    credentials: str = Depends(_require_key_or_jwt),
):
    """
    Generate a PDF incident report for a specific response plan.
    Admin role required when using JWT auth.

    Request body:
        {
          "plan_id": str,
          "admin_name": str,
          "incident_id": str  (optional — auto-generated if absent)
        }
    """
    _require_admin_role_if_jwt(request, credentials)

    body = await request.json()
    plan_id = str(body.get("plan_id", ""))
    # Derive admin_name from JWT claims (server-side) so callers cannot impersonate.
    # Fall back to the request body value only for API-key callers (no JWT present),
    # and ultimately to "SOC Analyst" if neither source provides a name.
    jwt_username = _decode_jwt_username(request)
    # jwt_username is the user's MongoDB ObjectId string (from JWT sub claim).
    # Look up the real display name from the users collection.
    _display_name = jwt_username
    if MONGO_OK and _db is not None and jwt_username:
        try:
            from bson import ObjectId as _ObjId
            _oid = _ObjId(jwt_username) if len(jwt_username) == 24 else None
            _user_doc = _db["users"].find_one(
                {"_id": _oid} if _oid is not None else {"_id": jwt_username},
                {"username": 1, "email": 1},
            )
            if _user_doc:
                _display_name = (
                    _user_doc.get("username")
                    or _user_doc.get("email")
                    or jwt_username
                )
        except Exception:
            pass
    admin_name = _display_name or str(body.get("admin_name", "")) or "SOC Analyst"
    # Derive role from JWT for the certification block; API-key callers use "admin".
    jwt_role = _decode_jwt_role(request) or "admin"
    incident_id = str(body.get("incident_id", "") or _uuid.uuid4())

    if not plan_id:
        raise HTTPException(status_code=400, detail="plan_id is required")

    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable — cannot fetch plan data")

    # Fetch the response plan
    plan_doc = await asyncio.to_thread(
        lambda: _db["response_plans"].find_one({"plan_id": plan_id}, {"_id": 0})
    )
    if plan_doc is None:
        raise HTTPException(status_code=404, detail=f"Response plan {plan_id!r} not found")

    endpoint_id = plan_doc.get("endpoint_id", "")
    severity = plan_doc.get("severity", "UNKNOWN")
    attack_type = plan_doc.get("attack_type", "Unknown")

    # Fetch the most recent fused_alert scoped to this endpoint (prevents
    # cross-endpoint data leakage when multiple endpoints are in the system).
    alert_doc = await asyncio.to_thread(
        lambda: _db["fused_alerts"].find_one(
            {"endpoint_id": endpoint_id},
            {"_id": 0},
            sort=[("_id", DESCENDING)],
        )
    ) or {}

    # Merge plan fields into alert for comprehensive reporting
    merged_alert = {
        **alert_doc,
        "endpoint_id":  endpoint_id,
        "severity":     severity,
        "attack_type":  attack_type,
        "threat_score": plan_doc.get("threat_score", alert_doc.get("threat_score", 0.0)),
        "shap_explanation": plan_doc.get("shap_explanation", []),
        "contributing_signals": plan_doc.get("contributing_signals", []),
        "ts": plan_doc.get("created_at", _now()),
    }

    # Fetch endpoint registry info
    endpoint_info = await asyncio.to_thread(
        lambda: _db["endpoint_registry"].find_one(
            {"endpoint_id": endpoint_id}, {"_id": 0}
        )
    ) or {"hostname": endpoint_id, "ip_address": "N/A"}

    # Fetch execution results (endpoint_commands linked to this plan)
    execution_results = await asyncio.to_thread(
        lambda: list(
            _db["endpoint_commands"]
            .find({"plan_id": plan_id}, {"_id": 0})
            .sort("created_at", DESCENDING)
            .limit(50)
        )
    )

    # Generate the PDF (blocking I/O — run in thread)
    try:
        pdf_path = await asyncio.to_thread(
            generate_incident_report,
            incident_id,
            merged_alert,
            plan_doc,
            execution_results,
            admin_name,
            endpoint_info,
            jwt_role,
        )
    except ImportError as exc:
        raise HTTPException(
            status_code=503,
            detail=f"reportlab not installed: {exc}. Run: pip install reportlab>=4.0.0",
        )
    except Exception as exc:
        logger.error(f"[REPORT] PDF generation failed for incident {incident_id}: {exc}")
        raise HTTPException(status_code=500, detail=f"PDF generation failed: {exc}")

    now_iso = _now()
    report_meta = {
        "incident_id":    incident_id,
        "plan_id":        plan_id,
        "endpoint_id":    endpoint_id,
        "severity":       severity,
        "attack_type":    attack_type,
        "pdf_path":       pdf_path,
        "generated_by":   admin_name,
        "generated_at":   now_iso,
        # BSON-native datetime for reliable sort/TTL index queries
        "generated_at_dt": _now_dt(),
        "status":         "generated",
    }
    _save("incident_reports", report_meta)

    # Strip pdf_path (absolute FS path) and generated_at_dt (BSON datetime, not JSON-safe)
    # from the socket payload before broadcasting to browser sessions.
    _STRIP_FROM_SOCKET = {"pdf_path", "generated_at_dt"}
    report_meta_public = {k: v for k, v in report_meta.items() if k not in _STRIP_FROM_SOCKET}
    await sio.emit("report_generated", _strip_mongo(report_meta_public))
    logger.info(
        f"[REPORT] Incident report generated: incident_id={incident_id} "
        f"plan_id={plan_id} path={pdf_path}"
    )

    # Audit: report generated
    _report_username = _jwt_sub_from_request(request) or "api_key"
    _report_ip = request.client.host if request.client else "unknown"
    _report_audit_doc = {
        "user":      _report_username,
        "action":    "report_generated",
        "timestamp": _now(),
        "ip":        _report_ip,
        "detail":    f"Incident report generated: {incident_id}",
        "status":    "success",
    }
    asyncio.create_task(sio.emit("audit_event", _report_audit_doc))
    if MONGO_OK and _db is not None:
        async def _write_report_audit():
            try:
                await asyncio.to_thread(lambda: _db["audit_logs"].insert_one(dict(_report_audit_doc)))
            except Exception:
                pass
        asyncio.create_task(_write_report_audit())

    # Embed PDF content as base64 so the frontend can download without a
    # second HTTP request (avoids CORS preflight issues with binary GETs).
    import base64 as _b64
    try:
        with open(pdf_path, "rb") as _f:
            pdf_content_b64 = _b64.b64encode(_f.read()).decode("utf-8")
    except Exception as _read_exc:
        logger.warning(f"[REPORT] Could not read PDF for b64 embed: {_read_exc}")
        pdf_content_b64 = ""

    download_url = f"/reports/{incident_id}/download"
    return {
        "incident_id":      incident_id,
        "pdf_path":         pdf_path,
        "download_url":     download_url,
        "generated_at":     now_iso,
        "pdf_content_b64":  pdf_content_b64,
    }


@app.get("/reports/{incident_id}/download")
async def download_incident_report(
    request: Request,
    incident_id: str,
    credentials: str = Depends(_require_key_or_jwt),
):
    """Serve the generated PDF for the specified incident as a file download.
    Requires analyst or admin JWT role (API-key callers are always permitted).
    """
    if credentials != "api_key":
        role = _decode_jwt_role(request)
        if role not in ("admin", "analyst"):
            raise HTTPException(
                status_code=403,
                detail="Analyst or admin role required to download incident reports",
            )
    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    # Bug-3 fix: wrap both the MongoDB query and the filesystem check in
    # try/except to match the hardening style applied to the other 6 endpoint
    # handlers.  An unhandled ServerSelectionTimeoutError from pymongo becomes
    # a bare 500 that strips CORS headers in transit, reaching the browser as a
    # "Network Error" with no status code — the identical symptom that triggered
    # the hardening pass on endpoint_get_commands / endpoint_list / etc.
    try:
        report_meta = await asyncio.to_thread(
            lambda: _db["incident_reports"].find_one(
                {"incident_id": incident_id}, {"_id": 0}
            )
        )
    except Exception as _db_err:
        logger.warning("[REPORTS] MongoDB error fetching incident_id=%s: %s", incident_id, _db_err)
        raise HTTPException(
            status_code=503,
            detail="MongoDB temporarily unavailable — please retry",
        )

    if report_meta is None:
        raise HTTPException(status_code=404, detail=f"Incident report {incident_id!r} not found")

    pdf_path = report_meta.get("pdf_path", "")
    try:
        _file_exists = bool(pdf_path) and Path(pdf_path).is_file()
    except Exception as _fs_err:
        logger.warning("[REPORTS] Filesystem check failed for path=%r: %s", pdf_path, _fs_err)
        raise HTTPException(
            status_code=500,
            detail="Could not access report file",
        )

    if not _file_exists:
        raise HTTPException(
            status_code=404,
            detail=f"PDF file not found on disk (path: {pdf_path!r}). "
                   "Report may have been deleted or generation failed.",
        )

    return FileResponse(
        path=pdf_path,
        media_type="application/pdf",
        filename=f"incident_{incident_id}.pdf",
    )


# ── Attack Graph REST endpoints ───────────────────────────────────────────────

@app.get("/attack-graph/snapshot")
async def get_attack_graph_snapshot(
    hours: int = 1,
    min_score: float = 0.70,
    _auth=Depends(_require_key_or_jwt),
):
    """
    Return graph nodes and edges built from HIGH/CRITICAL fusion alerts in the
    last N hours (default 2 hours, max 168).

    Query params:
      hours     — lookback window in hours (1–168, default 2)
      min_score — minimum threat_score to include (0.0–1.0, default 0.70)

    Each alert produces:
      • one alert node  (id: "alert_<mongo_id>")
      • one endpoint node (id: "endpoint_<endpoint_id>")
      • one directed edge between them (type: "triggered")

    Node metadata includes attack_type, threat_score, severity, endpoint_id,
    hostname, timestamp, sources, mitre_technique, and a shap list built from
    either a matching shap_explanations document or a synthetic score-based
    fallback.

    Capped at 50 nodes (25 alerts) to prevent visual clutter.
    """
    if _db is None:
        return {"nodes": [], "edges": [], "total": 0}

    try:
        from datetime import timedelta as _td
        cutoff = datetime.utcnow() - _td(hours=max(0.1, min(float(hours), 168.0)))
        cutoff_str = cutoff.isoformat()
        nodes: list = []
        edges: list = []
        seen: set = set()

        def _add_node(n: dict) -> None:
            nid = n.get("node_id")
            if nid and nid not in seen:
                seen.add(nid)
                nodes.append(n)

        # ── 1. XDR Server node (always present) ───────────────────────────────
        _add_node({
            "node_id": "ep-server_host",
            "type": "endpoint",
            "label": "XDR Server",
            "risk_score": 5,
            "severity": "LOW",
            "endpoint_id": "server_host",
            "timestamp": datetime.utcnow().isoformat(),
            "metadata": {"status": "online", "role": "xdr_server"},
        })

        # ── 2. Online endpoints from registry ─────────────────────────────────
        try:
            # Strict online check: endpoint must have checked in within last 60s.
            # The endpoint agent heartbeats every 5s; heartbeat_loop marks offline
            # after 35s.  The `hours` parameter controls alert history, not
            # which endpoints are currently considered "online".
            online_cutoff = (datetime.utcnow() - _td(seconds=60)).isoformat()
            for ep in _db["endpoint_registry"].find(
                {
                    "last_seen": {"$gte": online_cutoff},
                    "endpoint_id": {"$ne": "server_host"},
                    "hostname": {"$not": {"$regex": "^DEMO-", "$options": "i"}},
                },
                {"_id": 0},
            ).limit(20):
                ep_id = ep.get("endpoint_id", "")
                nid = f"ep-{ep_id}"
                _add_node({
                    "node_id": nid,
                    "type": "endpoint",
                    "label": ep.get("hostname") or ep_id or "Endpoint",
                    "risk_score": 10,
                    "severity": ep.get("status", "LOW").upper() if ep.get("status") in ("HIGH", "CRITICAL") else "LOW",
                    "endpoint_id": ep_id,
                    "timestamp": ep.get("last_seen", datetime.utcnow().isoformat()),
                    "metadata": {
                        "ip": ep.get("ip_address", ""),
                        "os": ep.get("os", ""),
                        "username": ep.get("username", ""),
                        "status": ep.get("status", "online"),
                    },
                })
                # Edge: server monitors this endpoint
                edges.append({
                    "edge_id": f"ep-server_host->{nid}:monitors",
                    "source": "ep-server_host",
                    "target": nid,
                    "relation": "monitors",
                    "timestamp": datetime.utcnow().isoformat(),
                    "metadata": {"severity": "LOW"},
                })
        except Exception as _e:
            logger.warning(f"[snapshot] registry: {_e}")

        # ── 3. Threat nodes from attack_graph_nodes (risk_score stored 0-100) ─
        try:
            score_threshold = float(min_score) * 100  # convert 0-1 → 0-100
            for n in _db["attack_graph_nodes"].find(
                {
                    "last_updated": {"$gte": cutoff_str},
                    # Exclude nodes from DEMO-* phantom endpoints
                    "endpoint_id": {"$not": {"$regex": "^demo-", "$options": "i"}},
                    "$or": [
                        {"type": "endpoint"},          # all endpoint nodes
                        {"risk_score": {"$gte": score_threshold}},  # alert/IP/process above threshold
                    ],
                },
                {"_id": 0},
            ).sort("last_updated", -1).limit(50):
                _add_node(n)
        except Exception as _e:
            logger.warning(f"[snapshot] graph_nodes: {_e}")

        # ── 4. High-severity alerts from fused_alerts (belt-and-suspenders) ───
        try:
            for col in ("critical_alerts", "fused_alerts"):
                col_results = list(_db[col].find(
                    {
                        "ts_dt": {"$gte": cutoff},
                        "threat_score": {"$gte": float(min_score)},
                        "severity": {"$in": ["HIGH", "CRITICAL"]},
                        # Exclude alerts from DEMO-* phantom endpoints
                        "hostname": {"$not": {"$regex": "^DEMO-", "$options": "i"}},
                    },
                    {"_id": 0},
                ).sort("ts_dt", -1).limit(25))
                if not col_results:
                    continue
                for alert in col_results:
                    ep_id = alert.get("endpoint_id", "server_host")
                    alert_nid = f"alert-{alert.get('attack_type','unknown').lower().replace(' ','_')}-{ep_id}"
                    ep_nid = f"ep-{ep_id}"
                    _add_node({
                        "node_id": alert_nid,
                        "type": "alert",
                        "label": alert.get("attack_type") or "ALERT",
                        "risk_score": int((alert.get("threat_score") or 0) * 100),
                        "severity": alert.get("severity", "MEDIUM"),
                        "endpoint_id": ep_id,
                        "timestamp": alert.get("ts") or alert.get("timestamp") or datetime.utcnow().isoformat(),
                        "metadata": {
                            "attack_type": alert.get("attack_type"),
                            "sources": alert.get("sources", []),
                            "shap_reasons": alert.get("shap_explanation", {}).get("reasons", []) if isinstance(alert.get("shap_explanation"), dict) else [],
                        },
                    })
                    # Edge: endpoint triggered this alert
                    if ep_nid in seen or ep_id == "server_host":
                        _edge_src = ep_nid if ep_nid in seen else "ep-server_host"
                        edges.append({
                            "edge_id": f"{_edge_src}->{alert_nid}:triggered",
                            "source": _edge_src,
                            "target": alert_nid,
                            "relation": "triggered",
                            "timestamp": alert.get("ts") or datetime.utcnow().isoformat(),
                            "metadata": {"severity": alert.get("severity", "HIGH")},
                        })
                break  # use whichever collection had results
        except Exception as _e:
            logger.warning(f"[snapshot] alerts: {_e}")

        # ── 5. Edges from attack_graph_edges ──────────────────────────────────
        try:
            if seen:
                for e in _db["attack_graph_edges"].find(
                    {
                        "source": {"$in": list(seen)},
                        "timestamp": {"$gte": cutoff_str},
                    },
                    {"_id": 0},
                ).sort("timestamp", -1).limit(100):
                    if e.get("target") in seen:
                        edges.append(e)
        except Exception as _e:
            logger.warning(f"[snapshot] graph_edges: {_e}")

        # Deduplicate edges by (source, target, relation)
        seen_edges: set = set()
        deduped_edges = []
        for e in edges:
            ek = (e.get("source"), e.get("target"), e.get("relation"))
            if ek not in seen_edges:
                seen_edges.add(ek)
                deduped_edges.append(e)

        return {
            "nodes": nodes,
            "edges": deduped_edges,
            "total": len(nodes),
            "meta": {"hours": hours, "min_score": min_score, "cutoff": cutoff_str},
        }

    except Exception as exc:
        logger.error(f"[snapshot] unhandled: {exc}", exc_info=True)
        return {"nodes": [], "edges": [], "total": 0}


@app.post("/attack-graph/clear", dependencies=[Depends(_require_key_or_jwt)])
async def clear_attack_graph(
    request: Request,
    credentials: str = Depends(_require_key_or_jwt),
):
    """
    Admin/analyst: wipe the in-memory and MongoDB attack graph state.
    Emits ``graph_update_remove`` Socket.IO event with all cleared node IDs
    so connected frontends immediately remove stale nodes from their canvas.

    Auth: valid X-API-Key OR JWT with admin or analyst role.
    """
    # JWT callers must hold admin or analyst role
    if credentials != "api_key":
        _role = _decode_jwt_role(request)
        if _role not in ("admin", "analyst"):
            raise HTTPException(
                status_code=403,
                detail="admin or analyst role required to clear the attack graph",
            )

    removed_ids: list = []

    # ── 1. Wipe MongoDB collections ──────────────────────────────────────────
    if _db is not None:
        try:
            def _clear_graph_db():
                nodes = list(_db["attack_graph_nodes"].find({}, {"node_id": 1}))
                ids = [n.get("node_id") for n in nodes if n.get("node_id")]
                _db["attack_graph_nodes"].delete_many({})
                _db["attack_graph_edges"].delete_many({})
                return ids
            removed_ids = await asyncio.to_thread(_clear_graph_db)
        except Exception as _e:
            logger.warning("[GRAPH-CLEAR] DB wipe failed: %s", _e)

    # ── 2. Clear in-memory graph engine state ────────────────────────────────
    if _graph_engine is not None:
        try:
            _graph_engine._graph.clear()
        except Exception as _eg:
            logger.debug("[GRAPH-CLEAR] in-memory graph clear error: %s", _eg)

    # ── 3. Notify all connected clients ──────────────────────────────────────
    if removed_ids:
        await sio.emit("graph_update_remove", {"node_ids": removed_ids})

    _actor = _decode_jwt_username(request) or "api_key"
    logger.info(
        "[GRAPH-CLEAR] Attack graph cleared by %s — %d nodes removed",
        _actor, len(removed_ids),
    )
    return {"cleared": True, "nodes_removed": len(removed_ids)}


@app.get("/attack-graph/timeline")
async def get_attack_graph_timeline(
    hours: int = 24,
    _auth=Depends(_require_key_or_jwt),
):
    """Return node and edge creation events sorted by timestamp for attack replay."""
    if _graph_engine is None:
        return {"events": []}
    hours = max(1, min(hours, 168))
    return {"events": _graph_engine.get_timeline(hours=hours)}


# ── Incident Correlation REST endpoints ──────────────────────────────────────

@app.get("/incidents", dependencies=[Depends(_require_key_or_jwt)])
async def list_incidents(hours: int = 48, limit: int = 50):
    """List correlated incidents sorted newest-first."""
    if not _graph_engine:
        return {"incidents": [], "total": 0}
    incidents = await asyncio.to_thread(
        _graph_engine.get_incidents, hours, min(limit, 200)
    )
    return {"incidents": incidents, "total": len(incidents)}


@app.get("/incidents/{incident_id}", dependencies=[Depends(_require_key_or_jwt)])
async def get_incident(incident_id: str):
    """Full incident detail: metadata + timeline + attached graph nodes/edges."""
    if not _graph_engine:
        raise HTTPException(503, "Graph engine not initialized")
    doc = await asyncio.to_thread(_graph_engine.get_incident, incident_id)
    if not doc:
        raise HTTPException(404, f"Incident {incident_id} not found")
    return doc


@app.get("/incidents/{incident_id}/replay", dependencies=[Depends(_require_key_or_jwt)])
async def incident_replay(incident_id: str):
    """
    Return chronologically ordered replay steps for movie-mode investigation.
    Each step: { step, timestamp, kind, event_type, attack_type, severity,
                 mitre_technique, tactic, description, source_layer }
    """
    if not _graph_engine:
        raise HTTPException(503, "Graph engine not initialized")
    doc = await asyncio.to_thread(_graph_engine.get_incident, incident_id)
    if not doc:
        raise HTTPException(404, f"Incident {incident_id} not found")

    graph    = doc.get("graph", {"nodes": [], "edges": []})
    timeline = doc.get("timeline", [])

    steps = []
    for i, t in enumerate(sorted(timeline, key=lambda x: x.get("timestamp", ""))):
        steps.append({
            "step":            i + 1,
            "timestamp":       t.get("timestamp"),
            "kind":            "timeline",
            "event_type":      t.get("event_type"),
            "attack_type":     t.get("attack_type"),
            "severity":        t.get("severity"),
            "mitre_technique": t.get("mitre_technique"),
            "tactic":          t.get("tactic"),
            "description":     t.get("description"),
            "source_layer":    t.get("source_layer"),
        })

    return {
        "incident_id":  incident_id,
        "total_steps":  len(steps),
        "steps":        steps,
        "graph":        graph,
        "metadata": {
            "title":            doc.get("title"),
            "severity":         doc.get("severity"),
            "attack_type":      doc.get("attack_type"),
            "mitre_techniques": doc.get("mitre_techniques", []),
            "source_layers":    doc.get("source_layers", []),
            "root_cause":       doc.get("root_cause"),
            "affected_assets":  doc.get("affected_assets", []),
            "created_at":       doc.get("created_at"),
            "last_event_at":    doc.get("last_event_at"),
        },
    }


@app.get("/reports")
async def list_incident_reports(
    limit: int = 20,
    skip: int = 0,
    credentials: str = Depends(_require_key_or_jwt),
):
    """Return the list of generated incident reports from MongoDB, newest-first."""
    limit = max(1, min(limit, 200))
    skip = max(0, min(skip, 10_000))  # cap to prevent full-collection scan abuse

    if not MONGO_OK or _db is None:
        return {"reports": [], "total": 0, "mongo_ok": False}

    try:
        total = _db["incident_reports"].count_documents({})
        # Sort by BSON datetime first (present on newer docs), then ISO string fallback.
        # Exclude internal BSON datetime and _id fields from the JSON response.
        docs_raw = list(
            _db["incident_reports"]
            .find({}, {"_id": 0, "generated_at_dt": 0})
            .sort([("generated_at_dt", DESCENDING), ("generated_at", DESCENDING)])
            .skip(skip)
            .limit(limit)
        )
        # Coerce any remaining datetime objects to ISO strings so JSONResponse never
        # fails with "datetime is not JSON serializable".
        docs = [
            {
                k: (v.isoformat() if hasattr(v, "isoformat") else v)
                for k, v in d.items()
            }
            for d in docs_raw
        ]
    except Exception as exc:
        logger.error(f"[REPORT] incident_reports query failed: {exc}")
        return {"reports": [], "total": 0, "error": str(exc)}

    return {"reports": docs, "total": total}


# ---------------------------------------------------------------------------
# Auth helpers — admin-only and analyst-or-admin JWT dependencies
# ---------------------------------------------------------------------------

async def _require_admin_jwt(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
) -> str:
    """
    Dependency: require either a valid API key OR a JWT with role=='admin'.

    Returns 'api_key' or 'jwt_admin'.
    Raises HTTP 403 when a JWT is present but the role is not 'admin'.
    Raises HTTP 401 when a Bearer token is present but invalid/expired.
    Raises HTTP 403 when no credentials at all.
    """
    # 1. API key path — trusted service accounts bypass role enforcement
    if api_key == settings.api_key:
        return "api_key"

    # 2. JWT path
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="Bearer token is empty")
        try:
            from auth.security import decode_token as _decode  # noqa: PLC0415
            payload = _decode(token, settings.jwt_secret_key, settings.jwt_algorithm)
            if payload.get("type") != "access" or not payload.get("sub"):
                raise HTTPException(status_code=401, detail="Invalid token type or subject")
            if payload.get("role") != "admin":
                raise HTTPException(
                    status_code=403,
                    detail="Admin role required for this endpoint",
                )
            return "jwt_admin"
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="JWT token is invalid or expired")

    raise HTTPException(
        status_code=403,
        detail="Provide a valid X-API-Key header or a Bearer JWT token with admin role",
    )


async def _require_analyst_or_admin_jwt(
    request: Request,
    api_key: Optional[str] = Security(_api_key_header),
) -> str:
    """
    Dependency: require either a valid API key OR a JWT with role in {analyst, admin}.

    Returns 'api_key', 'jwt_analyst', or 'jwt_admin'.
    Raises HTTP 403 for viewer-role JWTs or missing credentials.
    """
    # 1. API key path
    if api_key == settings.api_key:
        return "api_key"

    # 2. JWT path
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            raise HTTPException(status_code=401, detail="Bearer token is empty")
        try:
            from auth.security import decode_token as _decode  # noqa: PLC0415
            payload = _decode(token, settings.jwt_secret_key, settings.jwt_algorithm)
            if payload.get("type") != "access" or not payload.get("sub"):
                raise HTTPException(status_code=401, detail="Invalid token type or subject")
            role = payload.get("role", "viewer")
            if role not in ("admin", "analyst"):
                raise HTTPException(
                    status_code=403,
                    detail=f"Analyst or admin role required. Your role: {role}",
                )
            return f"jwt_{role}"
        except HTTPException:
            raise
        except Exception:
            raise HTTPException(status_code=401, detail="JWT token is invalid or expired")

    raise HTTPException(
        status_code=403,
        detail="Provide a valid X-API-Key header or a Bearer JWT token (analyst or admin role)",
    )


def _jwt_sub_from_request(request: Request) -> Optional[str]:
    """
    Extract the 'sub' (username/email) claim from the Bearer JWT.
    Returns None on any error — never raises.
    """
    try:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return None
        token = auth_header.removeprefix("Bearer ").strip()
        if not token:
            return None
        from auth.security import decode_token as _dec  # noqa: PLC0415
        payload = _dec(token, settings.jwt_secret_key, settings.jwt_algorithm)
        return str(payload.get("sub", "")) or None
    except Exception:
        return None


def _jwt_user_id_from_request(request: Request) -> Optional[str]:
    """
    Extract the 'sub' user_id claim (MongoDB ObjectId string) from the Bearer JWT.
    Returns None on any error — never raises.
    """
    return _jwt_sub_from_request(request)


# ---------------------------------------------------------------------------
# Group 1 — Settings / Thresholds
# ---------------------------------------------------------------------------

_DEFAULT_THRESHOLDS = {
    "network_anomaly_threshold":  0.70,
    "system_anomaly_threshold":   0.50,
    "fusion_critical_threshold":  0.85,
    "fusion_high_threshold":      0.70,
    "malware_threshold":          0.70,
    "user_behavior_threshold":    0.80,
}

# Module-level mutable threshold variables — updated at runtime by POST /settings/thresholds
# and loaded from MongoDB on startup so they survive server restarts.
_network_anomaly_threshold: float = 0.70
_system_anomaly_threshold:  float = 0.50
_malware_threshold:         float = 0.70
_user_behavior_threshold:   float = 0.80
_auto_response_enabled: bool = True   # controlled via POST /settings/thresholds


class ThresholdSettings(BaseModel):
    network_anomaly_threshold: float = Field(ge=0.40, le=0.90)
    system_anomaly_threshold:  float = Field(ge=0.35, le=0.85)
    fusion_critical_threshold: float = Field(ge=0.70, le=0.95)
    fusion_high_threshold:     float = Field(ge=0.50, le=0.85)
    malware_threshold:         float = Field(default=0.70, ge=0.10, le=0.99)
    user_behavior_threshold:   float = Field(default=0.80, ge=0.10, le=0.99)
    auto_response_enabled:     bool  = Field(default=True)


# ---------------------------------------------------------------------------
# User Behavior Rules — admin-configurable heuristic ruleset for the user model.
# Defaults come from the agent (single source of truth: _DEFAULT_USER_RULES).
# Persisted in `settings` collection (key="user_behavior_rules") and pushed into
# the live UserBehaviorAgent via apply_rules().
# ---------------------------------------------------------------------------
class UserBehaviorRules(BaseModel):
    enabled:                   bool  = Field(default=True)
    business_hours_start:      int   = Field(default=6,  ge=0, le=23)
    business_hours_end:        int   = Field(default=23, ge=1, le=24)
    flag_weekends:             bool  = Field(default=False)
    after_hours_weight:        float = Field(default=0.0,  ge=0.0, le=1.0)
    max_concurrent_sessions:   int   = Field(default=3,  ge=1, le=50)
    excess_sessions_weight:    float = Field(default=0.30, ge=0.0, le=1.0)
    max_remote_sessions:       int   = Field(default=2,  ge=0, le=50)
    remote_after_hours_weight: float = Field(default=0.50, ge=0.0, le=1.0)
    system_account_weight:     float = Field(default=0.60, ge=0.0, le=1.0)
    rule_anomaly_threshold:    float = Field(default=0.70, ge=0.10, le=1.0)
    watch_accounts:            list  = Field(default_factory=list)

    @validator("business_hours_end")
    def _end_after_start(cls, v, values):  # noqa: N805
        start = values.get("business_hours_start", 6)
        if v <= start:
            raise ValueError("business_hours_end must be greater than business_hours_start")
        return v

    @validator("watch_accounts")
    def _clean_accounts(cls, v):  # noqa: N805
        if not isinstance(v, list):
            return []
        # de-dup, strip, drop blanks, cap at 50 entries
        seen, out = set(), []
        for a in v:
            s = str(a).strip()
            key = s.lower()
            if s and key not in seen:
                seen.add(key)
                out.append(s)
        return out[:50]


# Live copy of the ruleset (mirrors what the agent is using); refreshed on
# startup and on every POST /settings/user-rules.
_user_behavior_rules: dict = dict(_DEFAULT_USER_RULES)


def _load_user_rules_from_db() -> dict:
    """Read the user-behavior ruleset from MongoDB, merged over agent defaults."""
    if not MONGO_OK or _db is None:
        return dict(_DEFAULT_USER_RULES)
    try:
        doc = _db["settings"].find_one({"key": "user_behavior_rules"}, {"_id": 0})
        if doc:
            merged = dict(_DEFAULT_USER_RULES)
            merged.update({k: v for k, v in doc.items()
                           if k in _DEFAULT_USER_RULES and v is not None})
            return merged
    except Exception as exc:
        logger.debug(f"[SETTINGS] user rules load failed: {exc}")
    return dict(_DEFAULT_USER_RULES)


def _load_thresholds_from_db() -> dict:
    """Read the current thresholds document from MongoDB, falling back to defaults."""
    if not MONGO_OK or _db is None:
        return dict(_DEFAULT_THRESHOLDS)
    try:
        doc = _db["settings"].find_one({"key": "thresholds"}, {"_id": 0})
        if doc:
            merged = dict(_DEFAULT_THRESHOLDS)
            merged.update({k: v for k, v in doc.items() if k != "key"})
            return merged
    except Exception as exc:
        logger.debug(f"[SETTINGS] thresholds load failed: {exc}")
    return dict(_DEFAULT_THRESHOLDS)


@app.get("/settings", dependencies=[Depends(_require_key_or_jwt)])
async def get_settings():
    """
    Return current XDR threshold configuration.
    Auth: valid API key OR any JWT (any role).
    """
    thresholds = await asyncio.to_thread(_load_thresholds_from_db)
    return {
        "status": "ok",
        "thresholds": thresholds,
        "mongo_ok": MONGO_OK,
    }


@app.post("/settings/thresholds")
async def update_thresholds(
    request: Request,
    body: ThresholdSettings,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Update detection thresholds.  Admin JWT (or API key) required.
    Immediately applies fusion high/critical thresholds in-memory.
    Persists all four values to the 'settings' MongoDB collection.
    """
    threshold_doc = {
        "key":                       "thresholds",
        "network_anomaly_threshold": body.network_anomaly_threshold,
        "system_anomaly_threshold":  body.system_anomaly_threshold,
        "fusion_critical_threshold": body.fusion_critical_threshold,
        "fusion_high_threshold":     body.fusion_high_threshold,
        "malware_threshold":         body.malware_threshold,
        "user_behavior_threshold":   body.user_behavior_threshold,
        "auto_response_enabled":     body.auto_response_enabled,
        "updated_at":                _now(),
    }

    # Persist to MongoDB (upsert)
    if MONGO_OK and _db is not None:
        try:
            await asyncio.to_thread(
                lambda: _db["settings"].update_one(
                    {"key": "thresholds"},
                    {"$set": threshold_doc},
                    upsert=True,
                )
            )
        except Exception as exc:
            logger.error(f"[SETTINGS] threshold upsert failed: {exc}")

    # Apply in-memory — update FusionEngineAgent thresholds immediately
    if _fusion_agent is not None:
        _fusion_agent.high_threshold = body.fusion_high_threshold
        _fusion_agent.critical_threshold = body.fusion_critical_threshold
        logger.info(
            "[SETTINGS] Fusion thresholds updated in-memory: "
            "high=%.2f critical=%.2f",
            body.fusion_high_threshold, body.fusion_critical_threshold,
        )

    # Apply network, system, malware, user behavior, and auto-response thresholds in-memory immediately
    global _network_anomaly_threshold, _system_anomaly_threshold
    global _malware_threshold, _user_behavior_threshold
    global _auto_response_enabled
    _network_anomaly_threshold = body.network_anomaly_threshold
    _system_anomaly_threshold  = body.system_anomaly_threshold
    _malware_threshold         = body.malware_threshold
    _user_behavior_threshold   = body.user_behavior_threshold
    _auto_response_enabled     = body.auto_response_enabled
    logger.info(
        "[SETTINGS] Detection thresholds updated in-memory: "
        "network=%.2f system=%.2f malware=%.2f user=%.2f auto_response=%s",
        _network_anomaly_threshold, _system_anomaly_threshold,
        _malware_threshold, _user_behavior_threshold, _auto_response_enabled,
    )

    # Emit audit_event so the audit panel reflects the admin action
    username = _jwt_sub_from_request(request) or "api_key"
    _client_ip = request.client.host if request.client else "unknown"
    await sio.emit("audit_event", {
        "user":      username,
        "user_id":   username,
        "action":    "thresholds_updated",
        "ip":        _client_ip,
        "timestamp": _now(),
        "status":    "success",
        "details":   (
            f"network={body.network_anomaly_threshold} "
            f"system={body.system_anomaly_threshold} "
            f"fusion_high={body.fusion_high_threshold} "
            f"fusion_critical={body.fusion_critical_threshold} "
            f"malware={body.malware_threshold} "
            f"user={body.user_behavior_threshold} "
            f"auto_response={body.auto_response_enabled}"
        ),
        "detail":    (
            f"network={body.network_anomaly_threshold} "
            f"system={body.system_anomaly_threshold} "
            f"fusion_high={body.fusion_high_threshold} "
            f"fusion_critical={body.fusion_critical_threshold} "
            f"malware={body.malware_threshold} "
            f"user={body.user_behavior_threshold} "
            f"auto_response={body.auto_response_enabled}"
        ),
    })

    logger.info(
        "[SETTINGS] Thresholds saved by user=%s: %s",
        username, threshold_doc,
    )

    return {
        "status": "ok",
        "thresholds": {
            "network_anomaly_threshold": body.network_anomaly_threshold,
            "system_anomaly_threshold":  body.system_anomaly_threshold,
            "fusion_critical_threshold": body.fusion_critical_threshold,
            "fusion_high_threshold":     body.fusion_high_threshold,
            "malware_threshold":         body.malware_threshold,
            "user_behavior_threshold":   body.user_behavior_threshold,
            "auto_response_enabled":     body.auto_response_enabled,
        },
        "message": "Thresholds updated and applied in-memory",
    }


@app.get("/settings/user-rules", dependencies=[Depends(_require_key_or_jwt)])
async def get_user_rules():
    """Return the current User Behavior ruleset (defaults if none saved).
    Auth: valid API key OR any JWT (any role) — viewers may read but not edit."""
    rules = await asyncio.to_thread(_load_user_rules_from_db)
    return {"status": "ok", "rules": rules, "defaults": dict(_DEFAULT_USER_RULES), "mongo_ok": MONGO_OK}


@app.post("/settings/user-rules")
async def update_user_rules(
    request: Request,
    body: UserBehaviorRules,
    credentials: str = Depends(_require_admin_jwt),
):
    """Update the User Behavior heuristic ruleset. Admin JWT (or API key) required.
    Persists to the `settings` collection and pushes the rules into the live
    UserBehaviorAgent immediately (no restart needed)."""
    rules_doc = {"key": "user_behavior_rules", **body.dict(), "updated_at": _now()}

    if MONGO_OK and _db is not None:
        try:
            await asyncio.to_thread(
                lambda: _db["settings"].update_one(
                    {"key": "user_behavior_rules"}, {"$set": rules_doc}, upsert=True,
                )
            )
        except Exception as exc:
            logger.error(f"[SETTINGS] user rules upsert failed: {exc}")

    # Apply in-memory to the live agent immediately.
    global _user_behavior_rules
    _user_behavior_rules = body.dict()
    if _user_agent is not None:
        try:
            _user_agent.apply_rules(_user_behavior_rules)
        except Exception as exc:
            logger.error(f"[SETTINGS] apply_rules failed: {exc}")

    username = _jwt_sub_from_request(request) or "api_key"
    _client_ip = request.client.host if request.client else "unknown"
    _detail = (
        f"enabled={body.enabled} hours={body.business_hours_start}-{body.business_hours_end} "
        f"weekends={body.flag_weekends} max_sessions={body.max_concurrent_sessions} "
        f"max_remote={body.max_remote_sessions} rule_threshold={body.rule_anomaly_threshold} "
        f"watch={len(body.watch_accounts)}"
    )
    await sio.emit("audit_event", {
        "user": username, "user_id": username, "action": "user_rules_updated",
        "ip": _client_ip, "timestamp": _now(), "status": "success",
        "details": _detail, "detail": _detail,
    })
    logger.info("[SETTINGS] User Behavior rules saved by user=%s: %s", username, _detail)

    return {"status": "ok", "rules": body.dict(), "message": "User Behavior rules updated and applied in-memory"}


@app.post("/user-behavior/snooze")
async def snooze_user_behavior(
    request: Request,
    body: dict = Body(...),
    credentials: str = Depends(_require_analyst_or_admin_jwt),
):
    """Snooze the off-hours / insider-threat alarm for one endpoint's user for a
    chosen window (default 60 min). During the snooze the endpoint reports NORMAL
    and no siren fires; when it expires, if the session is still anomalous the
    alarm re-fires automatically. Admin/analyst only.
    Body: {"endpoint_id": str, "minutes": int (optional, default 60)}"""
    endpoint_id = str(body.get("endpoint_id", "")).strip()
    if not endpoint_id:
        raise HTTPException(400, "endpoint_id required")
    try:
        minutes = int(body.get("minutes", 60))
    except (TypeError, ValueError):
        minutes = 60
    minutes = max(1, min(minutes, 1440))   # 1 min .. 24 h

    now = time.time()
    st = _ep_user_state.setdefault(endpoint_id, {})
    st["snooze_until"] = now + minutes * 60
    st["anomaly_until"] = 0.0   # clear sticky hold so it goes NORMAL immediately
    until_iso = datetime.fromtimestamp(st["snooze_until"], tz=timezone.utc).isoformat()

    username = _jwt_sub_from_request(request) or "api_key"
    _ip = request.client.host if request.client else "unknown"
    _audit = {
        "user": username, "user_id": username, "action": "user_behavior_snoozed",
        "ip": _ip, "timestamp": _now(), "status": "success",
        "details": f"endpoint={endpoint_id} minutes={minutes}",
        "detail": f"Snoozed insider-threat alarm for {endpoint_id} ({minutes} min)",
    }
    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(lambda: _db["audit_logs"].insert_one({**_audit})))
    await sio.emit("audit_event", _audit)
    # Tell the dashboard to reflect the snooze immediately.
    await sio.emit("user_behavior_snooze", {
        "endpoint_id": endpoint_id, "minutes": minutes,
        "snooze_until": until_iso, "snooze_remaining_s": minutes * 60,
    })
    logger.info("[UBA] snooze set: endpoint=%s minutes=%d by=%s", endpoint_id, minutes, username)
    return {"status": "ok", "endpoint_id": endpoint_id, "minutes": minutes, "snooze_until": until_iso}


# ---------------------------------------------------------------------------
# Group 2 — User Management (Admin only)
# ---------------------------------------------------------------------------

_VALID_ROLES = frozenset({"admin", "analyst", "viewer"})


class CreateUserPayload(BaseModel):
    username: str = Field(min_length=3, max_length=64)
    email: str = Field(min_length=5, max_length=254)
    password: str = Field(min_length=8)
    role: str = Field(default="viewer")


class ChangeRolePayload(BaseModel):
    role: str


@app.get("/users")
async def list_users(
    request: Request,
    limit: int = 50,
    skip: int = 0,
    role: Optional[str] = None,
    mfa_enabled: Optional[bool] = None,
    locked: Optional[bool] = None,
    search: Optional[str] = None,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Return registered user accounts (paginated) with optional server-side filters.
    Admin role or API key required.

    Query params (all optional, backward-compatible):
      role        — filter by role: admin | analyst | viewer
      mfa_enabled — true = only users with 2FA set up; false = users without
      locked      — true = currently locked-out accounts; false = unlocked
      search      — case-insensitive substring match on email or username
      limit / skip — pagination (max 500)
    """
    if not MONGO_OK or _db is None:
        return {"users": [], "total": 0, "mongo_ok": False}

    limit = max(1, min(limit, 500))
    skip = max(0, skip)

    # Build MongoDB query conditionally — each filter appends to `and_clauses`
    # so that multiple $or filters do not overwrite each other.
    and_clauses: list = []

    if role is not None:
        and_clauses.append({"role": role})

    if mfa_enabled is True:
        and_clauses.append({"two_factor_secret": {"$exists": True, "$ne": None}})
    elif mfa_enabled is False:
        and_clauses.append(
            {"$or": [{"two_factor_secret": {"$exists": False}}, {"two_factor_secret": None}]}
        )

    if locked is True:
        and_clauses.append({"locked_until": {"$gt": datetime.utcnow()}})
    elif locked is False:
        and_clauses.append(
            {"$or": [{"locked_until": {"$exists": False}}, {"locked_until": {"$lte": datetime.utcnow()}}]}
        )

    if search is not None and search.strip():
        _s = search.strip()
        and_clauses.append(
            {"$or": [
                {"email":    {"$regex": _s, "$options": "i"}},
                {"username": {"$regex": _s, "$options": "i"}},
            ]}
        )

    # Collapse: no filters → {}, single clause → that clause,
    # multiple clauses → {"$and": [...]}
    if not and_clauses:
        query: dict = {}
    elif len(and_clauses) == 1:
        query = and_clauses[0]
    else:
        query = {"$and": and_clauses}

    def _fetch():
        total = _db["users"].count_documents(query)
        docs = list(
            _db["users"]
            .find(
                query,
                {
                    "_id": 1,
                    "username": 1,
                    "email": 1,
                    "role": 1,
                    "created_at": 1,
                    "last_login": 1,
                    "two_factor_enabled": 1,
                    "two_factor_secret": 1,
                    "locked_until": 1,
                    "failed_attempts": 1,
                },
            )
            .sort("created_at", DESCENDING)
            .skip(skip)
            .limit(limit)
        )
        return total, docs

    try:
        total, docs = await asyncio.to_thread(_fetch)
    except Exception as exc:
        logger.error(f"[USERS] list_users query failed: {exc}")
        return {"users": [], "total": 0, "error": str(exc)}

    users = []
    now_utc = datetime.utcnow()
    for d in docs:
        lu = d.get("locked_until")
        is_locked = bool(lu and isinstance(lu, datetime) and lu > now_utc)
        users.append({
            "user_id":            str(d["_id"]),
            "username":           d.get("username", ""),
            "email":              d.get("email", ""),
            "role":               d.get("role", "viewer"),
            "created_at":         d.get("created_at", "").isoformat() if hasattr(d.get("created_at"), "isoformat") else str(d.get("created_at", "")),
            "last_login":         d.get("last_login", "").isoformat() if hasattr(d.get("last_login"), "isoformat") else str(d.get("last_login", "") or ""),
            "two_factor_enabled": bool(d.get("two_factor_secret")),
            "is_locked":          is_locked,
        })

    return {"users": users, "total": total}


@app.delete("/users/{user_id}")
async def delete_user(
    request: Request,
    user_id: str,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Delete a user account and cascade-delete all their sessions.
    Admins cannot delete their own account via this endpoint.
    """
    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    from bson import ObjectId as _ObjId  # noqa: PLC0415

    # Determine the calling user's own user_id to prevent self-deletion
    caller_user_id: Optional[str] = None
    if credentials != "api_key":
        # credentials == "jwt_admin" — extract sub from JWT
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from auth.security import decode_token as _dec  # noqa: PLC0415
                tok = auth_header.removeprefix("Bearer ").strip()
                pl = _dec(tok, settings.jwt_secret_key, settings.jwt_algorithm)
                caller_user_id = pl.get("sub")
            except Exception:
                pass

    if caller_user_id and caller_user_id == user_id:
        raise HTTPException(
            status_code=400,
            detail="Administrators cannot delete their own account via this endpoint",
        )

    # Validate target user exists
    try:
        target_user = await asyncio.to_thread(
            lambda: _db["users"].find_one({"_id": _ObjId(user_id)}, {"username": 1, "email": 1})
        )
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid user_id format")

    if target_user is None:
        raise HTTPException(status_code=404, detail=f"User {user_id!r} not found")

    target_username = target_user.get("username", user_id)

    # Cascade-delete sessions
    try:
        sessions_result = await asyncio.to_thread(
            lambda: _db["sessions"].delete_many({"user_id": user_id})
        )
        sessions_deleted = sessions_result.deleted_count
    except Exception as exc:
        logger.error(f"[USERS] session cascade-delete failed for user {user_id}: {exc}")
        sessions_deleted = 0

    # Delete the user document
    try:
        await asyncio.to_thread(
            lambda: _db["users"].delete_one({"_id": _ObjId(user_id)})
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete user: {exc}")

    username = _jwt_sub_from_request(request) or "api_key"
    ip = request.client.host if request.client else "unknown"
    _audit_doc = {
        "user":      username,
        "action":    "user_deleted",
        "timestamp": _now(),
        "status":    "success",
        "detail":    f"Admin '{username}' deleted user '{user_id}'",
        "ip":        ip,
    }
    await sio.emit("audit_event", _audit_doc)
    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(lambda: _db["audit_logs"].insert_one({**_audit_doc})))
    logger.info(
        "[USERS] User deleted: user_id=%s username=%s by=%s sessions_deleted=%d",
        user_id, target_username, username, sessions_deleted,
    )

    return {
        "status": "ok",
        "user_id": user_id,
        "username": target_username,
        "sessions_deleted": sessions_deleted,
    }


@app.post("/users/{user_id}/role")
async def change_user_role(
    request: Request,
    user_id: str,
    body: ChangeRolePayload,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Change the role of a specific user.
    Admin role or API key required.
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role {body.role!r}. Must be one of: {sorted(_VALID_ROLES)}",
        )

    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    from bson import ObjectId as _ObjId  # noqa: PLC0415

    try:
        result = await asyncio.to_thread(
            lambda: _db["users"].update_one(
                {"_id": _ObjId(user_id)},
                {"$set": {"role": body.role, "role_updated_at": _now()}},
            )
        )
    except Exception as exc:
        raise HTTPException(status_code=400, detail=f"Invalid user_id or DB error: {exc}")

    if result.matched_count == 0:
        raise HTTPException(status_code=404, detail=f"User {user_id!r} not found")

    username = _jwt_sub_from_request(request) or "api_key"
    ip = request.client.host if request.client else "unknown"

    # Look up the target user's display name for a human-readable audit trail
    _target_doc = (
        _db["users"].find_one({"_id": _ObjId(user_id)}, {"username": 1, "email": 1})
        if MONGO_OK and _db is not None else None
    )
    _target_name = (_target_doc or {}).get("username") or (_target_doc or {}).get("email") or user_id

    _audit_doc = {
        "user":      username,
        "action":    "role_changed",
        "timestamp": _now(),
        "status":    "success",
        "detail":    f"Admin '{username}' changed role of '{_target_name}' to '{body.role}'",
        "ip":        ip,
    }
    await sio.emit("audit_event", _audit_doc)
    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(lambda: _db["audit_logs"].insert_one({**_audit_doc})))
    logger.info("[USERS] Role changed: user_id=%s new_role=%s by=%s", user_id, body.role, username)

    return {"status": "ok", "user_id": user_id, "new_role": body.role}


@app.post("/users/{user_id}/force-logout")
async def force_logout_user(
    request: Request,
    user_id: str,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Invalidate all sessions for a specific user (force-logout everywhere).
    Admin role or API key required.
    """
    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    try:
        result = await asyncio.to_thread(
            lambda: _db["sessions"].delete_many({"user_id": user_id})
        )
        sessions_deleted = result.deleted_count
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to invalidate sessions: {exc}")

    username = _jwt_sub_from_request(request) or "api_key"
    ip = request.client.host if request.client else "unknown"

    from bson import ObjectId as _ObjId  # noqa: PLC0415
    _target_doc = (
        _db["users"].find_one({"_id": _ObjId(user_id)}, {"username": 1, "email": 1})
        if MONGO_OK and _db is not None else None
    )
    _target_name = (_target_doc or {}).get("username") or (_target_doc or {}).get("email") or user_id

    _audit_doc = {
        "user":      username,
        "action":    "force_logout",
        "timestamp": _now(),
        "status":    "success",
        "detail":    f"Admin '{username}' force-logged-out '{_target_name}' ({sessions_deleted} session(s) invalidated)",
        "ip":        ip,
    }
    await sio.emit("audit_event", _audit_doc)
    if MONGO_OK and _db is not None:
        asyncio.create_task(asyncio.to_thread(lambda: _db["audit_logs"].insert_one({**_audit_doc})))
    logger.info(
        "[USERS] Force-logout: user_id=%s sessions_deleted=%d by=%s",
        user_id, sessions_deleted, username,
    )

    return {"status": "ok", "user_id": user_id, "sessions_deleted": sessions_deleted}


@app.post("/users/create")
async def create_user(
    request: Request,
    body: CreateUserPayload,
    credentials: str = Depends(_require_admin_jwt),
):
    """
    Create a new user account.
    Admin role or API key required.
    Checks uniqueness of username and email before inserting.
    """
    if body.role not in _VALID_ROLES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid role {body.role!r}. Must be one of: {sorted(_VALID_ROLES)}",
        )

    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    from auth.security import hash_password as _hash_pw  # noqa: PLC0415

    # Check uniqueness of username and email
    def _check_unique():
        existing_username = _db["users"].find_one({"username": body.username})
        existing_email    = _db["users"].find_one({"email": body.email})
        return existing_username, existing_email

    try:
        existing_username, existing_email = await asyncio.to_thread(_check_unique)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"DB uniqueness check failed: {exc}")

    if existing_username is not None:
        raise HTTPException(status_code=409, detail=f"Username {body.username!r} is already taken")
    if existing_email is not None:
        raise HTTPException(status_code=409, detail=f"Email {body.email!r} is already registered")

    # Hash the password
    try:
        password_hash = await asyncio.to_thread(_hash_pw, body.password)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Password hashing failed: {exc}")

    now_dt = datetime.utcnow()
    user_doc = {
        "username":           body.username,
        "email":              body.email,
        "password_hash":      password_hash,
        "role":               body.role,
        "created_at":         now_dt,
        "last_login":         None,
        "failed_attempts":    0,
        "locked_until":       None,
        "two_factor_enabled": False,
        "two_factor_secret":  None,
    }

    try:
        result = await asyncio.to_thread(
            lambda: _db["users"].insert_one({**user_doc})
        )
        new_user_id = str(result.inserted_id)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"User creation failed: {exc}")

    caller = _jwt_sub_from_request(request) or "api_key"
    await sio.emit("audit_event", {
        "user":      caller,
        "action":    "user_created",
        "timestamp": _now(),
        "status":    "success",
        "detail":    f"Created user {body.username!r} (id={new_user_id}) with role={body.role!r}",
    })
    logger.info(
        "[USERS] User created: user_id=%s username=%s role=%s by=%s",
        new_user_id, body.username, body.role, caller,
    )

    return {
        "status":   "ok",
        "user_id":  new_user_id,
        "username": body.username,
        "email":    body.email,
        "role":     body.role,
    }


# ---------------------------------------------------------------------------
# Group 3 — Case Notes (Analyst + Admin)
# ---------------------------------------------------------------------------

class CaseNote(BaseModel):
    endpoint_id: str
    note: str = Field(min_length=1, max_length=2000)
    analyst: str = ""   # filled server-side from JWT; ignored if provided by caller


@app.get("/case-notes/{endpoint_id}")
async def get_case_notes(
    request: Request,
    endpoint_id: str,
    credentials: str = Depends(_require_analyst_or_admin_jwt),
):
    """
    Return the last 50 case notes for an endpoint, sorted newest-first.
    Analyst or admin JWT (or API key) required.
    """
    if not MONGO_OK or _db is None:
        return {"notes": [], "total": 0, "mongo_ok": False}

    def _fetch():
        docs = list(
            _db["case_notes"]
            .find({"endpoint_id": endpoint_id}, {"_id": 0})
            .sort("created_at", DESCENDING)
            .limit(50)
        )
        total = _db["case_notes"].count_documents({"endpoint_id": endpoint_id})
        return docs, total

    try:
        docs, total = await asyncio.to_thread(_fetch)
    except Exception as exc:
        logger.error(f"[CASE_NOTES] get_case_notes query failed: {exc}")
        return {"notes": [], "total": 0, "error": str(exc)}

    return {"notes": docs, "total": total, "endpoint_id": endpoint_id}


@app.post("/case-notes")
async def create_case_note(
    request: Request,
    body: CaseNote,
    credentials: str = Depends(_require_analyst_or_admin_jwt),
):
    """
    Save a new case note for an endpoint.
    Analyst or admin JWT (or API key) required.
    The 'analyst' field is always sourced from the JWT 'sub' claim — caller-supplied
    values are ignored to prevent impersonation.
    """
    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    # Force analyst identity from JWT (overrides any caller-supplied value)
    analyst_identity = _jwt_sub_from_request(request) or body.analyst or "api_key"

    note_id = str(_uuid.uuid4())
    note_doc = {
        "note_id":     note_id,
        "endpoint_id": body.endpoint_id,
        "note":        body.note.strip(),
        "analyst":     analyst_identity,
        "created_at":  _now(),
    }

    try:
        await asyncio.to_thread(
            lambda: _db["case_notes"].insert_one({**note_doc})
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to save case note: {exc}")

    logger.info(
        "[CASE_NOTES] Note created: note_id=%s endpoint_id=%s analyst=%s",
        note_id, body.endpoint_id, analyst_identity,
    )

    return {"status": "ok", "note_id": note_id, **note_doc}


@app.delete("/case-notes/{note_id}")
async def delete_case_note(
    request: Request,
    note_id: str,
    credentials: str = Depends(_require_analyst_or_admin_jwt),
):
    """
    Delete a case note.
    Analysts may only delete their own notes.
    Admins (and API key callers) may delete any note.
    """
    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    # Fetch the note to check ownership
    note_doc = await asyncio.to_thread(
        lambda: _db["case_notes"].find_one({"note_id": note_id})
    )
    if note_doc is None:
        raise HTTPException(status_code=404, detail=f"Case note {note_id!r} not found")

    caller_identity = _jwt_sub_from_request(request) or "api_key"

    # Role check — derive role from JWT, fall back to "admin" for API key callers
    caller_role: str = "admin"  # API key is trusted
    if credentials not in ("api_key",):
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                from auth.security import decode_token as _dec  # noqa: PLC0415
                tok = auth_header.removeprefix("Bearer ").strip()
                pl = _dec(tok, settings.jwt_secret_key, settings.jwt_algorithm)
                caller_role = pl.get("role", "viewer")
            except Exception:
                caller_role = "viewer"

    # Analysts can only delete their own notes
    note_analyst = note_doc.get("analyst", "")
    if caller_role == "analyst" and caller_identity != note_analyst:
        raise HTTPException(
            status_code=403,
            detail="Analysts can only delete their own notes",
        )

    try:
        await asyncio.to_thread(
            lambda: _db["case_notes"].delete_one({"note_id": note_id})
        )
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Failed to delete case note: {exc}")

    logger.info(
        "[CASE_NOTES] Note deleted: note_id=%s by=%s (role=%s)",
        note_id, caller_identity, caller_role,
    )

    return {"status": "ok", "note_id": note_id}


# ---------------------------------------------------------------------------
# GET /replay/plan/{plan_id} — investigation bundle accessed directly by plan_id
# Must be registered BEFORE /replay/{incident_id} so FastAPI matches it first.
# ---------------------------------------------------------------------------

@app.get("/replay/plan/{plan_id}", dependencies=[Depends(_require_key_or_jwt)])
async def get_replay_bundle_by_plan(plan_id: str, request: Request):
    """
    Return a replay/investigation bundle for a response plan that may not have
    a generated PDF incident report.  Accepts a plan_id directly and assembles
    the same ReplayData shape that AttackReconstructionView.tsx expects.

    Sub-queries that fail are returned as null / [] — never 500.
    """
    logger.info("[REPLAY/PLAN] Bundle requested: plan_id=%s", plan_id)

    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    # 1. Fetch the response plan
    try:
        plan_doc = await asyncio.to_thread(
            lambda: _db["response_plans"].find_one(
                {"plan_id": plan_id}, {"_id": 0}
            )
        )
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] response_plans query failed: %s", _e)
        plan_doc = None

    if plan_doc is None:
        raise HTTPException(
            status_code=404,
            detail=f"Response plan {plan_id!r} not found",
        )

    # Check whether a PDF report already exists for this plan (keyed by its own
    # incident_id, not plan_id) so the frontend can Download instead of Generate.
    _rp_incident_id = plan_id
    _rp_has_report = False
    try:
        _rp_report_doc = await asyncio.to_thread(
            lambda: _db["incident_reports"].find_one(
                {"plan_id": plan_id}, {"_id": 0}, sort=[("_id", DESCENDING)]
            )
        )
    except Exception as _rpe:
        logger.warning("[REPLAY/PLAN] incident_reports-by-plan_id query failed: %s", _rpe)
        _rp_report_doc = None
    if _rp_report_doc is not None:
        _rp_incident_id = _rp_report_doc.get("incident_id", plan_id)
        _rp_has_report = True

    # Audit: investigation started
    _rp_username = _jwt_sub_from_request(request) or "api_key"
    _rp_ip = request.client.host if request.client else "unknown"
    _rp_audit_doc = {
        "user":      _rp_username,
        "action":    "investigation_started",
        "timestamp": _now(),
        "ip":        _rp_ip,
        "detail":    f"Investigated plan {plan_id}",
        "status":    "success",
    }
    asyncio.create_task(sio.emit("audit_event", _rp_audit_doc))
    if MONGO_OK and _db is not None:
        async def _write_rp_audit():
            try:
                await asyncio.to_thread(lambda: _db["audit_logs"].insert_one(dict(_rp_audit_doc)))
            except Exception:
                pass
        asyncio.create_task(_write_rp_audit())

    endpoint_id   = plan_doc.get("endpoint_id", "")
    attack_type   = plan_doc.get("attack_type", "")
    severity      = plan_doc.get("severity", "MEDIUM")
    mitre_technique = plan_doc.get("mitre_technique", "")
    recommended_actions = plan_doc.get("recommended_actions", [])

    _plan_created = plan_doc.get("created_at", _now())
    if hasattr(_plan_created, "isoformat"):
        _plan_created = _plan_created.isoformat()

    # Parse created_at to datetime for time-window queries
    try:
        _gen_dt = datetime.fromisoformat(str(_plan_created).replace("Z", "+00:00"))
    except Exception:
        _gen_dt = datetime.now(timezone.utc)
    _window_30m_start = _gen_dt - timedelta(minutes=30)
    _window_30m_end   = _gen_dt + timedelta(minutes=30)

    # 2. Fetch the most recent fusion alert for this endpoint + attack_type
    #    (no time window restriction — just most recent)
    fusion_alert_doc = None
    _fa_query_typed = (
        {"endpoint_id": endpoint_id, "attack_type": attack_type}
        if (endpoint_id and attack_type)
        else ({"endpoint_id": endpoint_id} if endpoint_id else {})
    )
    _fa_query_base = {"endpoint_id": endpoint_id} if endpoint_id else {}
    for _fa_coll in ("fused_alerts", "critical_alerts"):
        if fusion_alert_doc is not None:
            break
        try:
            fusion_alert_doc = await asyncio.to_thread(
                lambda cn=_fa_coll: (
                    (_db[cn].find_one(_fa_query_typed, {"_id": 0}, sort=[("_id", DESCENDING)]) if _fa_query_typed else None)
                    or (_db[cn].find_one(_fa_query_base, {"_id": 0}, sort=[("_id", DESCENDING)]) if _fa_query_base else None)
                )
            )
        except Exception as _e:
            logger.warning("[REPLAY/PLAN] %s fusion alert query failed: %s", _fa_coll, _e)

    # 3. Fetch endpoint registry for hostname / IP / OS / username
    _endpoint_registry_doc: Optional[dict] = None
    if endpoint_id:
        try:
            _endpoint_registry_doc = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].find_one(
                    {"endpoint_id": endpoint_id}, {"_id": 0}
                )
            )
        except Exception:
            pass
    _reg = _endpoint_registry_doc or {}

    _is_server_host_rp = (not endpoint_id) or (endpoint_id == "server_host")

    # Helper functions (locally scoped — same logic as the main replay endpoint)
    def _coerce_ts_str_rp(entry: dict) -> str:
        for _f in ("timestamp", "received_at", "ts", "created_at", "alert_ts"):
            _v = entry.get(_f)
            if _v:
                return _v.isoformat() if hasattr(_v, "isoformat") else str(_v)
        return _gen_dt.isoformat()

    def _strip_ts_dt_rp(d: dict) -> dict:
        return {
            k: (v.isoformat() if hasattr(v, "isoformat") else v)
            for k, v in d.items()
            if k != "ts_dt"
        }

    # 4. Build timeline
    timeline_docs: list = []

    # 4a. endpoint_logs — skip for server_host
    if endpoint_id and not _is_server_host_rp:
        try:
            def _fetch_rp_ep_logs():
                return list(
                    _db["endpoint_logs"]
                    .find(
                        {
                            "endpoint_id": endpoint_id,
                            "$or": [
                                {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                                {
                                    "timestamp": {
                                        "$gte": _window_30m_start.isoformat(),
                                        "$lte": _window_30m_end.isoformat(),
                                    }
                                },
                            ],
                        },
                        {"_id": 0},
                    )
                    .sort("timestamp", ASCENDING)
                    .limit(50)
                )
            for _entry in await asyncio.to_thread(_fetch_rp_ep_logs):
                timeline_docs.append({
                    "ts":         _coerce_ts_str_rp(_entry),
                    "event_type": "endpoint_log",
                    "data":       _strip_ts_dt_rp(_entry),
                })
        except Exception as _e:
            logger.warning("[REPLAY/PLAN] endpoint_logs timeline query failed: %s", _e)

    _rp_fused_limit = 50 if _is_server_host_rp else 20

    # 4b. fused_alerts
    try:
        def _fetch_rp_fused():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            if endpoint_id:
                _q["endpoint_id"] = endpoint_id
            return list(
                _db["fused_alerts"]
                .find(_q, {"_id": 0})
                .sort("ts_dt", ASCENDING)
                .limit(_rp_fused_limit)
            )
        for _entry in await asyncio.to_thread(_fetch_rp_fused):
            timeline_docs.append({
                "ts":          _coerce_ts_str_rp(_entry),
                "event_type":  "fusion_alert",
                "attack_type": _entry.get("attack_type", ""),
                "severity":    _entry.get("severity", ""),
                "data":        _strip_ts_dt_rp(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] fused_alerts timeline query failed: %s", _e)

    # 4c. alerts (all types — rule hits, ML, user behavior)
    _rp_alerts_limit = 50 if _is_server_host_rp else 20
    try:
        def _fetch_rp_alerts():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            return list(
                _db["alerts"]
                .find(_q, {"_id": 0})
                .sort("timestamp", ASCENDING)
                .limit(_rp_alerts_limit)
            )
        for _entry in await asyncio.to_thread(_fetch_rp_alerts):
            _src = str(_entry.get("source", _entry.get("type", "")))
            if "user" in _src.lower():
                _rp_etype = "user_anomaly"
            elif "malware" in _src.lower():
                _rp_etype = "malware_alert"
            elif "sysmon" in _src.lower():
                _rp_etype = "sysmon_alert"
            elif "system" in _src.lower():
                _rp_etype = "system_anomaly"
            else:
                _rp_etype = "network_anomaly"
            timeline_docs.append({
                "ts":         _coerce_ts_str_rp(_entry),
                "event_type": _rp_etype,
                "severity":   _entry.get("severity", _entry.get("threat", "")),
                "data":       _strip_ts_dt_rp(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] alerts timeline query failed: %s", _e)

    # 4d. sysmon_alerts
    try:
        def _fetch_rp_sysmon():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                    {
                        "alert_ts": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            if endpoint_id:
                _q["endpoint_id"] = endpoint_id
            return list(
                _db["sysmon_alerts"]
                .find(_q, {"_id": 0})
                .sort("timestamp", ASCENDING)
                .limit(10)
            )
        for _entry in await asyncio.to_thread(_fetch_rp_sysmon):
            timeline_docs.append({
                "ts":         _coerce_ts_str_rp(_entry),
                "event_type": "sysmon_alert",
                "severity":   _entry.get("severity", ""),
                "data":       _strip_ts_dt_rp(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] sysmon_alerts timeline query failed: %s", _e)

    # Deduplicate and sort timeline (same logic as main replay endpoint)
    _rp_seen: set = set()
    _rp_deduped: list = []
    for _td in sorted(timeline_docs, key=lambda x: x.get("ts", "")):
        _rp_key = (str(_td.get("ts", ""))[:19], _td.get("event_type", ""))
        if _rp_key not in _rp_seen:
            _rp_seen.add(_rp_key)
            _rp_deduped.append(_td)
    timeline_docs = _rp_deduped[:50]

    # 5. Fetch SHAP explanation
    shap_doc = None
    try:
        shap_doc = await asyncio.to_thread(
            lambda: (
                (
                    _db["shap_explanations"].find_one(
                        {"endpoint_id": endpoint_id}, {"_id": 0},
                        sort=[("_id", DESCENDING)],
                    )
                    if endpoint_id
                    else None
                )
                or _db["shap_explanations"].find_one(
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                    {"_id": 0},
                    sort=[("_id", DESCENDING)],
                )
                or _db["shap_explanations"].find_one({}, {"_id": 0}, sort=[("_id", DESCENDING)])
            )
        )
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] shap_explanations query failed: %s", _e)

    # 6. Fetch SOAR commands for this plan
    commands_docs: list = []
    try:
        def _fetch_rp_commands():
            return list(
                _db["endpoint_commands"]
                .find({"plan_id": plan_id}, {"_id": 0})
                .sort("created_at", ASCENDING)
            )
        commands_docs = await asyncio.to_thread(_fetch_rp_commands)
        commands_docs = [
            {k: (v.isoformat() if hasattr(v, "isoformat") else v) for k, v in cd.items()}
            for cd in commands_docs
        ]
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] endpoint_commands query failed: %s", _e)

    # 7. Fetch case notes by plan_id or endpoint_id
    case_note_docs: list = []
    try:
        def _fetch_rp_notes():
            _note_q: dict = {"$or": [{"plan_id": plan_id}]}
            if endpoint_id:
                _note_q["$or"].append({"endpoint_id": endpoint_id})
            return list(
                _db["case_notes"]
                .find(_note_q, {"_id": 0})
                .sort("created_at", DESCENDING)
                .limit(50)
            )
        case_note_docs = await asyncio.to_thread(_fetch_rp_notes)
    except Exception as _e:
        logger.warning("[REPLAY/PLAN] case_notes query failed: %s", _e)

    # Normalise SHAP payload
    shap_payload: dict = {"top_features": [], "reason": [], "predicted_class": ""}
    if shap_doc:
        _top_feats = shap_doc.get("top_features", [])
        if not _top_feats:
            _feat_names = shap_doc.get("features", [])
            _feat_vals  = shap_doc.get("values", shap_doc.get("shap_values", []))
            _top_feats = [
                {"feature": str(fn), "shap_value": float(fv) if fv is not None else 0.0}
                for fn, fv in zip(_feat_names, _feat_vals)
            ]
        _plan_shap = plan_doc.get("shap_explanation", [])
        if _plan_shap and isinstance(_plan_shap, list):
            _top_feats = _plan_shap
        _reason = shap_doc.get("reason", shap_doc.get("reasons", []))
        if isinstance(_reason, str):
            _reason = [_reason]
        shap_payload = {
            "top_features":    _top_feats if _top_feats else [],
            "reason":          _reason if _reason else [],
            "predicted_class": str(shap_doc.get("predicted_class", shap_doc.get("prediction", ""))),
        }

    # Build narrative
    _rp_hostname = _reg.get("hostname", endpoint_id) or endpoint_id
    _rp_score: float = 0.0
    _rp_sources: list = []
    if fusion_alert_doc:
        _raw_score = fusion_alert_doc.get("threat_score", 0.0)
        _rp_score = _raw_score / 100 if _raw_score > 1 else float(_raw_score)
        _rp_sources = fusion_alert_doc.get("sources", fusion_alert_doc.get("contributing_signals", []))
    if not _rp_sources:
        _rp_sources = plan_doc.get("sources", [])
    _rp_sources_str = (", ".join(str(s) for s in _rp_sources)) if _rp_sources else "multiple sensors"
    _rp_technique_str = (f" MITRE technique: {mitre_technique}." if mitre_technique else "")
    _rp_actions_str = ""
    if recommended_actions:
        _rp_actions_preview = [str(a) for a in recommended_actions[:5]]
        _rp_remaining = len(recommended_actions) - len(_rp_actions_preview)
        _rp_actions_str = (
            f" Response plan contains {len(recommended_actions)} recommended action(s): "
            + ", ".join(_rp_actions_preview)
            + (f" and {_rp_remaining} more" if _rp_remaining > 0 else "")
            + "."
        )
    narrative = (
        f"{severity} severity {attack_type} detected on {_rp_hostname or endpoint_id}. "
        f"MITRE technique: {mitre_technique or 'N/A'}. "
        f"The fusion engine scored this event at {_rp_score:.0%} threat confidence. "
        f"Contributing models: {_rp_sources_str}.{_rp_technique_str}{_rp_actions_str}"
    )

    logger.info(
        "[REPLAY/PLAN] Bundle assembled: plan_id=%s endpoint=%s "
        "timeline_events=%d commands=%d case_notes=%d shap_items=%d fusion=%s",
        plan_id, endpoint_id,
        len(timeline_docs), len(commands_docs), len(case_note_docs),
        len(shap_payload.get("top_features", [])),
        "yes" if fusion_alert_doc else "no",
    )

    return {
        "incident_id":     _rp_incident_id,
        "plan_id":         plan_id,
        "has_report":      _rp_has_report,
        "endpoint_id":     endpoint_id,
        "hostname":        _reg.get("hostname", endpoint_id),
        "ip_address":      _reg.get("ip_address", ""),
        "os":              _reg.get("os", ""),
        "username":        _reg.get("username", ""),
        "attack_type":     attack_type,
        "severity":        severity,
        "mitre_technique": mitre_technique,
        "created_at":      _plan_created,
        "narrative":       narrative,
        "timeline":        timeline_docs,
        "fusion_alert":    fusion_alert_doc,
        "shap":            shap_payload,
        "commands":        commands_docs,
        "plan":            plan_doc,
        "case_notes":      case_note_docs,
        # These keys mirror the main replay endpoint for full shape compatibility
        "incident":        None,
        "advisory_actions": [],
    }


# ---------------------------------------------------------------------------
# Fix 3: GET /replay/{incident_id} — unified replay bundle for AttackReconstructionView
# ---------------------------------------------------------------------------

@app.get("/replay/{incident_id}")
async def get_replay_bundle(
    incident_id: str,
    request: Request,
    _auth: str = Depends(_require_key_or_jwt),
):
    """
    Return a single JSON bundle containing all evidence for a given incident.
    Called by the AttackReconstructionView replay scrubber.

    Sub-queries that fail or return nothing are included as null / [] — never 500.
    """
    logger.info("[REPLAY] Bundle requested: incident_id=%s", incident_id)

    if not MONGO_OK or _db is None:
        raise HTTPException(status_code=503, detail="MongoDB unavailable")

    # 1. Fetch the incident report
    try:
        incident_doc = await asyncio.to_thread(
            lambda: _db["incident_reports"].find_one(
                {"incident_id": incident_id}, {"_id": 0}
            )
        )
    except Exception as _e:
        logger.warning("[REPLAY] incident_reports query failed: %s", _e)
        incident_doc = None

    if incident_doc is None:
        # The caller may have supplied a plan_id instead of a real incident_id
        # (e.g. "Investigate" from the Active Threats table passes plan_id).
        # Before synthesizing a placeholder, check whether a report was already
        # generated for that plan — if so, surface its REAL incident_id/pdf_path
        # so "Download PDF" in the investigation page doesn't 404 against an
        # incident_reports doc that was never keyed by plan_id.
        try:
            incident_doc = await asyncio.to_thread(
                lambda: _db["incident_reports"].find_one(
                    {"plan_id": incident_id}, {"_id": 0}, sort=[("_id", DESCENDING)]
                )
            )
        except Exception as _pe2:
            logger.warning("[REPLAY] incident_reports-by-plan_id query failed: %s", _pe2)
            incident_doc = None

    _has_report = incident_doc is not None

    if incident_doc is None:
        # Fallback: treat incident_id as a plan_id and synthesize an incident_doc
        try:
            plan_as_incident = await asyncio.to_thread(
                lambda: _db["response_plans"].find_one(
                    {"plan_id": incident_id}, {"_id": 0}
                )
            )
        except Exception as _pe:
            logger.warning("[REPLAY] response_plans fallback query failed: %s", _pe)
            plan_as_incident = None

        if plan_as_incident is not None:
            logger.info("[REPLAY] Synthesizing incident_doc from response_plan for id=%s", incident_id)
            _plan_created = plan_as_incident.get("created_at", _now())
            if hasattr(_plan_created, "isoformat"):
                _plan_created = _plan_created.isoformat()
            incident_doc = {
                "incident_id":     incident_id,
                "plan_id":         incident_id,
                "endpoint_id":     plan_as_incident.get("endpoint_id", ""),
                "attack_type":     plan_as_incident.get("attack_type", ""),
                "severity":        plan_as_incident.get("severity", "MEDIUM"),
                "generated_at":    _plan_created,
                "generated_by":    "response_plan",
                "mitre_technique": plan_as_incident.get("mitre_technique", ""),
            }
        else:
            raise HTTPException(
                status_code=404,
                detail=f"Incident {incident_id!r} not found in incident_reports or response_plans",
            )

    # Audit: investigation started
    _replay_username = _jwt_sub_from_request(request) or "api_key"
    _replay_ip = request.client.host if request.client else "unknown"
    _replay_audit_doc = {
        "user":      _replay_username,
        "action":    "investigation_started",
        "timestamp": _now(),
        "ip":        _replay_ip,
        "detail":    f"Investigated incident {incident_id}",
        "status":    "success",
    }
    asyncio.create_task(sio.emit("audit_event", _replay_audit_doc))
    if MONGO_OK and _db is not None:
        async def _write_replay_audit():
            try:
                await asyncio.to_thread(lambda: _db["audit_logs"].insert_one(dict(_replay_audit_doc)))
            except Exception:
                pass
        asyncio.create_task(_write_replay_audit())

    plan_id     = incident_doc.get("plan_id", "")
    endpoint_id = incident_doc.get("endpoint_id", "")
    attack_type = incident_doc.get("attack_type", "")
    generated_at_str = incident_doc.get("generated_at", _now())

    # Parse generated_at to a datetime for ±-window queries
    try:
        _gen_dt = datetime.fromisoformat(generated_at_str.replace("Z", "+00:00"))
    except Exception:
        _gen_dt = datetime.now(timezone.utc)
    _window_30m_start = _gen_dt - timedelta(minutes=30)
    _window_30m_end   = _gen_dt + timedelta(minutes=30)

    # 2. Fetch the linked response plan
    plan_doc = None
    if plan_id:
        try:
            plan_doc = await asyncio.to_thread(
                lambda: _db["response_plans"].find_one(
                    {"plan_id": plan_id}, {"_id": 0}
                )
            )
        except Exception as _e:
            logger.warning("[REPLAY] response_plans query failed: %s", _e)

    # 3. Fetch the fusion alert — search fused_alerts first, then critical_alerts.
    #    Changed from ±5-min to ±30-min window: server-side detection reports can
    #    be generated minutes after the monitoring cycle that produced the alert.
    #    Three-stage fallback per collection:
    #      (a) endpoint_id + attack_type + 30-min ts_dt window
    #      (b) endpoint_id + 30-min ts_dt window (drops attack_type filter)
    #      (c) endpoint_id only — most-recent document, no time filter at all
    fusion_alert_doc = None
    _alert_query_base: dict = {"endpoint_id": endpoint_id} if endpoint_id else {}
    _alert_query_typed: dict = (
        {**_alert_query_base, "attack_type": attack_type} if attack_type else _alert_query_base
    )
    _time_query_typed_30m = {
        **_alert_query_typed,
        "ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end},
    }
    _time_query_base_30m = {
        **_alert_query_base,
        "ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end},
    }
    for _collection_name in ("fused_alerts", "critical_alerts"):
        if fusion_alert_doc is not None:
            break
        try:
            fusion_alert_doc = await asyncio.to_thread(
                lambda cn=_collection_name: (
                    _db[cn].find_one(_time_query_typed_30m, {"_id": 0}, sort=[("_id", DESCENDING)])
                    or _db[cn].find_one(_time_query_base_30m, {"_id": 0}, sort=[("_id", DESCENDING)])
                    or (
                        _db[cn].find_one(_alert_query_base, {"_id": 0}, sort=[("_id", DESCENDING)])
                        if _alert_query_base
                        else None
                    )
                )
            )
        except Exception as _e:
            logger.warning("[REPLAY] %s fusion alert query failed: %s", _collection_name, _e)

    # 4. Fetch timeline events within ±30 min of the incident.
    #    Sources (in priority order): endpoint_logs, fused_alerts, alerts, predictions.
    #    endpoint_logs is only populated by the standalone endpoint agent — for
    #    server-side detections (endpoint_id="server_host" or empty) the other
    #    collections provide the event history from the server detection pipeline.
    timeline_docs: list = []

    # Detect server-host investigations so we can skip endpoint_logs and use
    # larger query limits on the server-pipeline collections.
    _is_server_host = (not endpoint_id) or (endpoint_id == "server_host")

    def _coerce_ts_str(entry: dict) -> str:
        """Return a JSON-safe ISO timestamp string from a MongoDB document."""
        for _f in ("timestamp", "received_at", "ts", "created_at", "alert_ts"):
            _v = entry.get(_f)
            if _v:
                return _v.isoformat() if hasattr(_v, "isoformat") else str(_v)
        return _gen_dt.isoformat()

    def _strip_ts_dt(d: dict) -> dict:
        """Remove BSON datetime field and coerce any remaining datetimes to ISO strings."""
        return {
            k: (v.isoformat() if hasattr(v, "isoformat") else v)
            for k, v in d.items()
            if k != "ts_dt"
        }

    # 4a. endpoint_logs — written by standalone endpoint agent only.
    #     Skip entirely for server_host (that collection has no server entries).
    #     Bug-2 fix: only include heartbeat documents that carry real signal
    #     (non-empty suspicious_ports or non-empty suspicious malware entries).
    #     Routine 5-second heartbeats with no detections are excluded so the
    #     investigation timeline is not flooded with fake "Attack from unknown"
    #     entries derived from empty telemetry fields.
    if endpoint_id and not _is_server_host:
        try:
            def _fetch_endpoint_logs():
                return list(
                    _db["endpoint_logs"]
                    .find(
                        {
                            "$and": [
                                {
                                    "endpoint_id": endpoint_id,
                                    "$or": [
                                        {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                                        {
                                            "timestamp": {
                                                "$gte": _window_30m_start.isoformat(),
                                                "$lte": _window_30m_end.isoformat(),
                                            }
                                        },
                                    ],
                                },
                                # Require at least one suspicious signal — .0 existence
                                # is the standard Mongo idiom for "array is non-empty"
                                # and works whether or not the field exists at all.
                                {
                                    "$or": [
                                        {"network.suspicious_ports.0": {"$exists": True}},
                                        {"malware.suspicious.0":       {"$exists": True}},
                                    ]
                                },
                            ]
                        },
                        {"_id": 0},
                    )
                    .sort("timestamp", ASCENDING)
                    .limit(50)
                )
            for _entry in await asyncio.to_thread(_fetch_endpoint_logs):
                timeline_docs.append({
                    "ts":         _coerce_ts_str(_entry),
                    "event_type": "endpoint_log",
                    "data":       _strip_ts_dt(_entry),
                })
        except Exception as _e:
            logger.warning("[REPLAY] endpoint_logs timeline query failed: %s", _e)

    # Use larger per-collection limits for server_host since endpoint_logs is empty.
    _fused_alerts_limit = 50 if _is_server_host else 20
    _alerts_limit = 50 if _is_server_host else 20

    # 4b. fused_alerts — written by server pipeline on every fusion cycle
    try:
        def _fetch_fused_tl():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            if endpoint_id:
                _q["endpoint_id"] = endpoint_id
            return list(
                _db["fused_alerts"]
                .find(_q, {"_id": 0})
                .sort("ts_dt", ASCENDING)
                .limit(_fused_alerts_limit)
            )
        for _entry in await asyncio.to_thread(_fetch_fused_tl):
            timeline_docs.append({
                "ts":          _coerce_ts_str(_entry),
                "event_type":  "fusion_alert",
                "attack_type": _entry.get("attack_type", ""),
                "severity":    _entry.get("severity", ""),
                "data":        _strip_ts_dt(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY] fused_alerts timeline query failed: %s", _e)

    # 4c. alerts — rule hits and ML detections from _process_network_result + user behavior
    try:
        def _fetch_alerts_tl():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            return list(
                _db["alerts"]
                .find(_q, {"_id": 0})
                .sort("timestamp", ASCENDING)
                .limit(_alerts_limit)
            )
        for _entry in await asyncio.to_thread(_fetch_alerts_tl):
            _src = str(_entry.get("source", _entry.get("type", "")))
            if "user" in _src.lower():
                _etype = "user_anomaly"
            elif "malware" in _src.lower():
                _etype = "malware_alert"
            elif "sysmon" in _src.lower():
                _etype = "sysmon_alert"
            elif "system" in _src.lower():
                _etype = "system_anomaly"
            else:
                _etype = "network_anomaly"
            timeline_docs.append({
                "ts":         _coerce_ts_str(_entry),
                "event_type": _etype,
                "severity":   _entry.get("severity", _entry.get("threat", "")),
                "data":       _strip_ts_dt(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY] alerts timeline query failed: %s", _e)

    # 4d. sysmon_alerts — Sysmon behavioral events from the server-side pipeline
    try:
        def _fetch_sysmon_tl():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                    {
                        "alert_ts": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            if endpoint_id:
                _q["endpoint_id"] = endpoint_id
            return list(
                _db["sysmon_alerts"]
                .find(_q, {"_id": 0})
                .sort("timestamp", ASCENDING)
                .limit(20)
            )
        for _entry in await asyncio.to_thread(_fetch_sysmon_tl):
            timeline_docs.append({
                "ts":         _coerce_ts_str(_entry),
                "event_type": "sysmon_alert",
                "severity":   _entry.get("severity", ""),
                "data":       _strip_ts_dt(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY] sysmon_alerts timeline query failed: %s", _e)

    # 4e. predictions — ML model output records written by _process_network_result
    try:
        def _fetch_predictions_tl():
            _q: dict = {
                "$or": [
                    {"ts_dt": {"$gte": _window_30m_start, "$lte": _window_30m_end}},
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                ]
            }
            return list(
                _db["predictions"]
                .find(_q, {"_id": 0})
                .sort("timestamp", ASCENDING)
                .limit(10)
            )
        for _entry in await asyncio.to_thread(_fetch_predictions_tl):
            timeline_docs.append({
                "ts":         _coerce_ts_str(_entry),
                "event_type": "network_anomaly",
                "data":       _strip_ts_dt(_entry),
            })
    except Exception as _e:
        logger.warning("[REPLAY] predictions timeline query failed: %s", _e)

    # Sort all timeline events chronologically and deduplicate by (ts[:19], event_type).
    # Truncating to-the-second prevents near-duplicate entries from overlapping sources.
    # Cap at 50 events total for frontend performance.
    _seen_tl_keys: set = set()
    _deduped_tl: list = []
    for _td in sorted(timeline_docs, key=lambda x: x.get("ts", "")):
        _dedup_key = (str(_td.get("ts", ""))[:19], _td.get("event_type", ""))
        if _dedup_key not in _seen_tl_keys:
            _seen_tl_keys.add(_dedup_key)
            _deduped_tl.append(_td)
    timeline_docs = _deduped_tl[:50]

    # 5. Fetch SHAP explanation.
    #    shap_explanations documents from the server pipeline are stored with
    #    source/timestamp fields — they do NOT have an endpoint_id field.
    #    Four-stage lookup (first non-None result wins):
    #      (a) endpoint_id field present  (newer documents may have it)
    #      (b) timestamp string within ±30-minute window
    #      (c) alert_ts string within ±30-minute window
    #      (d) most-recent document in the entire collection (last resort)
    shap_doc = None
    try:
        shap_doc = await asyncio.to_thread(
            lambda: (
                (
                    _db["shap_explanations"].find_one(
                        {"endpoint_id": endpoint_id}, {"_id": 0},
                        sort=[("_id", DESCENDING)],
                    )
                    if endpoint_id
                    else None
                )
                or _db["shap_explanations"].find_one(
                    {
                        "timestamp": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                    {"_id": 0},
                    sort=[("_id", DESCENDING)],
                )
                or _db["shap_explanations"].find_one(
                    {
                        "alert_ts": {
                            "$gte": _window_30m_start.isoformat(),
                            "$lte": _window_30m_end.isoformat(),
                        }
                    },
                    {"_id": 0},
                    sort=[("_id", DESCENDING)],
                )
                or (
                    _db["shap_explanations"].find_one(
                        {"endpoint_id": endpoint_id}, {"_id": 0}, sort=[("_id", DESCENDING)]
                    )
                    if endpoint_id
                    else None
                )
            )
        )
    except Exception as _e:
        logger.warning("[REPLAY] shap_explanations query failed: %s", _e)

    # 6. Fetch SOAR commands executed for this plan (with results)
    commands_docs: list = []
    if plan_id:
        try:
            def _fetch_commands():
                return list(
                    _db["endpoint_commands"]
                    .find({"plan_id": plan_id}, {"_id": 0})
                    .sort("created_at", ASCENDING)
                )
            commands_docs = await asyncio.to_thread(_fetch_commands)
            # Coerce any datetime objects in command docs to ISO strings
            commands_docs = [
                {
                    k: (v.isoformat() if hasattr(v, "isoformat") else v)
                    for k, v in cd.items()
                }
                for cd in commands_docs
            ]
        except Exception as _e:
            logger.warning("[REPLAY] endpoint_commands query failed: %s", _e)

    # 7. Fetch advisory actions for this plan
    advisory_docs: list = []
    if plan_id:
        try:
            def _fetch_advisory():
                return list(
                    _db["response_advisory_logs"]
                    .find({"plan_id": plan_id}, {"_id": 0})
                    .sort("created_at", ASCENDING)
                )
            advisory_docs = await asyncio.to_thread(_fetch_advisory)
        except Exception as _e:
            logger.warning("[REPLAY] response_advisory_logs query failed: %s", _e)

    # 8. Fetch case notes for this endpoint (also include any tied to this incident's plan_id)
    case_note_docs: list = []
    if endpoint_id:
        try:
            def _fetch_notes():
                _note_q: dict = {"$or": [{"endpoint_id": endpoint_id}]}
                if plan_id:
                    _note_q["$or"].append({"plan_id": plan_id})
                return list(
                    _db["case_notes"]
                    .find(_note_q, {"_id": 0})
                    .sort("created_at", DESCENDING)
                    .limit(50)
                )
            case_note_docs = await asyncio.to_thread(_fetch_notes)
        except Exception as _e:
            logger.warning("[REPLAY] case_notes query failed: %s", _e)

    # Normalise SHAP doc into the shape expected by the frontend ReplayData.shap interface:
    #   { predicted_class, reason[], top_features[{feature, shap_value, feature_value}] }
    # Also include raw doc fields under "raw" for backward compat.
    # IMPORTANT: never return None for shap — the frontend crashes on null SHAP.
    # Return [] (empty list) as the synthetic fallback when no SHAP doc is found.
    shap_payload: dict = {"top_features": [], "reason": [], "predicted_class": ""}
    if shap_doc:
        # top_features can be stored as a list of {feature, shap_value} dicts
        # or as parallel lists "features" / "values".  Normalise to the former.
        _top_feats = shap_doc.get("top_features", [])
        if not _top_feats:
            _feat_names = shap_doc.get("features", [])
            _feat_vals  = shap_doc.get("values", shap_doc.get("shap_values", []))
            _top_feats = [
                {"feature": str(fn), "shap_value": float(fv) if fv is not None else 0.0}
                for fn, fv in zip(_feat_names, _feat_vals)
            ]
        # Inline SHAP from plan doc takes priority as it is already curated
        _plan_shap = (plan_doc or {}).get("shap_explanation", [])
        if _plan_shap and isinstance(_plan_shap, list):
            _top_feats = _plan_shap
        _reason = shap_doc.get("reason", shap_doc.get("reasons", []))
        if isinstance(_reason, str):
            _reason = [_reason]
        shap_payload = {
            "top_features":    _top_feats if _top_feats else [],
            "reason":          _reason if _reason else [],
            "predicted_class": str(shap_doc.get("predicted_class", shap_doc.get("prediction", ""))),
        }

    # Flatten incident_doc fields to the response top level so the frontend
    # ReplayData interface (which expects incident_id, endpoint_id, hostname,
    # attack_type, severity, etc. as direct keys) works without adaptation.
    # The nested "incident" key is kept for backward compatibility.
    _inc = incident_doc or {}
    _endpoint_registry_doc: Optional[dict] = None
    if endpoint_id:
        try:
            _endpoint_registry_doc = await asyncio.to_thread(
                lambda: _db["endpoint_registry"].find_one(
                    {"endpoint_id": endpoint_id}, {"_id": 0}
                )
            )
        except Exception:
            pass
    _reg = _endpoint_registry_doc or {}

    # Build a plain-English attack narrative for the investigation panel.
    # All fields are null-safe — missing values are substituted with readable defaults.
    _narrative_attack_type = _inc.get("attack_type", attack_type) or "Unknown Attack"
    _narrative_hostname = _reg.get("hostname", endpoint_id) or endpoint_id
    _narrative_severity = _inc.get("severity", "UNKNOWN")
    _narrative_time = generated_at_str
    _narrative_score: float = 0.0
    _narrative_sources: list = []
    _narrative_technique = ""
    if fusion_alert_doc:
        _raw_score = fusion_alert_doc.get("threat_score", 0.0)
        _narrative_score = _raw_score / 100 if _raw_score > 1 else float(_raw_score)
        _narrative_sources = fusion_alert_doc.get("sources", fusion_alert_doc.get("contributing_signals", []))
    if plan_doc:
        _narrative_technique = plan_doc.get("mitre_technique", "")
        if not _narrative_sources:
            _narrative_sources = plan_doc.get("sources", [])
    _sources_str = (", ".join(str(s) for s in _narrative_sources)) if _narrative_sources else "multiple sensors"
    _technique_str = (f" MITRE technique: {_narrative_technique}." if _narrative_technique else "")
    # Include recommended actions from the plan when available
    _narrative_actions: list = []
    if plan_doc:
        _narrative_actions = plan_doc.get("recommended_actions", [])
    _actions_str = ""
    if _narrative_actions:
        _actions_preview = [str(a) for a in _narrative_actions[:5]]
        _remaining = len(_narrative_actions) - len(_actions_preview)
        _actions_str = (
            f" Response plan contains {len(_narrative_actions)} recommended action(s): "
            + ", ".join(_actions_preview)
            + (f" and {_remaining} more" if _remaining > 0 else "")
            + "."
        )
    narrative = (
        f"A {_narrative_attack_type} attack was detected on {_narrative_hostname} at {_narrative_time}. "
        f"Severity: {_narrative_severity}. "
        f"The fusion engine scored this event at {_narrative_score:.0%} threat confidence. "
        f"Contributing models: {_sources_str}.{_technique_str}{_actions_str}"
    )

    logger.info(
        "[REPLAY] Bundle assembled: incident_id=%s plan=%s endpoint=%s "
        "timeline_events=%d commands=%d advisory=%d case_notes=%d shap_items=%d fusion=%s",
        incident_id, plan_id, endpoint_id,
        len(timeline_docs), len(commands_docs), len(advisory_docs), len(case_note_docs),
        len(shap_payload.get("top_features", [])),
        "yes" if fusion_alert_doc else "no",
    )

    return {
        # ── Top-level incident fields (required by frontend ReplayData interface) ──
        "incident_id":      _inc.get("incident_id", incident_id),
        "endpoint_id":      _inc.get("endpoint_id", endpoint_id),
        "hostname":         _reg.get("hostname", _inc.get("hostname", endpoint_id)),
        "ip_address":       _reg.get("ip_address", _inc.get("ip_address", "")),
        "os":               _reg.get("os", _inc.get("os", "")),
        "username":         _reg.get("username", _inc.get("username", "")),
        "attack_type":      _inc.get("attack_type", attack_type),
        "severity":         _inc.get("severity", ""),
        "mitre_technique":  _inc.get("mitre_technique", "") or (plan_doc or {}).get("mitre_technique", ""),
        "created_at":       _inc.get("generated_at", _inc.get("created_at", "")),
        # plan_id + has_report let the frontend know whether a real PDF exists
        # for this incident (Download) or must be generated on demand (Generate).
        "plan_id":          plan_id,
        "has_report":       _has_report,
        # ── Sub-documents ──────────────────────────────────────────────────────────
        "incident":         _inc,
        "plan":             plan_doc,
        "fusion_alert":     fusion_alert_doc,
        "timeline":         timeline_docs,
        # shap is always a dict — never null.  Empty top_features means no SHAP available.
        "shap":             shap_payload,
        "commands":         commands_docs,
        "advisory_actions": advisory_docs,
        "case_notes":       case_note_docs,
        "narrative":        narrative,
    }


# ---------------------------------------------------------------------------
# Fix 4: GET /critical-alerts — list the permanent evidence store
# ---------------------------------------------------------------------------

@app.get("/critical-alerts")
async def list_critical_alerts(
    request: Request,
    limit: int = 50,
    skip: int = 0,
    credentials: str = Depends(_require_key_or_jwt),
):
    """
    Return HIGH and CRITICAL alerts from the uncapped critical_alerts collection,
    newest-first.  Supports limit/skip pagination (max 200 per page).

    Auth: valid X-API-Key OR JWT with any role.
    """
    logger.info("[CRITICAL_ALERTS] List requested: limit=%d skip=%d", limit, skip)

    limit = max(1, min(limit, 200))
    skip  = max(0, skip)

    if not MONGO_OK or _db is None:
        return {"alerts": [], "total": 0, "mongo_ok": False}

    try:
        def _fetch():
            total = _db["critical_alerts"].count_documents({})
            docs = list(
                _db["critical_alerts"]
                .find({}, {"_id": 0})
                .sort("ts_dt", DESCENDING)
                .skip(skip)
                .limit(limit)
            )
            return total, docs

        total, docs = await asyncio.to_thread(_fetch)
    except Exception as exc:
        logger.error("[CRITICAL_ALERTS] query failed: %s", exc)
        return {"alerts": [], "total": 0, "error": str(exc)}

    # Coerce any remaining datetime objects to ISO strings for JSON serialisation
    clean: list = []
    for d in docs:
        row = {}
        for k, v in d.items():
            row[k] = v.isoformat() if hasattr(v, "isoformat") else v
        clean.append(row)

    return {"alerts": clean, "total": total, "limit": limit, "skip": skip}


# ---------------------------------------------------------------------------
# GET /logs/network — historical network anomaly / fused alert query
# ---------------------------------------------------------------------------

@app.get("/logs/network", dependencies=[Depends(_require_key_or_jwt)])
async def get_network_logs(
    limit: int = 100,
    skip: int = 0,
    severity: Optional[str] = None,
    attack_type: Optional[str] = None,
    endpoint_id: Optional[str] = None,
    since: Optional[str] = None,
    collection: str = "fused_alerts",
):
    """
    Query historical network anomaly records from MongoDB.

    By default queries `fused_alerts` (fusion results that include network
    contributions).  Set `collection=alerts` to query the raw alert stream.

    Query params (all optional, backward-compatible):
      limit       — max documents to return (1–500, default 100)
      skip        — pagination offset (default 0)
      severity    — filter by severity: LOW | MEDIUM | HIGH | CRITICAL
      attack_type — case-insensitive substring match on attack_type field
      endpoint_id — filter by originating endpoint
      since       — ISO datetime string; return only events after this timestamp
      collection  — source collection: fused_alerts (default) | alerts

    Response: {"alerts": [...], "total": N, "limit": N, "skip": N}

    Auth: valid X-API-Key OR JWT with any role.
    """
    limit = max(1, min(limit, 500))
    skip = max(0, skip)

    # Only allow safe collection names to prevent arbitrary DB access
    _ALLOWED_COLS = {"fused_alerts", "alerts"}
    if collection not in _ALLOWED_COLS:
        raise HTTPException(
            status_code=400,
            detail=f"collection must be one of: {', '.join(sorted(_ALLOWED_COLS))}",
        )

    if not MONGO_OK or _db is None:
        return {"alerts": [], "total": 0, "mongo_ok": False}

    # Build filter query
    query: dict = {}

    if severity is not None and severity.strip():
        query["severity"] = severity.strip().upper()

    if attack_type is not None and attack_type.strip():
        query["attack_type"] = {"$regex": attack_type.strip(), "$options": "i"}

    if endpoint_id is not None and endpoint_id.strip():
        query["endpoint_id"] = endpoint_id.strip()

    if since is not None and since.strip():
        try:
            _since_dt = datetime.fromisoformat(since.strip().rstrip("Z"))
            # ts_dt is a BSON datetime field; ts is an ISO string.
            # Query ts_dt when available (fused_alerts always has it),
            # fall back to ts string comparison.
            query["ts_dt"] = {"$gt": _since_dt}
        except ValueError:
            logger.warning("[LOGS/NETWORK] Invalid 'since' value: %s", since)

    try:
        def _fetch():
            total = _db[collection].count_documents(query)
            docs = list(
                _db[collection]
                .find(query, {"_id": 0})
                .sort("ts_dt", DESCENDING)
                .skip(skip)
                .limit(limit)
            )
            return total, docs

        total, docs = await asyncio.to_thread(_fetch)
    except Exception as exc:
        logger.error("[LOGS/NETWORK] query failed: %s", exc)
        return {"alerts": [], "total": 0, "error": str(exc)}

    # Coerce datetime objects to ISO strings for JSON serialisation
    clean: list = []
    for d in docs:
        row = {}
        for k, v in d.items():
            row[k] = v.isoformat() if hasattr(v, "isoformat") else v
        clean.append(row)

    return {"alerts": clean, "total": total, "limit": limit, "skip": skip}


# ---------------------------------------------------------------------------
# Public contact form — no auth required (used from the login/about page)
# ---------------------------------------------------------------------------
@app.post("/contact")
async def submit_contact_inquiry(
    inquiry: ContactInquiry,
    request: Request,
):
    """Public contact form submission — no auth required."""
    client_ip = _get_client_ip(request)

    # Rate limit: 3 submissions per IP per hour using sliding-window deque
    now_mono = time.monotonic()
    cutoff = now_mono - _CONTACT_RATE_WINDOW
    timestamps = _contact_rate.get(client_ip, [])
    # Evict timestamps outside the current window
    timestamps = [t for t in timestamps if t > cutoff]
    if len(timestamps) >= _CONTACT_RATE_LIMIT:
        oldest = min(timestamps)
        retry_after = int(_CONTACT_RATE_WINDOW - (now_mono - oldest)) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Too many contact submissions. Try again in {retry_after} seconds.",
            headers={"Retry-After": str(retry_after)},
        )
    timestamps.append(now_mono)
    _contact_rate[client_ip] = timestamps

    ticket_id = str(_uuid.uuid4())[:8].upper()

    doc = {
        "ticket_id": ticket_id,
        "name": inquiry.name,
        "email": inquiry.email,
        "phone": inquiry.phone or "",
        "subject": inquiry.subject,
        "message": inquiry.message,
        "ip": client_ip,
        "ts": datetime.utcnow().isoformat(),
        "ts_dt": datetime.utcnow(),
        "status": "open",
    }

    if _db is not None:
        try:
            asyncio.create_task(
                asyncio.to_thread(lambda: _db["contact_inquiries"].insert_one(doc.copy()))
            )
        except Exception as _e:
            logger.warning("[CONTACT] DB save failed: %s", _e)

    logger.info(
        "[CONTACT] New inquiry ticket=%s from=%s subject=%s ip=%s",
        ticket_id, inquiry.email, inquiry.subject, client_ip,
    )

    return {"submitted": True, "ticket_id": ticket_id}


# ---------------------------------------------------------------------------
# Static dashboard serving (same-origin).
# Registered LAST, after every API route, so it never shadows them. When the
# built React dashboard is present, the backend serves it — the SPA, REST API,
# and Socket.IO then share one origin, so the frontend needs no hardcoded
# backend URL (config.ts resolves BACKEND_URL to window.location.origin).
# /socket.io is handled by the socketio ASGIApp wrapper before FastAPI, so it
# is never caught here.
# ---------------------------------------------------------------------------
from fastapi.staticfiles import StaticFiles  # noqa: E402

_frontend_dir = Path(settings.frontend_dir)
if _frontend_dir.is_dir() and (_frontend_dir / "index.html").is_file():
    _static_subdir = _frontend_dir / "static"
    if _static_subdir.is_dir():
        app.mount("/static", StaticFiles(directory=str(_static_subdir)), name="dashboard-static")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def _serve_dashboard(full_path: str):
        # Serve a real file when it exists (favicon.ico, manifest.json, logo.jpg,
        # Sounds/, team/, ...); otherwise fall back to index.html so React Router
        # handles client-side routes. Path-traversal guarded via relative_to.
        index = _frontend_dir / "index.html"
        if full_path:
            candidate = (_frontend_dir / full_path).resolve()
            try:
                candidate.relative_to(_frontend_dir.resolve())
                if candidate.is_file():
                    return FileResponse(str(candidate))
            except ValueError:
                pass
        return FileResponse(str(index))

    logger.info("Dashboard served same-origin from %s", _frontend_dir)
else:
    logger.info("Dashboard build not found at %s — running API-only", _frontend_dir)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    uvicorn.run(
        "backend:sio_app",
        host=settings.backend_host,
        port=settings.backend_port,
        reload=True,
        reload_dirs=[str(Path(__file__).parent)],
        app_dir=str(Path(__file__).parent),
    )
