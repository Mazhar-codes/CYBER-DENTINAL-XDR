import json
import os
import psutil
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np
import pandas as pd
from joblib import load as joblib_load
import pickle


_HERE = Path(__file__).parent
MODEL_PATH = Path(os.getenv("USER_MODEL_DIR", str(_HERE))) / "user_model.pkl"
SCALER_PATH = Path(os.getenv("USER_MODEL_DIR", str(_HERE))) / "user_scaler.pkl"
FEATURES_PATH = Path(os.getenv("USER_MODEL_DIR", str(_HERE))) / "feature_columns.json"
THRESHOLD_PATH = Path(os.getenv("USER_MODEL_DIR", str(_HERE))) / "model_threshold.json"
LOG_DIR = Path(os.getenv("USER_LOG_DIR", str(_HERE / "logs")))

# Default lookback window for the Get-WinEvent primary path.
# Override via UBA_LOOKBACK_MINUTES env var.
_DEFAULT_LOOKBACK_MINUTES = int(os.getenv("UBA_LOOKBACK_MINUTES", "120"))

# Fast-path rule thresholds (configurable via env vars).
# FAST_PATH_FILE_OPS counts only genuine file-access events (4663, 4670, Sysmon 11/15/23).
# Event 4688 (process creation) is intentionally excluded from file_ops_count to avoid
# false positives: a normal Windows workstation generates 200-500 process-creation events
# per 120-minute window from background services, which would otherwise always trigger
# this rule.  Set XDR_FAST_PATH_FILE_OPS in the environment to tune per deployment.
FAST_PATH_FILE_OPS = int(os.getenv("XDR_FAST_PATH_FILE_OPS", "500"))
FAST_PATH_DIR_SCANS = int(os.getenv("XDR_FAST_PATH_DIR_SCANS", "100"))


def load_pickle(path: Path) -> Any:
    try:
        return joblib_load(path)
    except Exception:
        with path.open("rb") as f:
            return pickle.load(f)


def load_feature_columns(path: Path) -> List[str]:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def load_threshold(path: Path) -> float:
    if not path.exists():
        return 0.5
    try:
        with path.open("r", encoding="utf-8") as f:
            return float(json.load(f).get("threshold", 0.5))
    except Exception:
        return 0.5


def local_hour_from_timestamp(ts_value: Any) -> Optional[int]:
    ts = pd.to_datetime(ts_value, errors="coerce", utc=True)
    if pd.isna(ts):
        return None
    try:
        local_tz = datetime.now().astimezone().tzinfo
        local_ts = ts.tz_convert(local_tz)
    except Exception:
        local_ts = ts
    return int(local_ts.hour)


def read_ndjson_logs(log_dir: Path) -> List[Dict[str, Any]]:
    events: List[Dict[str, Any]] = []
    if not log_dir.exists():
        return events
    candidates = sorted(
        [p for p in log_dir.iterdir()
         if p.is_file() and (p.name.startswith("winlogbeat") or p.suffix == ".ndjson")]
    )
    for file_path in candidates:
        with file_path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return events


def filter_recent_events(events: List[Dict[str, Any]], lookback_minutes: int) -> List[Dict[str, Any]]:
    if lookback_minutes <= 0:
        return events
    now_utc = pd.Timestamp.now(tz="UTC")
    cutoff = now_utc - pd.Timedelta(minutes=lookback_minutes)
    out: List[Dict[str, Any]] = []
    for e in events:
        ts = pd.to_datetime(e.get("@timestamp"), errors="coerce", utc=True)
        if pd.notna(ts) and ts >= cutoff:
            out.append(e)
    return out


def normalize_events_to_features(events: List[Dict[str, Any]]) -> pd.DataFrame:
    """
    Extract per-user behavioral features from Windows event log records.

    Feature set (19 dimensions, matches feature_columns.json):
        file_ops_count, file_write_count, file_read_count, unique_files_accessed,
        file_ops_rate, logon_count, logoff_count, failed_logon_count,
        after_hours_activity, device_connects, device_disconnects, device_events,
        emails_sent, unique_recipients,
        O, C, E, A, N  (behavioral proxies derived from Windows event log signals;
                         see the OCEAN proxy block below for mapping details)

    Event ID to feature mapping:
        4624  — logon_count; logon_hour for C proxy; LogonType=3 for E proxy
        4625  — failed_logon_count; A proxy degradation
        4634  — logoff_count
        4647  — logoff_count (user-initiated)
        4648  — failed_logon_count (explicit credential / runas attempt)
        4663  — file_ops_count, file_read_count, unique_files_accessed (object access)
        4670  — file_ops_count (permission change treated as file op)
        4672  — contributes to N proxy (privileged logon often off-hours or admin work)
        4688  — file_ops_count proxy (process creation implies app/file activity)
        4697  — device_events (service install is a privileged device-like event)
        4698/4699/4700 — device_events (scheduled task lifecycle)
        4719  — device_events (audit policy change is an elevated system event)
        4720/4726/4732 — device_events (account management events)
        4776  — failed_logon_count (credential validation failure)

    OCEAN proxy mapping (behavioral approximations — not true psychometric scores):
        O (Openness)         — unique event-provider diversity ratio
        C (Conscientiousness)— login-time regularity, inverted std of logon hours
        E (Extraversion)     — proportion of type-3 (network/remote) logons
        A (Agreeableness)    — 1 - (failed_logon_count / total_events), clamped [0,1]
        N (Neuroticism)      — after-hours event ratio (events outside 08:00–18:00)

    All five OCEAN features are present in feature_columns.json and are active model
    dimensions. The model was originally trained on psychometric scores from the CERT
    r4.2 HR dataset; these event-log proxies reduce (but do not eliminate) the scoring
    degradation that would result from passing constant 0.0 values.
    """
    if not events:
        return pd.DataFrame()

    # Track min/max timestamp per user for ops-rate calculation
    by_user: Dict[str, Dict[str, Any]] = {}

    for e in events:
        user = (
            e.get("user", {}).get("name")
            or e.get("winlog", {}).get("user_data", {}).get("TargetUserName")
            # NOTE: do NOT fall back to host.name — that is the machine hostname,
            # not a human user account.  Events with no user field are skipped.
            or ""
        )
        # Skip machine accounts, system service accounts, and events with no
        # identifiable human user.  This prevents the machine hostname (e.g.
        # 'DELL') from appearing as a second user in the behavior log.
        if _should_skip_user(user):
            continue
        if user not in by_user:
            by_user[user] = {
                "user": user,
                # file
                "file_ops_count": 0,
                "file_write_count": 0,
                "file_read_count": 0,
                "unique_files_set": set(),
                "unique_dirs_set": set(),
                "_ts_first": None,
                "_ts_last": None,
                # logon
                "logon_count": 0,
                "logoff_count": 0,
                "failed_logon_count": 0,
                # after-hours (all event types)
                "after_hours_activity": 0,
                # device
                "device_connects": 0,
                "device_disconnects": 0,
                "device_events": 0,
                # email
                "emails_sent": 0,
                "unique_recipients_set": set(),
                # OCEAN proxy accumulators
                "_total_events": 0,          # denominator for ratios
                "_unique_providers": set(),   # diversity proxy for Openness
                "_logon_hours": [],           # login-hour samples for Conscientiousness
                "_network_logon_count": 0,    # type-3 (network) logons for Extraversion
                "_events_in_hours": 0,        # events 8-18 for Agreeableness denominator
                "_events_outside_hours": 0,   # events outside 8-18 for Neuroticism
            }

        row = by_user[user]
        event_code = str(e.get("winlog", {}).get("event_id", ""))
        provider = str(e.get("winlog", {}).get("provider_name", "")).lower()
        msg = str(e.get("message", "")).lower()
        ts_raw = e.get("@timestamp")
        hour = local_hour_from_timestamp(ts_raw)

        # Prefer structured _parsed dict injected by _normalize_powershell_item;
        # fall back to winlog.event_data for Winlogbeat NDJSON events.
        _parsed: Dict[str, Any] = e.get("_parsed") or {}
        event_data: Dict[str, Any] = e.get("winlog", {}).get("event_data", {})

        def _field(*keys: str) -> str:
            """Return first non-empty value from _parsed or event_data."""
            for k in keys:
                v = _parsed.get(k) or event_data.get(k, "")
                if v:
                    return str(v)
            return ""

        # OCEAN accumulators: count every event seen for this user
        row["_total_events"] += 1
        if provider:
            row["_unique_providers"].add(provider)

        # Track timestamp range for ops-rate
        if ts_raw is not None:
            ts_val = pd.to_datetime(ts_raw, errors="coerce", utc=True)
            if pd.notna(ts_val):
                if row["_ts_first"] is None or ts_val < row["_ts_first"]:
                    row["_ts_first"] = ts_val
                if row["_ts_last"] is None or ts_val > row["_ts_last"]:
                    row["_ts_last"] = ts_val

        # After-hours flag (any event outside 9-18)
        if hour is not None and (hour < 9 or hour >= 18):
            row["after_hours_activity"] += 1

        # OCEAN Neuroticism proxy: count events outside business hours (8-18)
        if hour is not None:
            if hour < 8 or hour >= 18:
                row["_events_outside_hours"] += 1
            else:
                row["_events_in_hours"] += 1

        # ------------------------------------------------------------------
        # Per-event-code feature extraction
        # ------------------------------------------------------------------

        if event_code == "4624":
            # Successful logon
            row["logon_count"] += 1
            if hour is not None:
                row["_logon_hours"].append(hour)
            # Extraversion proxy: LogonType 3 = network (remote) logon
            logon_type = _field("logon_type", "LogonType")
            if logon_type == "3":
                row["_network_logon_count"] += 1

        elif event_code in {"4625", "4776"}:
            # Failed logon (4625) or credential validation failure (4776)
            row["failed_logon_count"] += 1

        elif event_code == "4648":
            # Explicit credential logon (runas / over-the-shoulder) — counts as
            # a failed-auth signal because it implies the standard token was
            # insufficient and a credential was explicitly supplied.
            row["failed_logon_count"] += 1

        elif event_code in {"4634", "4647"}:
            # Logoff (4634 = system-initiated, 4647 = user-initiated)
            row["logoff_count"] += 1

        elif event_code in {"4663", "4670"}:
            # 4663: Object (file) access attempt — read the accessed object name.
            # 4670: Permissions on an object changed — treat as a file operation.
            row["file_ops_count"] += 1
            row["file_read_count"] += 1
            file_path_val = (
                _field("file_path", "ObjectName")
                or e.get("file", {}).get("path", "")
                or event_data.get("ObjectName", "")
            )
            if file_path_val:
                row["unique_files_set"].add(str(file_path_val))
                dir_part = str(Path(file_path_val).parent)
                if dir_part:
                    row["unique_dirs_set"].add(dir_part)

        elif event_code == "4672":
            # Special privileges assigned to a new logon (admin/elevated session).
            # Contributes to device_events as a privilege-use indicator and
            # inflates the after-hours / Neuroticism proxy when it occurs
            # outside business hours (already handled by the generic hour check).
            row["device_events"] += 1

        elif event_code == "4688":
            # Process creation — record the launched binary in unique_files_set so
            # that process diversity is reflected in unique_files_accessed.
            # We deliberately do NOT increment file_ops_count here: 4688 fires for
            # every background service, antivirus scan and shell command, so counting
            # it as a file operation inflates file_ops_count by hundreds of events
            # per lookback window on any normal workstation and causes the fast-path
            # rule to fire false positives for every user.
            proc_name = _field("process_name", "ProcessName", "NewProcessName")
            if proc_name:
                row["unique_files_set"].add(proc_name)

        elif event_code in {"4697", "4698", "4699", "4700", "4719", "4720", "4726", "4732"}:
            # Elevated system-change events: service install, scheduled task
            # lifecycle, audit policy changes, account creation/deletion/group change.
            # These indicate privileged actions beyond normal user activity and are
            # mapped to device_events (the model's existing "elevated activity" feature).
            row["device_events"] += 1

        # ------------------------------------------------------------------
        # Sysmon-sourced file events (Winlogbeat path only)
        # These fire alongside Security log events; process them independently.
        # ------------------------------------------------------------------
        if event_code in {"11", "23"}:
            row["file_ops_count"] += 1
            row["file_write_count"] += 1
        elif event_code == "15":
            row["file_ops_count"] += 1
            row["file_read_count"] += 1
        elif ("microsoft-windows-sysmon" in provider
              and event_code not in {
                  "4624", "4625", "4634", "4647", "4648",
                  "4663", "4670", "4672", "4688",
                  "4697", "4698", "4699", "4700",
                  "4719", "4720", "4726", "4732", "4776",
              }):
            row["file_ops_count"] += 1
            row["file_read_count"] += 1

        # Generic file path extraction for Winlogbeat events that carry the path
        # in standard ECS fields (not handled by the per-event-code blocks above).
        if event_code not in {"4663", "4670", "4688"}:
            file_path_val = (
                e.get("file", {}).get("path")
                or event_data.get("TargetFilename")
                or ""
            )
            if file_path_val:
                row["unique_files_set"].add(str(file_path_val))
                dir_part = str(Path(file_path_val).parent) if file_path_val else ""
                if dir_part:
                    row["unique_dirs_set"].add(dir_part)

        # Device/USB events (keyword-based — applies to all event codes)
        if "usb" in msg or "usbstor" in msg or "removable" in msg:
            row["device_events"] += 1
            if "disconnect" in msg or "remove" in msg:
                row["device_disconnects"] += 1
            else:
                row["device_connects"] += 1

        # Email events
        if "smtp" in msg or "outlook" in msg or "email" in msg:
            row["emails_sent"] += 1
            recipient = (
                e.get("email", {}).get("to", {}).get("address")
                or e.get("destination", {}).get("user", {}).get("name")
                or ""
            )
            if recipient:
                row["unique_recipients_set"].add(str(recipient))

    rows = []
    for data in by_user.values():
        # Calculate file_ops_rate (ops per second over active window, min 1s)
        if data["_ts_first"] is not None and data["_ts_last"] is not None:
            window_sec = max(
                1.0,
                (data["_ts_last"] - data["_ts_first"]).total_seconds()
            )
        else:
            window_sec = 1.0
        file_ops_rate = round(data["file_ops_count"] / window_sec, 6)

        # ------------------------------------------------------------------
        # OCEAN behavioral proxies
        # These approximate the psychometric dimensions from the CERT r4.2
        # training data using observable Windows event log signals.
        # All values are clamped to [0.0, 1.0] to match the training scale.
        #
        # NOTE: These are behavioral approximations, not true psychometric
        # scores. The model was trained on actual OCEAN values; these proxies
        # reduce (but do not eliminate) the degradation from 0.0 defaults.
        # ------------------------------------------------------------------
        total_ev = max(1, data["_total_events"])  # safe denominator

        # Openness (O): diversity of event sources (unique providers / total events)
        # High provider diversity → user interacts with many subsystems → more open.
        n_providers = len(data["_unique_providers"])
        O_proxy = round(min(1.0, n_providers / max(1, total_ev ** 0.5)), 4)

        # Conscientiousness (C): regularity of login times
        # Low std of logon hours → consistent schedule → more conscientious.
        # Inverted and normalized: C = 1 - (std / 12.0), clamped [0, 1].
        logon_hours = data["_logon_hours"]
        if len(logon_hours) >= 2:
            std_hours = float(np.std(logon_hours))
            C_proxy = round(max(0.0, min(1.0, 1.0 - std_hours / 12.0)), 4)
        elif len(logon_hours) == 1:
            C_proxy = 0.8  # single logon → assume regular (no evidence of irregularity)
        else:
            C_proxy = 0.5  # no logon data → neutral

        # Extraversion (E): proportion of network (type-3) logons vs total logons
        # More remote/network logons → more extraverted (outward-facing activity).
        total_logons = max(1, data["logon_count"])
        E_proxy = round(min(1.0, data["_network_logon_count"] / total_logons), 4)

        # Agreeableness (A): inverse of failed authentication ratio
        # Fewer auth failures → more agreeable (less adversarial behavior).
        # A = 1 - (failed_logon_count / total_events), clamped [0, 1].
        A_proxy = round(max(0.0, min(1.0, 1.0 - data["failed_logon_count"] / total_ev)), 4)

        # Neuroticism (N): after-hours activity ratio
        # More events outside 8am–6pm → higher neuroticism.
        total_timed = data["_events_in_hours"] + data["_events_outside_hours"]
        if total_timed > 0:
            N_proxy = round(min(1.0, data["_events_outside_hours"] / total_timed), 4)
        else:
            N_proxy = 0.0

        rows.append({
            "user": data["user"],
            # file
            "file_ops_count": data["file_ops_count"],
            "file_write_count": data["file_write_count"],
            "file_read_count": data["file_read_count"],
            "unique_files_accessed": len(data["unique_files_set"]),
            "file_ops_rate": file_ops_rate,
            # logon
            "logon_count": data["logon_count"],
            "logoff_count": data["logoff_count"],
            "failed_logon_count": data["failed_logon_count"],
            # after-hours
            "after_hours_activity": data["after_hours_activity"],
            # device
            "device_connects": data["device_connects"],
            "device_disconnects": data["device_disconnects"],
            "device_events": data["device_events"],
            # email
            "emails_sent": data["emails_sent"],
            "unique_recipients": len(data["unique_recipients_set"]),
            # OCEAN behavioral proxies (derived from Windows event log signals)
            "O": O_proxy,  # Openness: event-source diversity ratio
            "C": C_proxy,  # Conscientiousness: login-time regularity (inverted std)
            "E": E_proxy,  # Extraversion: network logon proportion
            "A": A_proxy,  # Agreeableness: inverse failed-auth ratio
            "N": N_proxy,  # Neuroticism: after-hours activity ratio
            # internal — kept for backward-compat display in the output rows
            "_unique_dirs": len(data["unique_dirs_set"]),
        })
    return pd.DataFrame(rows)


def _winlogbeat_is_fresh(log_dir: Path, max_age_seconds: int = 300) -> bool:
    """Return True if at least one Winlogbeat NDJSON file in log_dir exists
    and was modified within the last max_age_seconds.  Returns False when the
    directory is absent, empty, or all files are stale."""
    if not log_dir.exists():
        return False
    now = datetime.now(timezone.utc).timestamp()
    for p in log_dir.iterdir():
        if p.is_file() and (p.name.startswith("winlogbeat") or p.suffix == ".ndjson"):
            try:
                if (now - p.stat().st_mtime) <= max_age_seconds:
                    return True
            except OSError:
                continue
    return False


import logging as _logging
import re as _re
import subprocess as _subprocess
_log = _logging.getLogger(__name__)

# Event IDs collected from the Windows Security log.
# These cover authentication, privilege use, file/object access, process
# creation, service/task changes, and account management.
_SECURITY_EVENT_IDS = (
    "4624", "4625", "4634", "4647", "4648",
    "4663", "4670", "4672", "4688", "4697",
    "4698", "4699", "4700", "4719", "4720",
    "4726", "4732", "4776",
)

# XPath OR expression used in the Get-WinEvent -FilterXPath argument.
_EVENT_ID_XPATH = " or ".join(f"EventID={eid}" for eid in _SECURITY_EVENT_IDS)

_SKIP_USERS = frozenset({
    "SYSTEM", "LOCAL SERVICE", "NETWORK SERVICE",
    "ANONYMOUS LOGON", "IUSR", "DWM-1", "UMFD-0", "UMFD-1",
    "UNKNOWN",
})

# Prefix patterns for service/virtual accounts — matched case-insensitively.
_SKIP_USER_PREFIXES = ("DWM-", "UMFD-", "FONT DRIVER HOST")

# Hostname of the machine running the backend, used to filter out Windows
# computer accounts that appear in event logs under the machine name.
# Populated once at module load; fine to be empty string if psutil is absent.
try:
    import socket as _socket
    _MACHINE_HOSTNAME = _socket.gethostname().upper()
except Exception:
    _MACHINE_HOSTNAME = ""


def _should_skip_user(username: str) -> bool:
    """Return True if the username should be excluded from user behavior analysis.

    Filters:
    - Empty or whitespace-only names
    - Windows computer accounts ending in '$'
    - Well-known system/service accounts (SYSTEM, LOCAL SERVICE, etc.)
    - Virtual session accounts with numeric suffixes (DWM-*, UMFD-*, etc.)
    - Usernames that match the machine hostname (e.g. 'DELL' on a Dell machine)
    """
    if not username or not username.strip():
        return True
    u = username.strip()
    # Windows computer account (always ends with '$')
    if u.endswith("$"):
        return True
    u_upper = u.upper()
    # Exact match against known system accounts
    if u_upper in _SKIP_USERS:
        return True
    # Prefix match for numbered virtual accounts (DWM-2, UMFD-3, etc.)
    for prefix in _SKIP_USER_PREFIXES:
        if u_upper.startswith(prefix):
            return True
    # Machine hostname match — catches 'DELL', 'PC-LAB01', etc.
    if _MACHINE_HOSTNAME and u_upper == _MACHINE_HOSTNAME:
        return True
    return False


def _parse_event_message(message: str) -> Dict[str, Any]:
    """Extract structured key-value pairs from a Windows Security event Message field.

    The Message field contains lines of the form:
        Account Name:    jsmith
        Logon Type:      3
        Process Name:    C:\\Windows\\explorer.exe
        Workstation Name: PC-1
        Object Name:     C:\\sensitive\\file.docx

    Returns a dict with string values for each recognised key. Unknown keys
    are also captured so callers can inspect raw message content.
    """
    parsed: Dict[str, Any] = {}
    for key, value in _re.findall(r"^\s*([\w\s]+?):\s+(.+)$", message, _re.MULTILINE):
        parsed[key.strip()] = value.strip()

    # Normalise the most common field names used by downstream extractors.
    # The raw Message uses inconsistent capitalisation across event types.
    def _get(*keys: str) -> str:
        for k in keys:
            v = parsed.get(k, "")
            if v:
                return v
        return ""

    return {
        "_raw": parsed,
        "account_name": _get("Account Name", "New Account Name", "Target Account Name"),
        "logon_type": _get("Logon Type"),
        "process_name": _get("Process Name", "New Process Name", "Application Name"),
        "workstation": _get("Workstation Name", "Caller Workstation"),
        "file_path": _get("Object Name", "File Name"),
        "service_name": _get("Service Name"),
        "task_name": _get("Task Name"),
    }


def _normalize_powershell_item(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert a single PowerShell Get-WinEvent item to the normalised event dict.

    Returns None if the item should be skipped (missing ID, system account only).
    """
    try:
        event_id = str(item.get("Id", ""))
        ts_raw = item.get("TimeCreated", "")
        # PowerShell serialises DateTime as "/Date(ms_epoch)/" or ISO string
        if isinstance(ts_raw, str) and ts_raw.startswith("/Date("):
            ms = int(ts_raw[6:ts_raw.index(")")])
            ts_iso = datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc).isoformat()
        else:
            ts_iso = str(ts_raw)

        msg = str(item.get("Message", ""))
        parsed_msg = _parse_event_message(msg)

        # Prefer the structured account_name extracted from the message body.
        # Fall back to the UserId SID only when no account name is available.
        user_name = ""
        candidate = parsed_msg.get("account_name", "")
        if (candidate
                and not candidate.startswith(("C:\\", "D:\\", "\\\\", "S-1-", "0x", "{"))
                and not candidate.isdigit()
                and len(candidate) >= 2
                and not _should_skip_user(candidate)):
            user_name = candidate

        # Parse logon_type as int for the Extraversion OCEAN proxy
        logon_type_raw = parsed_msg.get("logon_type", "")
        try:
            logon_type = int(logon_type_raw) if logon_type_raw else 0
        except ValueError:
            logon_type = 0

        provider = str(item.get("ProviderName", "")).lower()
        computer = str(item.get("ComputerName", "localhost"))
        workstation = parsed_msg.get("workstation", "")
        process_name = parsed_msg.get("process_name", "")
        file_path_val = parsed_msg.get("file_path", "")

        return {
            "@timestamp": ts_iso,
            "winlog": {
                "event_id": event_id,
                "provider_name": provider,
                "event_data": {
                    "TargetUserName": user_name,
                    "LogonType": str(logon_type) if logon_type else "",
                    "ProcessName": process_name,
                    "WorkstationName": workstation,
                    "ObjectName": file_path_val,
                },
                "user_data": {"TargetUserName": user_name},
            },
            "user": {"name": user_name} if user_name else {},
            "host": {"name": computer},
            # Keep the original message (lowered) for USB/email keyword matching
            "message": msg.lower(),
            # Structured fields extracted for richer feature mapping
            "_parsed": parsed_msg,
        }
    except Exception:
        return None


def _build_ps_query(lookback_minutes: int) -> str:
    """Build the PowerShell Get-WinEvent command string.

    Uses a compound XPath filter so only the 18 target event IDs are retrieved,
    reducing both query time and result set size.  MaxEvents is 500 to ensure
    enough history is available for the 120-minute lookback window.
    """
    lookback_ms = lookback_minutes * 60 * 1000
    xpath = (
        f"*[System[({_EVENT_ID_XPATH}) "
        f"and TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]"
    )
    return (
        f'Get-WinEvent -LogName Security -MaxEvents 500 '
        f'-FilterXPath "{xpath}" '
        f'-ErrorAction SilentlyContinue '
        f"| Select-Object Id,TimeCreated,"
        f"@{{n='ProviderName';e={{$_.ProviderName}}}},"
        f"@{{n='Message';e={{$_.Message}}}},"
        f"@{{n='UserId';e={{if($_.UserId){{$_.UserId.Value}}else{{''}}}}}},"
        f"@{{n='ComputerName';e={{$_.MachineName}}}}"
        f"| ConvertTo-Json -Depth 2"
    )


def read_windows_event_logs_direct(lookback_minutes: int = 120) -> List[Dict[str, Any]]:
    """Read Windows Security event logs directly via PowerShell Get-WinEvent.

    This replaces the former win32evtlog implementation which produced persistent
    winerror 6 (ERROR_INVALID_HANDLE) failures on Windows 10/11.  PowerShell
    Get-WinEvent is the Microsoft-recommended alternative and does not require
    the pywin32 package.

    Collects event IDs: 4624, 4625, 4634, 4647, 4648, 4663, 4670, 4672, 4688,
    4697, 4698, 4699, 4700, 4719, 4720, 4726, 4732, 4776.

    Used as a fallback when Winlogbeat NDJSON files are absent or stale (> 300 s).
    Returns events in the same normalised dict shape as read_ndjson_logs().
    """
    ps_script = _build_ps_query(lookback_minutes)
    try:
        result = _subprocess.run(
            ["powershell", "-NonInteractive", "-Command", ps_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (FileNotFoundError, _subprocess.TimeoutExpired) as exc:
        _log.debug("PowerShell fallback unavailable: %s", exc)
        return []

    if result.returncode != 0 or not result.stdout.strip():
        _log.debug("PowerShell Get-WinEvent returned no output (rc=%d)", result.returncode)
        return []

    try:
        raw = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        _log.debug("PowerShell output JSON parse error: %s", exc)
        return []

    if isinstance(raw, dict):
        raw = [raw]

    events: List[Dict[str, Any]] = []
    for item in raw:
        normalized = _normalize_powershell_item(item)
        if normalized is not None:
            events.append(normalized)

    return events


def _sigmoid_score(raw: float) -> float:
    """Map a decision_function output to [0, 1] anomaly probability.

    Convention: higher output value = more anomalous.

    For IsolationForest, decision_function() returns negative values for
    anomalies and positive values for normal points.  To produce a score
    where 1.0 = most anomalous and 0.0 = most normal, raw is negated before
    the sigmoid is applied:

        score = sigmoid(-raw * k) = 1 / (1 + exp(raw * k))

    With k=5 (softer curve than the training-time k=10):
      - raw = -0.30 (strong anomaly)  → score ≈ 0.82
      - raw =  0.00 (boundary)        → score = 0.50
      - raw = +0.20 (clear normal)    → score ≈ 0.27

    This matches the training-script sigmoid convention
    (train_user_model.py: 1 / (1 + exp(raw * 10))) so that the calibrated
    threshold stored in model_threshold.json is directionally consistent with
    the runtime scores it is compared against.

    The multiplier 5 (vs the training-time 10) softens the curve so that
    borderline scores (|raw| ≈ 0.1–0.3) produce probabilities in the 0.3–0.7
    range rather than collapsing to near-0 or near-1.

    NOTE: the previous formula was 1 / (1 + exp(-raw * 5)) which maps anomalies
    (negative raw) toward 0.0 — the opposite of the documented convention and the
    training-time formula.  That inversion caused the deployed threshold of 0.80
    to produce recall=0 because all insider-threat samples scored below 0.50.
    """
    # Positive exponent negates raw: anomalies (negative raw) → score near 1.0
    return float(1.0 / (1.0 + np.exp(raw * 5)))


def _build_anomaly_reason(r: pd.Series, threshold: float) -> str:
    reasons = []
    if r.get("_fast_path_triggered"):
        reasons.append(f"Fast-path rule: file_ops_count={r['file_ops_count']} exceeded {FAST_PATH_FILE_OPS}")
    if r.get("after_hours_activity", 0) > 5:
        reasons.append("Elevated after-hours activity")
    if r.get("device_events", 0) >= 10:
        reasons.append("USB burst")
    if r.get("file_ops_count", 0) >= 100:
        reasons.append(f"High file activity ({int(r['file_ops_count'])} ops)")
    if r.get("failed_logon_count", 0) >= 5:
        reasons.append(f"Repeated failed logons ({int(r['failed_logon_count'])})")
    if float(r.get("anomaly_score", 0.0)) >= threshold:
        reasons.append(f"Model score {float(r['anomaly_score']):.3f} >= threshold {threshold:.3f}")
    return ", ".join(reasons) if reasons else "No strong anomaly indicators"


def run_inference(
    lookback_minutes: int = _DEFAULT_LOOKBACK_MINUTES,
    threshold_override: Optional[float] = None,
    usb_override_threshold: int = 10,
) -> Dict[str, Any]:
    """
    Run user behavior inference over recent Windows event logs.

    Returns a dict with the following shape (preserved for UserBehaviorAgent):
    {
        "threshold": float,
        "lookback_minutes": int,
        "events_count": int,
        "log_files_count": int,
        "summary": {"total_users": int, "normal": int, "anomaly": int, "avg_score": float},
        "rows": [
            {
                "user": str,
                "prediction_label": "NORMAL" | "ANOMALY",
                "anomaly_score": float,           # 0-1, higher = more anomalous
                "total_logins": int,               # backward-compat alias for logon_count
                "avg_login_hour": float,           # backward-compat (0.0 when no logon data)
                "after_hours_logins": int,         # backward-compat alias
                "device_events": int,
                "usb_connects": int,               # backward-compat alias for device_connects
                "files_accessed": int,             # backward-compat alias for file_ops_count
                "emails_sent": int,
                "time_anomaly": bool,
                "usb_burst": bool,
                "activity_spike": bool,
                "anomaly_reason": str,
            }
        ]
    }
    """
    model = load_pickle(MODEL_PATH)
    scaler = load_pickle(SCALER_PATH)
    feature_columns = load_feature_columns(FEATURES_PATH)
    threshold = threshold_override if threshold_override is not None else load_threshold(THRESHOLD_PATH)
    scaler_features = list(getattr(scaler, "feature_names_in_", feature_columns))

    # Data source priority:
    # 1. Winlogbeat NDJSON (richer data, more fields) — used only when the file
    #    exists, is fresh (< 300 s old), and actually contains recent events.
    # 2. PowerShell Get-WinEvent (primary fallback, works on any Windows machine
    #    with no additional tooling).
    if _winlogbeat_is_fresh(LOG_DIR, max_age_seconds=300):
        events_all = read_ndjson_logs(LOG_DIR)
        events = filter_recent_events(events_all, lookback_minutes)
        if events:
            _log.debug("User behavior: reading from Winlogbeat (%d events)", len(events))
        else:
            _log.debug(
                "User behavior: Winlogbeat file is fresh but has no recent events — "
                "falling back to PowerShell Get-WinEvent"
            )
            events = read_windows_event_logs_direct(lookback_minutes)
    else:
        _log.debug(
            "User behavior: reading from Get-WinEvent (Winlogbeat not configured)"
        )
        events = read_windows_event_logs_direct(lookback_minutes)

    df = normalize_events_to_features(events)

    log_files_count = len(list(LOG_DIR.glob("*.ndjson"))) if LOG_DIR.exists() else 0

    if df.empty:
        return {
            "threshold": threshold,
            "lookback_minutes": lookback_minutes,
            "events_count": len(events),
            "log_files_count": log_files_count,
            "rows": [],
            "summary": {"total_users": 0, "normal": 0, "anomaly": 0, "avg_score": 0.0},
        }

    # Ensure all model features exist in df
    for col in scaler_features:
        if col not in df.columns:
            df[col] = 0.0

    X = df[scaler_features].fillna(0.0)
    X_scaled = scaler.transform(X)

    # Score via decision_function; map to [0,1] where 1 = most anomalous
    if hasattr(model, "decision_function"):
        raw_scores = model.decision_function(X_scaled)
        anomaly_scores = np.array([_sigmoid_score(r) for r in raw_scores])
    elif hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_scaled)
        anomaly_scores = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
    else:
        anomaly_scores = model.predict(X_scaled).astype(float)

    labels = np.where(anomaly_scores >= threshold, "ANOMALY", "NORMAL")

    # USB override (configurable)
    df["_fast_path_triggered"] = False
    if usb_override_threshold > 0 and "device_events" in df.columns:
        usb_mask = df["device_events"].to_numpy() >= usb_override_threshold
        labels = np.where(usb_mask, "ANOMALY", labels)

    # Fast-path rules: immediately flag without ML score for obvious bulk ops
    # These override the ML decision to ensure the rule fires reliably
    if "file_ops_count" in df.columns:
        bulk_file_mask = df["file_ops_count"].to_numpy() >= FAST_PATH_FILE_OPS
        labels = np.where(bulk_file_mask, "ANOMALY", labels)
        # Boost score to 1.0 so the dashboard shows maximum severity
        anomaly_scores = np.where(bulk_file_mask, np.maximum(anomaly_scores, 1.0), anomaly_scores)
        df.loc[bulk_file_mask, "_fast_path_triggered"] = True

    # Directory scan fast-path: "_unique_dirs" is computed in normalize_events_to_features
    if "_unique_dirs" in df.columns:
        dir_scan_mask = df["_unique_dirs"].to_numpy() >= FAST_PATH_DIR_SCANS
        labels = np.where(dir_scan_mask, "ANOMALY", labels)
        anomaly_scores = np.where(dir_scan_mask, np.maximum(anomaly_scores, 1.0), anomaly_scores)
        df.loc[dir_scan_mask, "_fast_path_triggered"] = True

    out = df.copy()
    out["prediction_label"] = labels
    out["anomaly_score"] = np.round(anomaly_scores, 4)

    # Backward-compatible aliases for the dashboard / UserBehaviorAgent
    out["total_logins"] = out.get("logon_count", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["avg_login_hour"] = 0.0   # not tracked per-event in new feature set
    out["after_hours_logins"] = out.get("after_hours_activity", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["usb_connects"] = out.get("device_connects", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["files_accessed"] = out.get("file_ops_count", pd.Series(0, index=out.index)).fillna(0).astype(int)

    out["time_anomaly"] = (out["after_hours_activity"] > 5).map({True: "YES", False: "NO"})
    out["usb_burst"] = (out["device_events"] >= max(1, usb_override_threshold)).map({True: "YES", False: "NO"})
    out["activity_spike"] = (out["file_ops_count"] >= FAST_PATH_FILE_OPS).map({True: "YES", False: "NO"})
    out["anomaly_reason"] = out.apply(lambda r: _build_anomaly_reason(r, threshold), axis=1)

    total = len(out)
    anomalies = int((out["prediction_label"] == "ANOMALY").sum())
    avg_score = float(np.mean(out["anomaly_score"])) if total > 0 else 0.0

    return {
        "threshold": threshold,
        "lookback_minutes": lookback_minutes,
        "events_count": len(events),
        "log_files_count": log_files_count,
        "summary": {
            "total_users": total,
            "normal": total - anomalies,
            "anomaly": anomalies,
            "avg_score": round(avg_score, 4),
        },
        "rows": out[
            [
                "user",
                "prediction_label",
                "anomaly_score",
                "total_logins",
                "avg_login_hour",
                "after_hours_logins",
                "device_events",
                "usb_connects",
                "files_accessed",
                "emails_sent",
                "time_anomaly",
                "usb_burst",
                "activity_spike",
                "anomaly_reason",
            ]
        ].to_dict(orient="records"),
    }


def run_inference_from_events(
    events: List[Dict[str, Any]],
    threshold_override: Optional[float] = None,
    usb_override_threshold: int = 10,
) -> Dict[str, Any]:
    """
    Run user behavior inference on a pre-loaded event list.

    Same pipeline as run_inference() but receives events in memory instead
    of reading from disk. Used by the backend endpoint ingest handler when
    the endpoint agent ships winlogbeat_events inline.

    Parameters
    ----------
    events : list of dicts
        Winlogbeat NDJSON event dicts (same format as read_ndjson_logs returns).
    threshold_override : float, optional
        Override the model threshold from model_threshold.json.
    usb_override_threshold : int
        Minimum device_events count before forcing ANOMALY label.

    Returns
    -------
    Same dict shape as run_inference().
    """
    model = load_pickle(MODEL_PATH)
    scaler = load_pickle(SCALER_PATH)
    feature_columns = load_feature_columns(FEATURES_PATH)
    threshold = threshold_override if threshold_override is not None else load_threshold(THRESHOLD_PATH)
    scaler_features = list(getattr(scaler, "feature_names_in_", feature_columns))

    df = normalize_events_to_features(events)

    if df.empty:
        return {
            "threshold": threshold,
            "lookback_minutes": 0,
            "events_count": len(events),
            "log_files_count": 0,
            "rows": [],
            "summary": {"total_users": 0, "normal": 0, "anomaly": 0, "avg_score": 0.0},
        }

    for col in scaler_features:
        if col not in df.columns:
            df[col] = 0.0

    X = df[scaler_features].fillna(0.0)
    X_scaled = scaler.transform(X)

    if hasattr(model, "decision_function"):
        raw_scores = model.decision_function(X_scaled)
        anomaly_scores = np.array([_sigmoid_score(r) for r in raw_scores])
    elif hasattr(model, "predict_proba"):
        probs = model.predict_proba(X_scaled)
        anomaly_scores = probs[:, 1] if probs.shape[1] > 1 else probs[:, 0]
    else:
        anomaly_scores = model.predict(X_scaled).astype(float)

    labels = np.where(anomaly_scores >= threshold, "ANOMALY", "NORMAL")

    df["_fast_path_triggered"] = False
    if usb_override_threshold > 0 and "device_events" in df.columns:
        usb_mask = df["device_events"].to_numpy() >= usb_override_threshold
        labels = np.where(usb_mask, "ANOMALY", labels)

    if "file_ops_count" in df.columns:
        bulk_file_mask = df["file_ops_count"].to_numpy() >= FAST_PATH_FILE_OPS
        labels = np.where(bulk_file_mask, "ANOMALY", labels)
        anomaly_scores = np.where(bulk_file_mask, np.maximum(anomaly_scores, 1.0), anomaly_scores)
        df.loc[bulk_file_mask, "_fast_path_triggered"] = True

    if "_unique_dirs" in df.columns:
        dir_scan_mask = df["_unique_dirs"].to_numpy() >= FAST_PATH_DIR_SCANS
        labels = np.where(dir_scan_mask, "ANOMALY", labels)
        anomaly_scores = np.where(dir_scan_mask, np.maximum(anomaly_scores, 1.0), anomaly_scores)
        df.loc[dir_scan_mask, "_fast_path_triggered"] = True

    out = df.copy()
    out["prediction_label"] = labels
    out["anomaly_score"] = np.round(anomaly_scores, 4)

    out["total_logins"] = out.get("logon_count", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["avg_login_hour"] = 0.0
    out["after_hours_logins"] = out.get("after_hours_activity", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["usb_connects"] = out.get("device_connects", pd.Series(0, index=out.index)).fillna(0).astype(int)
    out["files_accessed"] = out.get("file_ops_count", pd.Series(0, index=out.index)).fillna(0).astype(int)

    out["time_anomaly"] = (out["after_hours_activity"] > 5).map({True: "YES", False: "NO"})
    out["usb_burst"] = (out["device_events"] >= max(1, usb_override_threshold)).map({True: "YES", False: "NO"})
    out["activity_spike"] = (out["file_ops_count"] >= FAST_PATH_FILE_OPS).map({True: "YES", False: "NO"})
    out["anomaly_reason"] = out.apply(lambda r: _build_anomaly_reason(r, threshold), axis=1)

    total = len(out)
    anomalies = int((out["prediction_label"] == "ANOMALY").sum())
    avg_score = float(np.mean(out["anomaly_score"])) if total > 0 else 0.0

    return {
        "threshold": threshold,
        "lookback_minutes": 0,
        "events_count": len(events),
        "log_files_count": 0,
        "summary": {
            "total_users": total,
            "normal": total - anomalies,
            "anomaly": anomalies,
            "avg_score": round(avg_score, 4),
        },
        "rows": out[
            [
                "user", "prediction_label", "anomaly_score",
                "total_logins", "avg_login_hour", "after_hours_logins",
                "device_events", "usb_connects", "files_accessed",
                "emails_sent", "time_anomaly", "usb_burst",
                "activity_spike", "anomaly_reason",
            ]
        ].to_dict(orient="records"),
    }


def get_service_status(name: str) -> str:
    """Return the running status of a Windows service by name.
    Uses psutil to avoid PowerShell command injection."""
    try:
        return psutil.win_service_get(name).status()
    except psutil.NoSuchProcess:
        return "not_found"
    except Exception:
        return "unknown"


def get_log_health() -> Dict[str, Any]:
    files = sorted(LOG_DIR.glob("*.ndjson")) if LOG_DIR.exists() else []
    total_bytes = sum(fp.stat().st_size for fp in files) if files else 0
    last_modified = max((fp.stat().st_mtime for fp in files), default=None)
    return {
        "path": str(LOG_DIR),
        "files": len(files),
        "total_mb": round(total_bytes / (1024 * 1024), 2),
        "latest_modified_epoch": last_modified,
    }
