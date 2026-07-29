"""
SysmonBehaviorAgent — Cyber Sentinel XDR
Async agent that reads Sysmon events, maintains a per-PID rolling token
window, and scores each window using a pre-trained WindowsAnomalyDetector
(TF-IDF + XGBoost/RandomForest + IsolationForest).

This agent is SEPARATE from system_monitor_agent.py, which handles psutil
LSTM telemetry.  This agent handles process-level behavioral anomalies
derived from Sysmon EventIDs 1, 3, 7, 8, 10, 11, 12, 13, 22, 25, etc.

Event source:
    Winlogbeat NDJSON file (sysmon_log_path).
    The Windows Event Log / win32evtlog approach has been abandoned due to
    persistent winerror 6 failures.  All events are read from the file that
    Winlogbeat writes at C:\\winlogbeat\\logs\\sysmon_events.json.

Artifact expected:
    <model_pkl_path>   — pickled WindowsAnomalyDetector (detector.pkl)

Callback signature:
    async def on_result(result: dict): ...

    result keys:
        anomaly_score   float  [0.0, 1.0]   (normalised; raw / 3.0 clipped)
        severity        str    CRITICAL | HIGH | MEDIUM | LOW
        label           str    attack label from classifier
        process_name    str    basename of the triggering process image
        pid             str    process ID as string
        confidence      float  classifier confidence [0.0, 1.0]
        high_risk       bool   True when EventID 8 or 25 triggered the score
        ts              str    ISO-8601 UTC timestamp
        source          str    "sysmon_behavior"
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import pickle
import re
import sys
import time
from collections import deque, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable, Dict, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Windows Event Log reader — file-based only; win32evtlog abandoned
# ---------------------------------------------------------------------------
_WINEVENT_AVAILABLE = False  # file-based reader only

# ---------------------------------------------------------------------------
# Constants — copied inline from windows_detector_final.py
# (Do NOT import from that file; it is a standalone CLI script.)
# ---------------------------------------------------------------------------

BENIGN_LABEL = "Background"

BENIGN_WHITELIST: set = {
    "system", "registry", "smss.exe", "csrss.exe", "wininit.exe",
    "winlogon.exe", "services.exe", "lsass.exe", "lsm.exe",
    "svchost.exe", "spoolsv.exe", "dwm.exe", "explorer.exe",
    "taskhostw.exe", "sihost.exe", "fontdrvhost.exe",
    "runtimebroker.exe", "conhost.exe", "ctfmon.exe",
    "trustedinstaller.exe", "tiworker.exe", "wuauclt.exe",
    "msiexec.exe", "wudfhost.exe",
    "searchindexer.exe", "searchprotocolhost.exe", "searchfilterhost.exe",
    "searchapp.exe",
    "wmiprvse.exe", "dllhost.exe", "msdtc.exe",
    "chrome.exe", "msedge.exe", "firefox.exe", "msedgewebview2.exe",
    "iexplore.exe",
    "microsoftedgeupdate.exe", "updater.exe", "googleupdate.exe",
    "backgroundtaskhost.exe", "smartscreen.exe", "consent.exe",
    "ipfsvc.exe", "lnbitssvc.exe", "wudfsvc.exe",
    "mpdefendercoreservice.exe", "msmpeng.exe", "nissrv.exe",
    "securityhealthservice.exe", "powershell_ise.exe",
    # NOTE: "unknown" deliberately omitted — an unresolvable image path is suspicious,
    # not safe. Do not whitelist processes whose identity cannot be confirmed.
}

HIGH_ALERT_PROCESSES: set = {
    "mimikatz.exe", "meterpreter.exe", "psexec.exe", "psexecsvc.exe",
}

SYSMON_EVENTS: dict = {
    "1":  "ProcessCreate",     "2":  "FileCreationTimeChanged",
    "3":  "NetworkConnect",    "5":  "ProcessTerminate",
    "6":  "DriverLoad",        "7":  "ImageLoad",
    "8":  "CreateRemoteThread","10": "ProcessAccess",
    "11": "FileCreate",        "12": "RegistryObjectAddedOrDeleted",
    "13": "RegistryValueSet",  "15": "FileCreateStreamHash",
    "17": "PipeCreated",       "22": "DNSQuery",
    "23": "FileDelete",        "25": "ProcessTampering",
    "26": "FileDeleteDetected",
}

HIGH_RISK: set = {"8", "25"}

# Scoring parameters — match SysmonMonitor defaults
_WINDOW_SIZE        = 200   # tokens per PID rolling window
_STRIDE             = 15    # score every N events per PID
_MIN_FEAT_HITS      = 5     # minimum TF-IDF non-zero features to trust a score
_ALERT_COOLDOWN_S   = 120   # seconds between repeated alerts for the same PID
# Minimum normalised score before a non-high-risk alert is fired.
# Prevents the IsolationForest from flooding alerts on score≈0 events that
# happen to cross the threshold with negligible anomaly signal.
_MIN_ALERT_SCORE    = 0.12

# Processes that are well-understood and known-good on this machine.
# Extend this set rather than lowering the score threshold globally.
_EXTENDED_WHITELIST: set = {
    "node.exe", "bash.exe", "git.exe", "git-remote-https.exe",
    "suricata.exe", "winlogbeat.exe", "sysmon64.exe",
    "python.exe", "pythonw.exe",
}

# Raw anomaly scores from IsolationForest decision_function are negated in
# predict() so they typically range from ~-2 (benign) to ~+3 (anomaly).
# We normalise to [0, 1] by dividing by 3.0 and clipping.
_RAW_SCORE_CEILING  = 3.0


# ---------------------------------------------------------------------------
# Token conversion — copied inline from windows_detector_final.py
# ---------------------------------------------------------------------------

def _sysmon_event_to_token(event: dict):
    """
    Convert a Sysmon event dict into (token_str, meta_dict).
    Returns (None, {}) if the event is not a recognised Sysmon EventID.

    Handles both formats:
    - New flat format from SysmonFileReader: {"event_id": int, "process": str, ...}
    - Old nested format from Winlogbeat NDJSON: {"winlog": {"event_id": "1", "event_data": {...}}}
    """
    try:
        # New flat format {"event_id": int, "process": str, ...}
        if "event_id" in event and not isinstance(event.get("event_id"), dict):
            event_id = str(event.get("event_id", ""))
            image    = event.get("process", "")
            data     = {
                "Image":           image,
                "ProcessId":       event.get("pid", "0"),
                "DestinationPort": event.get("dest_port", "0"),
                "DestinationIp":   event.get("dest_ip", ""),
                "TargetFilename":  event.get("file", ""),
                "CommandLine":     event.get("cmdline", ""),
                "Protocol":        "tcp",
            }
        else:
            # Old nested format {"winlog": {"event_id": "1", "event_data": {...}}}
            winlog   = event.get("winlog", event)
            event_id = str(winlog.get("event_id") or winlog.get("EventID") or "")
            data     = winlog.get("event_data", winlog.get("EventData", {}))
            image    = data.get("Image", data.get("ParentImage", ""))

        if event_id not in SYSMON_EVENTS:
            return None, {}

        eid_name = SYSMON_EVENTS[event_id]

        if event_id == "7":
            img   = data.get("ImageLoaded", data.get("Image", ""))
            base  = os.path.basename(img).lower()
            token = f"{base}+{eid_name}"
        elif event_id == "3":
            port  = data.get("DestinationPort", "0")
            proto = data.get("Protocol", "tcp")
            token = f"net+{eid_name}_{proto}_{port}"
        elif event_id in ("12", "13"):
            key   = data.get("TargetObject", "")
            hive  = key.split("\\")[0].lower() if "\\" in key else "registry"
            token = f"{hive}+{eid_name}"
        else:
            img   = data.get("Image", data.get("ParentImage", ""))
            base  = os.path.basename(img).lower() if img else "unknown.exe"
            token = f"{base}+{eid_name}"

        meta = {
            "event_id":    event_id,
            "pid":         str(data.get("ProcessId",
                               data.get("SourceProcessId", "0"))),
            "image":       data.get("Image",
                           data.get("ParentImage", "unknown")),
            "commandline": data.get("CommandLine", ""),
            "high_risk":   event_id in HIGH_RISK,
        }
        return token, meta
    except Exception:
        return None, {}


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

def _score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


# ---------------------------------------------------------------------------
# SysmonBehaviorAgent
# ---------------------------------------------------------------------------

class SysmonBehaviorAgent:
    """
    Async agent: Sysmon events → per-PID token window → score → callback.

    Parameters
    ----------
    model_pkl_path : str
        Absolute path to detector.pkl (pickled WindowsAnomalyDetector).
    sysmon_log_path : str
        Path to the Winlogbeat NDJSON output file (the only event source).
    on_result : async callable, optional
        Called with a result dict whenever a score is produced.
    on_telemetry : async callable, optional
        Called with a telemetry dict for every parsed event (rate-limited).
    use_win_event_log : bool
        Accepted for backwards compatibility but ignored.  The agent always
        reads from the Winlogbeat NDJSON file — win32evtlog has been abandoned.
    """

    def __init__(
        self,
        model_pkl_path: str,
        sysmon_log_path: str,
        on_result: Optional[Callable] = None,
        on_telemetry: Optional[Callable] = None,
        use_win_event_log: bool = False,
    ):
        self.model_pkl_path = model_pkl_path
        self.sysmon_log_path = sysmon_log_path
        self.on_result = on_result
        self.on_telemetry = on_telemetry
        self.use_win_event_log = use_win_event_log

        self._detector = None
        self._model_loaded = False
        self._running = False
        self._task: Optional[asyncio.Task] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None  # captured at start()

        # Per-PID state: {pid: {"window": deque, "counter": int, "image": str}}
        self._processes: Dict[str, dict] = {}

        # Cooldown tracker: {pid: last_alert_timestamp_float}
        self._last_alert_time: Dict[str, float] = {}

        # Telemetry rate-limiter: {pid: last_telemetry_timestamp_float}
        self._last_telemetry_time: Dict[str, float] = {}

        # Rolling summary counters
        self._total_events = 0
        self._total_alerts = 0
        self._last_score: float = 0.0

        self._load_model()

    # ------------------------------------------------------------------
    # Model loading
    # ------------------------------------------------------------------

    def _load_model(self) -> None:
        """Load the pickled WindowsAnomalyDetector.  Non-fatal on failure."""
        path = Path(self.model_pkl_path)
        if not path.exists():
            logger.warning(
                f"SysmonBehaviorAgent: model file not found at {path}. "
                "Agent will start in degraded mode — all scores return 0.0. "
                "Run train_sysmon_model.py to produce detector.pkl."
            )
            return

        # detector.pkl was saved from windows_detector_final.py running as __main__,
        # so pickle stores WindowsAnomalyDetector as __main__.WindowsAnomalyDetector.
        # We resolve this with a custom Unpickler that loads the class from the
        # source file at unpickle time, avoiding polluting sys.modules['__main__'].
        import importlib.util as _ilu
        import sys as _sys

        _wdf_script = path.parent.parent / "windows_detector_final.py"
        _wdf_mod = None

        if _wdf_script.exists():
            try:
                spec = _ilu.spec_from_file_location("_wdf_internal", str(_wdf_script))
                _wdf_mod = _ilu.module_from_spec(spec)
                spec.loader.exec_module(_wdf_mod)  # type: ignore[union-attr]
            except Exception as _e:
                logger.debug(f"SysmonBehaviorAgent: could not load wdf module: {_e}")
                _wdf_mod = None

        # Strict allowlist — only classes that legitimately appear in detector.pkl
        # are permitted.  Any other class raises an error, blocking code-execution
        # attacks via a compromised .pkl file.
        _PICKLE_ALLOWLIST: set = {
            ("__main__",           "WindowsAnomalyDetector"),
            ("sklearn.feature_extraction.text", "TfidfVectorizer"),
            ("sklearn.ensemble._forest",        "RandomForestClassifier"),
            ("sklearn.ensemble._iforest",       "IsolationForest"),
            ("sklearn.preprocessing._label",    "LabelEncoder"),
            ("xgboost.sklearn",                 "XGBClassifier"),
            ("numpy",                           "dtype"),
            ("numpy.core.multiarray",           "_reconstruct"),
            ("numpy",                           "ndarray"),
            ("builtins",                        "object"),
            ("collections",                     "OrderedDict"),
        }

        class _DetectorUnpickler(pickle.Unpickler):
            def find_class(self, module: str, name: str):
                if name == "WindowsAnomalyDetector" and module == "__main__":
                    if _wdf_mod is not None and hasattr(_wdf_mod, "WindowsAnomalyDetector"):
                        return _wdf_mod.WindowsAnomalyDetector
                # Allow numpy internals (many submodule paths)
                if module.startswith("numpy"):
                    return super().find_class(module, name)
                # Allow sklearn internals
                if module.startswith("sklearn"):
                    return super().find_class(module, name)
                # Allow xgboost
                if module.startswith("xgboost"):
                    return super().find_class(module, name)
                # Allow scipy (used by sklearn sparse matrices)
                if module.startswith("scipy"):
                    return super().find_class(module, name)
                # Allow Python builtins (bytearray, bytes, dict, list, etc.)
                if module == "builtins":
                    return super().find_class(module, name)
                if (module, name) in _PICKLE_ALLOWLIST:
                    return super().find_class(module, name)
                raise pickle.UnpicklingError(
                    f"Blocked unpickling of {module}.{name} — not in allowlist. "
                    "If this is a legitimate class, add it to _PICKLE_ALLOWLIST."
                )

        try:
            with open(path, "rb") as fh:
                self._detector = _DetectorUnpickler(fh).load()
            if not getattr(self._detector, "is_trained", False):
                logger.warning(
                    "SysmonBehaviorAgent: loaded detector reports is_trained=False. "
                    "Scores will be unreliable — retrain the model."
                )
            else:
                vocab_size = len(getattr(self._detector.vectorizer, "vocabulary_", {}))
                logger.info(
                    f"SysmonBehaviorAgent: detector loaded — "
                    f"vocab={vocab_size}, "
                    f"iso_threshold={getattr(self._detector, 'iso_threshold', 0.0):.4f}"
                )
            self._model_loaded = True
        except Exception as exc:
            logger.error(
                f"SysmonBehaviorAgent: failed to load model: {exc}", exc_info=True
            )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the Sysmon event collection loop in the background.

        Always reads from the Winlogbeat NDJSON file source.
        The use_win_event_log parameter is accepted for backwards compatibility
        but does nothing — win32evtlog has been abandoned.
        """
        if self._running:
            return
        if not self._model_loaded:
            logger.warning(
                "SysmonBehaviorAgent: starting without a model — "
                "all score() calls will return 0.0."
            )
        self._loop = asyncio.get_running_loop()  # captured before spawning thread
        self._running = True

        logger.info(
            f"SysmonBehaviorAgent: using Winlogbeat NDJSON file source "
            f"({self.sysmon_log_path})"
        )
        self._task = asyncio.create_task(self._tail_loop(), name="sysmon_behavior_agent")
        logger.info(
            f"SysmonBehaviorAgent started "
            f"(model_loaded={self._model_loaded}, source=file, "
            f"log={self.sysmon_log_path})"
        )

    async def stop(self) -> None:
        """Gracefully cancel the background task."""
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("SysmonBehaviorAgent stopped")

    def score(self) -> float:
        """
        Return the most recent normalised anomaly score in [0.0, 1.0].
        Returns 0.0 when no score has been produced yet or model is absent.
        """
        return self._last_score

    def status(self) -> dict:
        return {
            "running":       self._running,
            "model_loaded":  self._model_loaded,
            "log_path":      self.sysmon_log_path,
            "active_source": "file",
            "winevent_available": False,
            "last_score":    self._last_score,
            "total_events":  self._total_events,
            "total_alerts":  self._total_alerts,
        }

    # ------------------------------------------------------------------
    # Internal: Windows Event Log loop — DEPRECATED, stub only
    # ------------------------------------------------------------------

    async def _winevent_loop(self) -> None:
        """Deprecated — win32evtlog has been abandoned. Logs a warning and exits."""
        logger.warning(
            "SysmonBehaviorAgent: _winevent_loop is deprecated and does nothing. "
            "The agent now reads exclusively from the Winlogbeat NDJSON file."
        )

    def _winevent_read_sync(self) -> None:
        """Deprecated — win32evtlog has been abandoned. This method is a no-op."""
        logger.warning(
            "SysmonBehaviorAgent: _winevent_read_sync is deprecated and does nothing."
        )

    # ------------------------------------------------------------------
    # Internal: log tailer (fallback NDJSON file source)
    # ------------------------------------------------------------------

    def _resolve_log_path(self) -> Optional[Path]:
        """
        Return the log Path to tail.  Falls back to scanning the log directory
        for the most-recently-modified .json / .ndjson file if the configured
        path does not exist — handles Winlogbeat naming variants automatically.
        """
        primary = Path(self.sysmon_log_path)
        if primary.exists():
            return primary

        # Scan the parent directory for any JSON log file
        parent = primary.parent
        if parent.exists():
            candidates = sorted(
                [p for p in parent.iterdir() if p.suffix.lower() in (".json", ".ndjson") and p.is_file()],
                key=lambda p: p.stat().st_mtime,
                reverse=True,
            )
            if candidates:
                found = candidates[0]
                logger.info(
                    f"SysmonBehaviorAgent: configured log path not found; "
                    f"auto-selected {found} (most recently modified JSON in {parent})"
                )
                return found

        return None

    async def _tail_loop(self) -> None:
        """
        Open the Sysmon log file, seek to end, and tail new lines.
        Sleeps 0.05 s when no data is available (matching SysmonMonitor).
        If the log file does not exist at startup, waits 5 s and retries.
        """
        while self._running:
            log_path = self._resolve_log_path()
            if log_path is None:
                logger.warning(
                    f"SysmonBehaviorAgent: no JSON log files found in "
                    f"{Path(self.sysmon_log_path).parent}. Retrying in 5 s."
                )
                await asyncio.sleep(5.0)
                continue

            try:
                await asyncio.to_thread(self._tail_file, str(log_path))
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.error(
                    f"SysmonBehaviorAgent: tail loop error: {exc}", exc_info=True
                )
                await asyncio.sleep(5.0)

    def _tail_file(self, log_path_str: str) -> None:
        """
        Synchronous inner loop — runs in a thread via asyncio.to_thread.
        Opens the log file, seeks to EOF, and reads new lines until
        self._running is False.
        """
        with open(log_path_str, "r", encoding="utf-8", errors="ignore") as fh:
            fh.seek(0, 2)  # seek to end — tail mode only
            while self._running:
                line = fh.readline()
                if not line:
                    time.sleep(0.05)
                    continue
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                self._handle_event(event)

    # ------------------------------------------------------------------
    # Internal: event handling
    # ------------------------------------------------------------------

    def _handle_event(self, event: dict) -> None:
        """Parse one Sysmon event and update the per-PID window."""
        token, meta = _sysmon_event_to_token(event)
        if token is None:
            return

        self._total_events += 1
        pid   = meta["pid"]
        image = meta["image"]

        logger.debug(
            f"SysmonBehaviorAgent: processed event EventID={meta['event_id']} "
            f"token={token} pid={pid}"
        )

        # Emit raw telemetry for every parsed event — rate-limited to 1 per PID per 5s
        if self.on_telemetry is not None:
            now_t = time.time()
            if now_t - self._last_telemetry_time.get(pid, 0) >= 5.0:
                self._last_telemetry_time[pid] = now_t
                proc_name_raw = os.path.basename(image).lower() if image else "unknown.exe"
                raw_entry = {
                    "event_id":     meta["event_id"],
                    "event_name":   SYSMON_EVENTS.get(meta["event_id"], "Unknown"),
                    "process_name": proc_name_raw,
                    "pid":          pid,
                    "commandline":  meta.get("commandline", ""),
                    "high_risk":    meta.get("high_risk", False),
                    "is_anomaly":   False,
                    "ts":           datetime.now(timezone.utc).isoformat(),
                    "source":       "sysmon_raw",
                }
                loop = self._loop
                if loop and loop.is_running():
                    loop.call_soon_threadsafe(
                        lambda e=raw_entry: loop.create_task(self._fire_telemetry(e))
                    )

        # Ensure per-PID state exists
        if pid not in self._processes:
            self._processes[pid] = {
                "window":  deque(maxlen=_WINDOW_SIZE),
                "counter": 0,
                "image":   image,
            }
        ps = self._processes[pid]
        ps["window"].append(token)
        ps["counter"] += 1

        # Need at least MIN_FEAT_HITS tokens before scoring is meaningful
        if len(ps["window"]) < _MIN_FEAT_HITS:
            return

        # Score immediately on high-risk events, or every stride events
        if meta["high_risk"]:
            self._score_pid(ps, pid, high_risk=True)
        elif ps["counter"] % _STRIDE == 0:
            self._score_pid(ps, pid, high_risk=False)

    # ------------------------------------------------------------------
    # Internal: scoring
    # ------------------------------------------------------------------

    def _score_pid(self, ps: dict, pid: str, high_risk: bool) -> None:
        """Run the detector on the current window for one PID."""
        if not self._model_loaded or self._detector is None:
            return

        tokens_str  = " ".join(ps["window"])
        image       = ps["image"]
        proc_name   = os.path.basename(image).lower() if image else "unknown.exe"

        logger.debug(
            f"SysmonBehaviorAgent: scoring PID={pid} proc={proc_name} "
            f"window_len={len(ps['window'])} high_risk={high_risk}"
        )

        # Whitelist check — always bypass for high-risk EventIDs and known-bad procs
        is_whitelisted = proc_name in BENIGN_WHITELIST or proc_name in _EXTENDED_WHITELIST
        is_high_alert  = proc_name in HIGH_ALERT_PROCESSES
        in_cooldown    = self._in_cooldown(pid)

        # Suppress entirely for whitelisted procs unless this is a high-risk event
        # or the process is explicitly in HIGH_ALERT_PROCESSES
        if is_whitelisted and not high_risk and not is_high_alert:
            return

        try:
            results = self._detector.predict([tokens_str])
            r = results[0]
        except Exception as exc:
            logger.debug(f"SysmonBehaviorAgent: predict error for pid={pid}: {exc}")
            return

        raw_score   = float(r.get("anomaly_score", 0.0))
        label       = str(r.get("label", BENIGN_LABEL))
        confidence  = float(r.get("confidence", 0.0))
        nonzero     = int(r.get("nonzero_feats", 0))
        is_anomaly  = bool(r.get("is_anomaly", False))

        # Normalise raw score to [0, 1]
        norm_score = min(1.0, max(0.0, raw_score / _RAW_SCORE_CEILING))
        self._last_score = norm_score

        logger.debug(
            f"SysmonBehaviorAgent: scoring PID={pid} score={norm_score:.4f} "
            f"label={label} confidence={confidence:.3f} "
            f"nonzero_feats={nonzero} is_anomaly={is_anomaly}"
        )

        low_feats = nonzero < _MIN_FEAT_HITS

        # Decide whether to fire an alert.
        # High-risk EventIDs (CreateRemoteThread, ProcessTampering) always alert —
        # even whitelisted process names can be spoofed (process masquerading).
        should_alert = (
            is_high_alert
            or high_risk
            or (is_anomaly and not is_whitelisted and not in_cooldown
                and not low_feats and norm_score >= _MIN_ALERT_SCORE)
        )

        if not should_alert:
            return

        # Update cooldown
        self._last_alert_time[pid] = time.time()
        self._total_alerts += 1

        severity = _score_to_severity(norm_score)

        result = {
            "anomaly_score": round(norm_score, 4),
            "severity":      severity,
            "label":         label,
            "process_name":  proc_name,
            "pid":           pid,
            "confidence":    round(confidence, 4),
            "high_risk":     high_risk,
            "ts":            datetime.now(timezone.utc).isoformat(),
            "source":        "sysmon_behavior",
        }

        logger.info(
            f"SysmonBehaviorAgent: {severity} alert — "
            f"proc={proc_name} pid={pid} score={norm_score:.3f} "
            f"label={label} high_risk={high_risk}"
        )
        logger.debug(
            f"SysmonBehaviorAgent: alert fired score={norm_score:.4f} "
            f"severity={severity} process={proc_name}"
        )

        # Schedule the async callback from the sync thread using the captured loop.
        # asyncio.get_event_loop() fails in Python 3.10+ worker threads, so we use
        # self._loop which was captured in start() on the main event loop thread.
        if self.on_result is not None:
            try:
                loop = self._loop
                if loop and loop.is_running():
                    loop.call_soon_threadsafe(
                        lambda r=result: loop.create_task(self._fire(r))
                    )
            except Exception as exc:
                logger.error(
                    f"SysmonBehaviorAgent: failed to schedule callback: {exc}"
                )

    async def _fire(self, result: dict) -> None:
        """Invoke the on_result callback safely."""
        try:
            await self.on_result(result)
        except Exception as exc:
            logger.error(
                f"SysmonBehaviorAgent: on_result callback error: {exc}", exc_info=True
            )

    async def _fire_telemetry(self, entry: dict) -> None:
        """Invoke the on_telemetry callback safely."""
        if self.on_telemetry is not None:
            try:
                await self.on_telemetry(entry)
            except Exception as exc:
                logger.debug(
                    f"SysmonBehaviorAgent: on_telemetry callback error: {exc}"
                )

    # ------------------------------------------------------------------
    # Internal: cooldown helper
    # ------------------------------------------------------------------

    def _in_cooldown(self, pid: str) -> bool:
        last = self._last_alert_time.get(pid)
        return last is not None and (time.time() - last) < _ALERT_COOLDOWN_S
