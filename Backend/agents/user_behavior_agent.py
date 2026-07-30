"""
User Behavior Agent
Wraps xdr_runtime.run_inference() and runs it as a recurring async background task.
Emits results via an async callback so the backend can forward them to Socket.IO.
"""
import asyncio
import json
import logging
import math
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

import numpy as np

logger = logging.getLogger(__name__)

import os as _os

# Path to xdr_runtime.py and model artifacts relative to this file
_XDR_DIR = Path(__file__).parent.parent.parent / "User Behavior" / "final_model_backend_only"
sys.path.insert(0, str(_XDR_DIR))

# Absolute paths to model artifacts — used by score_session_telemetry()
_MODEL_PATH = _XDR_DIR / "user_model.pkl"
_SCALER_PATH = _XDR_DIR / "user_scaler.pkl"
_THRESHOLD_PATH = _XDR_DIR / "model_threshold.json"

# Ordered feature list that matches scaler.feature_names_in_ (19 dimensions).
# Hard-coded here so we never need to read feature_columns.json at score time
# on the fast 5-second telemetry path.
_SESSION_FEATURE_NAMES: List[str] = [
    "file_ops_count", "file_write_count", "file_read_count",
    "unique_files_accessed", "file_ops_rate",
    "logon_count", "logoff_count", "failed_logon_count",
    "after_hours_activity",
    "device_connects", "device_disconnects", "device_events",
    "emails_sent", "unique_recipients",
    "O", "C", "E", "A", "N",
]

# Default Winlogbeat NDJSON output directory (overrideable via USER_LOG_DIR env var,
# matching the same variable used by xdr_runtime.py).
_WINLOGBEAT_LOG_DIR = Path(_os.getenv("USER_LOG_DIR", r"C:\XDR_Logs"))

# Staleness threshold in seconds: if no Winlogbeat file has been modified within
# this window the agent falls back to PowerShell Get-WinEvent.
_WINLOGBEAT_STALE_SECONDS = 300

# ---------------------------------------------------------------------------
# Admin-configurable User Behavior ruleset.
# These defaults REPRODUCE the original hardcoded heuristic exactly, so shipping
# this feature changes nothing until an admin edits the rules from Settings.
# Persisted in MongoDB `settings` (key="user_behavior_rules") and pushed into the
# live agent via apply_rules() by backend.py. See POST /settings/user-rules.
#   business_hours_start/end : a logon at hour < start OR >= end counts as
#                              "after hours" (24-hour clock).
#   flag_weekends            : also treat Sat/Sun logons as after-hours.
#   after_hours_weight       : score added when ANY after-hours logon is seen
#                              (0.0 = original behavior: after-hours alone scores
#                              nothing and only matters combined with remote).
#   max_concurrent_sessions  : sessions strictly above this = "excess" (full
#                              weight); exactly this many = half weight.
#   max_remote_sessions      : remote sessions strictly above this (with no
#                              after-hours signal) = "excess remote".
#   watch_accounts           : extra usernames to treat like a system account.
# ---------------------------------------------------------------------------
_DEFAULT_RULES: Dict[str, Any] = {
    "enabled":                    True,   # False => ignore stored values, use these defaults
    "business_hours_start":       6,      # logon before 06:00 = after hours
    "business_hours_end":         23,     # logon at/after 23:00 = after hours
    "flag_weekends":              False,
    "after_hours_weight":         0.0,    # standalone after-hours score (0 = legacy)
    "max_concurrent_sessions":    3,      # >3 sessions = excess
    "excess_sessions_weight":     0.30,
    "max_remote_sessions":        2,      # >2 remote (no after-hours) = excess remote
    "remote_after_hours_weight":  0.50,
    "system_account_weight":      0.60,
    "rule_anomaly_threshold":     0.70,
    "watch_accounts":             [],     # additional usernames flagged like SYSTEM
}

try:
    from xdr_runtime import (
        run_inference as _run_inference,
        _build_ps_query as _xdr_build_ps_query,
        _normalize_powershell_item as _xdr_normalize_item,
    )
    _RUNTIME_AVAILABLE = True
except ImportError as e:
    logger.warning(f"xdr_runtime not importable: {e}. UserBehaviorAgent will return empty results.")
    _RUNTIME_AVAILABLE = False

    def _run_inference(**kwargs) -> dict:
        return {"threshold": 0.5, "lookback_minutes": 120, "events_count": 0,
                "log_files_count": 0, "summary": {"total_users": 0, "normal": 0, "anomaly": 0},
                "rows": [], "error": "xdr_runtime not available"}

    def _xdr_build_ps_query(lookback_minutes: int) -> str:  # type: ignore[misc]
        lookback_ms = lookback_minutes * 60 * 1000
        return (
            f"Get-WinEvent -LogName Security -MaxEvents 500 "
            f"-FilterXPath \"*[System[TimeCreated[timediff(@SystemTime) <= {lookback_ms}]]]\" "
            f"-ErrorAction SilentlyContinue "
            f"| Select-Object Id,TimeCreated,"
            f"@{{n='ProviderName';e={{$_.ProviderName}}}},"
            f"@{{n='Message';e={{$_.Message}}}},"
            f"@{{n='UserId';e={{if($_.UserId){{$_.UserId.Value}}else{{''}}}}}},"
            f"@{{n='ComputerName';e={{$_.MachineName}}}}"
            f"| ConvertTo-Json -Depth 2"
        )

    def _xdr_normalize_item(item: dict) -> Optional[dict]:  # type: ignore[misc]
        return item


AsyncCallback = Callable[[dict], Awaitable[None]]


class UserBehaviorAgent:
    """
    Periodically calls xdr_runtime.run_inference() in a thread (it does blocking I/O)
    and fires `on_result` with the structured output for each cycle.

    Usage:
        agent = UserBehaviorAgent(interval_seconds=300, on_result=my_async_handler)
        await agent.start()    # begins background loop
        ...
        await agent.stop()     # graceful shutdown
    """

    # Class-level model cache shared across all instances.
    # Populated on first call to _load_session_model(); None = not yet attempted.
    # False = load was attempted and failed (do not retry on every call).
    _model: Any = None        # IsolationForest (or False if unavailable)
    _scaler: Any = None       # StandardScaler (or False if unavailable)
    _model_threshold: float = 0.50  # default; overwritten from model_threshold.json

    def __init__(
        self,
        interval_seconds: int = 300,
        lookback_minutes: int = 120,
        usb_override_threshold: int = 10,
        on_result: Optional[AsyncCallback] = None,
    ):
        self.interval_seconds = interval_seconds
        self.lookback_minutes = lookback_minutes
        self.usb_override_threshold = usb_override_threshold
        self.on_result = on_result
        # Admin-configurable ruleset (see _DEFAULT_RULES). Overridden at runtime
        # via apply_rules() from backend.py POST /settings/user-rules.
        self._rules: Dict[str, Any] = dict(_DEFAULT_RULES)

    def apply_rules(self, rules: Optional[dict]) -> None:
        """Merge an admin-supplied ruleset over the defaults. Unknown keys are
        ignored; missing keys keep their default so partial updates are safe."""
        if not isinstance(rules, dict):
            return
        merged = dict(_DEFAULT_RULES)
        for k, v in rules.items():
            if k in _DEFAULT_RULES and v is not None:
                merged[k] = v
        self._rules = merged
        logger.info(
            "UserBehaviorAgent rules applied: enabled=%s hours=%s-%s weekends=%s "
            "max_sessions=%s max_remote=%s rule_threshold=%s watch=%d",
            merged["enabled"], merged["business_hours_start"], merged["business_hours_end"],
            merged["flag_weekends"], merged["max_concurrent_sessions"],
            merged["max_remote_sessions"], merged["rule_anomaly_threshold"],
            len(merged["watch_accounts"]),
        )

        self._task: Optional[asyncio.Task] = None
        self._running = False
        self.last_result: Optional[dict] = None
        self.runtime_available = _RUNTIME_AVAILABLE

    # ------------------------------------------------------------------
    # Audit policy setup
    # ------------------------------------------------------------------

    async def _enable_audit_policies(self) -> None:
        """Enable Windows audit subcategories for rich Security event collection.

        Requires the process to be running as Administrator.  If the auditpol
        command fails (e.g. insufficient privileges) a WARNING is logged and
        the agent continues — the user behavior pipeline degrades gracefully to
        whatever events are already audited.

        Audit subcategories enabled:
            Process Creation      — event 4688 (process launch visibility)
            Logon                 — events 4624, 4625 (interactive/network auth)
            Logoff                — event 4634, 4647 (session end)
            Account Logon         — events 4648, 4776 (credential use)
            File System           — event 4663 (object/file access; requires SACL)
            Registry              — event 4657 (registry key access; requires SACL)
            Sensitive Privilege Use — event 4672 (admin privilege assignment)
            User Account Management — events 4720, 4726, 4732 (account lifecycle)
        """
        # --- Admin-rights check -------------------------------------------
        # auditpol /set requires Administrator privileges.  When the backend is
        # started as a normal user (the typical dev scenario) every call would
        # fail and produce a noisy WARNING per subcategory.  Check once up-front
        # and skip the whole loop if we are not elevated.
        try:
            import ctypes
            _is_admin: bool = bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            # ctypes or windll unavailable (non-Windows CI, unit tests, etc.)
            _is_admin = False

        if not _is_admin:
            logger.info(
                "Audit policy configuration skipped — backend is not running as "
                "Administrator. Start the backend as Administrator for full Security "
                "event coverage (4624/4625/4663/4672/4688/…)."
            )
            return
        # ------------------------------------------------------------------

        _POLICIES: List[tuple] = [
            ("Process Creation",        True,  True),
            ("Logon",                   True,  True),
            ("Logoff",                  True,  False),
            ("Account Logon",           True,  True),
            ("File System",             True,  False),
            ("Registry",                True,  False),
            ("Sensitive Privilege Use", True,  True),
            ("User Account Management", True,  True),
        ]
        any_failed = False
        for subcategory, enable_success, enable_failure in _POLICIES:
            success_flag = "enable" if enable_success else "disable"
            failure_flag = "enable" if enable_failure else "disable"
            # auditpol parses its own command line; subcategory names with spaces
            # must be passed as a single /subcategory:<name> token.  Because we
            # use create_subprocess_exec (no shell), the OS hands the element as
            # one argv entry and auditpol receives the full name correctly.
            cmd = [
                "auditpol", "/set",
                f"/subcategory:{subcategory}",
                f"/success:{success_flag}",
                f"/failure:{failure_flag}",
            ]
            try:
                proc = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                _, stderr = await asyncio.wait_for(proc.communicate(), timeout=10.0)
                if proc.returncode != 0:
                    err_text = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
                    logger.warning(
                        "auditpol: failed to enable '%s' (rc=%d) — %s",
                        subcategory, proc.returncode, err_text or "no details",
                    )
                    any_failed = True
            except asyncio.TimeoutError:
                logger.warning("auditpol: timed out setting '%s'", subcategory)
                any_failed = True
            except FileNotFoundError:
                logger.warning(
                    "auditpol not found — Windows audit policies cannot be configured "
                    "automatically. Run the backend as Administrator on Windows."
                )
                return  # auditpol absent on this platform; stop trying
            except Exception as exc:
                logger.debug(
                    "auditpol: unexpected error for '%s' (%s): %s",
                    subcategory, type(exc).__name__, exc,
                )
                any_failed = True

        if not any_failed:
            logger.info(
                "Audit policies enabled — rich Security event collection active "
                "(4624/4625/4634/4647/4648/4663/4672/4688/4697/4698-4700/"
                "4719/4720/4726/4732/4776)"
            )
        else:
            logger.warning(
                "Some audit policies could not be enabled — run the backend as "
                "Administrator for full Security event coverage."
            )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self):
        if self._running:
            return
        self._running = True
        # Enable Windows audit policies in the background; do not block startup.
        asyncio.create_task(self._enable_audit_policies(), name="user_behavior_audit_policies")
        self._task = asyncio.create_task(self._loop(), name="user_behavior_agent")
        logger.info(f"UserBehaviorAgent started (interval={self.interval_seconds}s)")

    async def stop(self):
        self._running = False
        if self._task and not self._task.done():
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("UserBehaviorAgent stopped")

    # ------------------------------------------------------------------
    # Manual trigger (for /predict/user endpoint)
    # ------------------------------------------------------------------

    async def run_once(
        self,
        lookback_minutes: Optional[int] = None,
        threshold_override: Optional[float] = None,
        usb_override_threshold: Optional[int] = None,
    ) -> dict:
        """Run inference once and return results without firing the callback."""
        return await asyncio.to_thread(
            _run_inference,
            lookback_minutes=lookback_minutes or self.lookback_minutes,
            threshold_override=threshold_override,
            usb_override_threshold=usb_override_threshold or self.usb_override_threshold,
        )

    async def run_once_from_events(
        self,
        events: list,
        threshold_override: Optional[float] = None,
        usb_override_threshold: Optional[int] = None,
    ) -> dict:
        """Score a list of Winlogbeat events passed in-memory (no file read)."""
        if not _RUNTIME_AVAILABLE:
            return {
                "threshold": 0.5, "lookback_minutes": 0, "events_count": len(events),
                "log_files_count": 0, "rows": [],
                "summary": {"total_users": 0, "normal": 0, "anomaly": 0},
                "error": "xdr_runtime not available",
            }
        from xdr_runtime import run_inference_from_events as _run_from_events  # noqa: PLC0415
        return await asyncio.to_thread(
            _run_from_events,
            events=events,
            threshold_override=threshold_override,
            usb_override_threshold=usb_override_threshold or self.usb_override_threshold,
        )

    # ------------------------------------------------------------------
    # Session-model lazy loader
    # ------------------------------------------------------------------

    @classmethod
    def _load_session_model(cls) -> bool:
        """Load the IsolationForest model and scaler into class attributes.

        Returns True when both are ready to use, False otherwise.
        Uses a sentinel value of False (not None) to prevent repeated load
        attempts when the artifact files are absent.
        """
        if cls._model is False:  # previously attempted and failed
            return False
        if cls._model is not None:  # already loaded
            return True
        try:
            import joblib  # optional dep; already required by xdr_runtime
            m = joblib.load(_MODEL_PATH)
            s = joblib.load(_SCALER_PATH)
            # Read threshold from JSON; fall back to compiled default
            try:
                with _THRESHOLD_PATH.open("r", encoding="utf-8") as _f:
                    cls._model_threshold = float(json.load(_f).get("threshold", 0.50))
            except Exception:
                cls._model_threshold = 0.50
            cls._model = m
            cls._scaler = s
            logger.info(
                "UserBehaviorAgent: session model loaded "
                "(IsolationForest n_features=%d, threshold=%.2f)",
                getattr(m, "n_features_in_", -1),
                cls._model_threshold,
            )
            return True
        except Exception as exc:
            logger.warning(
                "UserBehaviorAgent: could not load session model — "
                "will use rule-based scoring only. Error: %s", exc
            )
            cls._model = False  # sentinel: do not retry
            cls._scaler = False
            return False

    # ------------------------------------------------------------------
    # Session-telemetry sigmoid (mirrors xdr_runtime._sigmoid_score)
    # ------------------------------------------------------------------

    @staticmethod
    def _sigmoid_score(raw: float) -> float:
        """Map IsolationForest decision_function output to [0,1] anomaly probability.

        IsolationForest decision_function returns negative values for anomalies
        and positive values for normal points.  Using a positive exponent negates
        raw so anomalies (negative raw) map toward 1.0:

            score = 1 / (1 + exp(raw * 5))

        With k=5:
          - raw = -0.30  (strong anomaly)  -> score ~0.82
          - raw =  0.00  (boundary)        -> score  0.50
          - raw = +0.20  (clear normal)    -> score ~0.27

        This matches the convention in xdr_runtime._sigmoid_score() exactly
        so both code paths (Winlogbeat 300s tick and endpoint 5s tick) are
        calibrated against the same threshold stored in model_threshold.json.
        """
        return float(1.0 / (1.0 + math.exp(raw * 5)))

    # ------------------------------------------------------------------
    # Session-telemetry feature builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_session_feature_vector(
        sessions: list,
        session_count: int,
        after_hours_count: int,
        remote_session_count: int,
    ) -> "np.ndarray":
        """Build the 19-dimensional feature vector from endpoint session telemetry.

        Feature mapping (19 dimensions, same order as scaler.feature_names_in_):

        Mapped from session data:
            logon_count           = session_count (each active session implies a logon)
            after_hours_activity  = count of sessions started before 06:00 or >= 23:00
            E (Extraversion)      = remote_session_count / max(1, session_count)
            N (Neuroticism)       = after_hours_count / max(1, session_count)
            A (Agreeableness)     = 1.0 (no failed-auth data from psutil; assume none)
            C (Conscientiousness) = login-time regularity via inverted std of session
                                    start hours; 0.5 (neutral) when fewer than 2 samples
            O (Openness)          = 0.0 (no event-source diversity available in snapshot)

        Zeroed (not available from endpoint session snapshot):
            file_ops_count, file_write_count, file_read_count, unique_files_accessed,
            file_ops_rate, logoff_count, failed_logon_count,
            device_connects, device_disconnects, device_events,
            emails_sent, unique_recipients
        """
        # --- Conscientiousness proxy: regularity of session start hours -----------
        start_hours: List[int] = []
        for sess in sessions:
            started = sess.get("started", "")
            if not started:
                continue
            try:
                dt = datetime.strptime(str(started), "%Y-%m-%d %H:%M:%S")
                start_hours.append(dt.hour)
            except (ValueError, TypeError):
                pass

        if len(start_hours) >= 2:
            std_h = float(np.std(start_hours))
            C_proxy = float(max(0.0, min(1.0, 1.0 - std_h / 12.0)))
        elif len(start_hours) == 1:
            C_proxy = 0.8  # single session => assume regular schedule
        else:
            C_proxy = 0.5  # no timestamp data => neutral

        # --- Extraversion proxy: proportion of remote (non-local) sessions --------
        E_proxy = float(remote_session_count) / max(1.0, float(session_count))
        E_proxy = min(1.0, E_proxy)

        # --- Neuroticism proxy: proportion of after-hours sessions ----------------
        N_proxy = float(after_hours_count) / max(1.0, float(session_count))
        N_proxy = min(1.0, N_proxy)

        # --- Agreeableness: 1.0 (no failed-auth signal available) ----------------
        A_proxy = 1.0

        # --- Openness: 0.0 (no event-source diversity available) -----------------
        O_proxy = 0.0

        # Assemble in _SESSION_FEATURE_NAMES order:
        # file_ops_count, file_write_count, file_read_count, unique_files_accessed,
        # file_ops_rate, logon_count, logoff_count, failed_logon_count,
        # after_hours_activity, device_connects, device_disconnects, device_events,
        # emails_sent, unique_recipients, O, C, E, A, N
        vec = np.array([
            0.0,             # file_ops_count
            0.0,             # file_write_count
            0.0,             # file_read_count
            0.0,             # unique_files_accessed
            0.0,             # file_ops_rate
            float(session_count),   # logon_count
            0.0,             # logoff_count
            0.0,             # failed_logon_count
            float(after_hours_count),  # after_hours_activity
            0.0,             # device_connects
            0.0,             # device_disconnects
            0.0,             # device_events
            0.0,             # emails_sent
            0.0,             # unique_recipients
            O_proxy,         # O
            C_proxy,         # C
            E_proxy,         # E
            A_proxy,         # A
            N_proxy,         # N
        ], dtype=np.float64)
        return vec

    # ------------------------------------------------------------------
    # Session-telemetry hybrid scorer
    # ------------------------------------------------------------------

    def score_session_telemetry(self, user_data: dict) -> dict:
        """Score a single user-session snapshot from the endpoint agent.

        Combines two complementary scoring paths:

        1. Rule-based heuristic (always runs, no dependencies):
           Evaluates system-account sessions, concurrent session count,
           after-hours start times (before 05:00 or >= 23:00), and remote IP
           sessions.  Anomaly threshold is 0.70.

        2. IsolationForest model (runs when model artifacts are available):
           Builds a 19-feature vector from session telemetry, scales it with
           the trained StandardScaler, and applies decision_function() +
           sigmoid(raw * 5) to produce a [0,1] anomaly probability.  The
           sigmoid convention matches xdr_runtime._sigmoid_score() exactly so
           the same model_threshold.json value applies to both the Winlogbeat
           300-second pipeline and this 5-second endpoint path.

           Feature mapping from session data:
             logon_count          = session_count
             after_hours_activity = sessions started before 06:00 or >= 23:00
             C (Conscientiousness)= 1 - (std(start_hours) / 12), clamped [0,1]
             E (Extraversion)     = remote_sessions / max(1, session_count)
             A (Agreeableness)    = 1.0 (no failed-auth available from psutil)
             N (Neuroticism)      = after_hours_count / max(1, session_count)
             O (Openness)         = 0.0 (no event-source diversity available)
             All file/device/email features = 0.0 (not present in snapshot)

        Final score = max(rule_score, model_score), so neither path can
        suppress the other.  When the model is unavailable, only the rule
        score is returned and ``model_used`` is False.

        Args:
            user_data: dict with keys ``current_user`` (str) and ``sessions``
                (list of dicts with keys ``name``, ``terminal``, ``host``,
                ``started``), matching the shape produced by the endpoint
                agent's ``user_collector.py``.

        Returns:
            A dict suitable for passing directly into the fusion pipeline as a
            user-layer risk signal.  Always includes ``model_used: bool``.
        """
        try:
            current_user: str = user_data.get("current_user", "")
            sessions: list = user_data.get("sessions", [])
            session_count: int = len(sessions)

            rule_score: float = 0.0
            flags: list = []
            unusual_hours_detected: bool = False
            remote_session_count: int = 0
            after_hours_count: int = 0

            # ------------------------------------------------------------------
            # Rule path
            # ------------------------------------------------------------------

            # Load the active ruleset. When custom rules are disabled we fall
            # back to the compiled defaults, exactly reproducing legacy behavior.
            r = self._rules if self._rules.get("enabled", True) else _DEFAULT_RULES
            bh_start   = int(r.get("business_hours_start", 6))
            bh_end     = int(r.get("business_hours_end", 23))
            flag_wknd  = bool(r.get("flag_weekends", False))
            ah_weight  = float(r.get("after_hours_weight", 0.0))
            max_sess   = int(r.get("max_concurrent_sessions", 3))
            excess_w   = float(r.get("excess_sessions_weight", 0.30))
            max_remote = int(r.get("max_remote_sessions", 2))
            remote_w   = float(r.get("remote_after_hours_weight", 0.50))
            sys_w      = float(r.get("system_account_weight", 0.60))
            watch      = {str(a).strip().lower() for a in r.get("watch_accounts", []) if str(a).strip()}

            def _is_after_hours(dt) -> bool:
                if flag_wknd and dt.weekday() >= 5:  # Sat=5, Sun=6
                    return True
                return dt.hour < bh_start or dt.hour >= bh_end

            # Factor 1 — system account (or admin watch-listed account) with an
            # interactive session. SYSTEM / LOCAL SERVICE etc. must not appear in
            # interactive psutil.users() output.
            _SYSTEM_ACCOUNTS = {
                "system",
                "nt authority\\system",
                "local service",
                "network service",
            }
            if current_user.strip().lower() in (_SYSTEM_ACCOUNTS | watch):
                rule_score += sys_w
                flags.append("system_account_session")

            # Factor 2 — excessive concurrent sessions (> max = full weight,
            # exactly max = half weight — a soft warning band).
            if session_count > max_sess:
                rule_score += excess_w
                flags.append("excess_sessions")
            elif session_count == max_sess:
                rule_score += excess_w / 2.0

            # Factor 3 — configurable after-hours window. A session counts as
            # after-hours activity if EITHER (a) the user logged in during the
            # after-hours window (a suspicious off-hours logon — e.g. 3 AM), OR
            # (b) the session is active *right now* and the current wall-clock
            # time is outside business hours (after-hours activity on a session
            # that may have started earlier). Both use the same configurable
            # window; (b) is what makes an ongoing session flag once the clock
            # passes the configured end hour.
            _now_local = datetime.now()
            now_after_hours = _is_after_hours(_now_local)
            for session in sessions:
                session_after_hours = now_after_hours
                started = session.get("started", "")
                if started:
                    try:
                        dt = datetime.strptime(str(started), "%Y-%m-%d %H:%M:%S")
                        if _is_after_hours(dt):
                            session_after_hours = True
                    except (ValueError, TypeError):
                        pass
                if session_after_hours:
                    unusual_hours_detected = True
                    after_hours_count += 1

            # Standalone after-hours contribution (0 by default; admins raise it
            # to make off-hours logons meaningful on their own).
            if after_hours_count > 0 and ah_weight > 0.0:
                rule_score += ah_weight
                flags.append("after_hours_logon")

            # Factor 4 — remote IP session counting
            # A single remote session during business hours contributes nothing.
            _LOCALHOST_NAMES = {"localhost", "127.0.0.1", "::1", ""}
            for session in sessions:
                host: str = session.get("host", "").strip()
                if not host or host.lower() in _LOCALHOST_NAMES:
                    continue
                # IP-like: contains at least one dot and is all digits/dots
                if "." in host and all(c.isdigit() or c == "." for c in host):
                    remote_session_count += 1

            # Factor 5 — compound: remote sessions + after-hours
            if remote_session_count >= 2 and unusual_hours_detected:
                rule_score += remote_w
                flags.append("multiple_remote_after_hours")
            elif remote_session_count >= 1 and unusual_hours_detected:
                rule_score += remote_w * 0.6
                flags.append("remote_after_hours")
            elif remote_session_count > max_remote and not unusual_hours_detected:
                rule_score += excess_w
                flags.append("excess_remote_sessions")
            # single remote session during business hours → zero contribution

            # Clamp rule score to [0.0, 1.0]
            rule_score = min(1.0, rule_score)

            # Design invariants (rule path):
            # - 1 remote session + business hours   → score=0.00 → NORMAL (RDP admin)
            # - 1 remote session + 1am              → score=0.30 → NORMAL (on-call, borderline)
            # - 2 remote sessions + 1am             → score=0.50 → NORMAL (borderline, needs more)
            # - SYSTEM account                      → score=0.60 → NORMAL (borderline; + any second factor → ANOMALY)
            # - SYSTEM account + remote at 1am      → score=0.90 → ANOMALY
            # - 3+ simultaneous remote (day)        → score=0.30 → NORMAL (not enough alone)
            # - 4+ sessions (any)                   → score=0.30 → NORMAL (needs a second factor)
            # Rule anomaly threshold: 0.70

            # ------------------------------------------------------------------
            # Model path (lazy-loaded, runs if artifacts are available)
            # ------------------------------------------------------------------
            model_score: float = 0.0
            model_used: bool = False

            if self._load_session_model():
                try:
                    feat_vec = self._build_session_feature_vector(
                        sessions=sessions,
                        session_count=session_count,
                        after_hours_count=after_hours_count,
                        remote_session_count=remote_session_count,
                    )
                    # Reshape to (1, 19) for scaler and model
                    X = feat_vec.reshape(1, -1)
                    X_scaled = self.__class__._scaler.transform(X)
                    raw = float(self.__class__._model.decision_function(X_scaled)[0])
                    model_score = self._sigmoid_score(raw)
                    model_used = True

                    if model_score >= self.__class__._model_threshold:
                        flags.append(
                            f"model_score={model_score:.3f}>={self.__class__._model_threshold:.2f}"
                        )

                    logger.debug(
                        "[endpoint_user] model path: raw=%.4f model_score=%.4f "
                        "threshold=%.2f",
                        raw, model_score, self.__class__._model_threshold,
                    )

                except Exception as model_exc:
                    # Model inference failure must never affect the rule-based result
                    logger.warning(
                        "score_session_telemetry: model inference failed, "
                        "falling back to rule score only. Error: %s", model_exc
                    )
                    model_score = 0.0
                    model_used = False

            # ------------------------------------------------------------------
            # Combine: take the higher of the two scores so neither suppresses
            # the other.  A session that looks normal to the rules but unusual
            # to the model (or vice-versa) will be caught.
            # ------------------------------------------------------------------
            final_score: float = max(rule_score, model_score)

            # Anomaly decision uses the model threshold when available; falls
            # back to the admin-configurable rule threshold (default 0.70).
            rule_thr = float(r.get("rule_anomaly_threshold", 0.70))
            if model_used:
                anomaly_threshold = max(self.__class__._model_threshold, rule_thr)
            else:
                anomaly_threshold = rule_thr
            anomaly: bool = final_score >= anomaly_threshold

            logger.debug(
                "[endpoint_user] user=%r sessions=%d remote=%d after_hours=%d "
                "rule=%.4f model=%.4f final=%.4f anomaly=%s flags=%s",
                current_user, session_count, remote_session_count, after_hours_count,
                rule_score, model_score, final_score, anomaly, flags,
            )

            return {
                "source": "user_session_hybrid",
                "user_score": round(final_score, 4),
                "rule_score": round(rule_score, 4),
                "model_score": round(model_score, 4),
                "model_used": model_used,
                "anomaly": anomaly,
                "session_count": session_count,
                "current_user": current_user,
                "unusual_hours_detected": unusual_hours_detected,
                "after_hours_count": after_hours_count,
                "remote_sessions": remote_session_count,
                "flags": flags,
            }

        except Exception as exc:
            logger.error(f"score_session_telemetry error: {exc}", exc_info=True)
            return {
                "source": "user_session_hybrid",
                "user_score": 0.0,
                "rule_score": 0.0,
                "model_score": 0.0,
                "model_used": False,
                "anomaly": False,
                "session_count": 0,
                "current_user": "",
                "unusual_hours_detected": False,
                "after_hours_count": 0,
                "remote_sessions": 0,
                "flags": [],
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Winlogbeat freshness + PowerShell fallback
    # ------------------------------------------------------------------

    @staticmethod
    def _winlogbeat_is_fresh(log_dir: Path, max_age_seconds: int = _WINLOGBEAT_STALE_SECONDS) -> bool:
        """Return True if at least one Winlogbeat NDJSON file exists and was
        modified within max_age_seconds.  Returns False when the directory is
        absent, empty, or all files are stale."""
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

    async def _collect_via_powershell(self, lookback_minutes: int = 120) -> list:
        """Read Windows Security events via PowerShell Get-WinEvent.

        This is the PRIMARY event source when Winlogbeat is not installed.
        Winlogbeat is an optional enhancement that provides richer field data.
        The returned list uses the same normalised dict shape as
        xdr_runtime.read_ndjson_logs() and can be passed directly to
        run_inference_from_events().

        Uses the shared _build_ps_query() and _normalize_powershell_item()
        helpers from xdr_runtime so both code paths stay in sync when the
        event ID list or field selections change.

        Collects event IDs: 4624, 4625, 4634, 4647, 4648, 4663, 4670, 4672,
        4688, 4697, 4698, 4699, 4700, 4719, 4720, 4726, 4732, 4776.
        """
        ps_script = _xdr_build_ps_query(lookback_minutes)
        cmd = ["powershell", "-NonInteractive", "-Command", ps_script]
        try:
            import subprocess as _sp
            _proc_result = await asyncio.wait_for(
                asyncio.to_thread(
                    _sp.run,
                    cmd,
                    capture_output=True,
                    timeout=28,
                ),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            logger.warning("PowerShell Get-WinEvent timed out after 30 s")
            return []
        except FileNotFoundError:
            logger.warning("PowerShell not found — cannot collect Windows Security events")
            return []
        except Exception as _exc:
            logger.debug("PowerShell subprocess error: %s", _exc)
            return []

        stdout = _proc_result.stdout
        if _proc_result.returncode != 0 or not stdout:
            return []

        try:
            raw = json.loads(stdout.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            logger.debug("PowerShell output JSON parse error: %s", exc)
            return []

        if isinstance(raw, dict):
            raw = [raw]

        events: list = []
        for item in raw:
            normalized = _xdr_normalize_item(item)
            if normalized is not None:
                events.append(normalized)

        return events

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _loop(self):
        while self._running:
            await self._tick()
            await asyncio.sleep(self.interval_seconds)

    async def _tick(self):
        try:
            log_dir = _WINLOGBEAT_LOG_DIR
            winlogbeat_fresh = self._winlogbeat_is_fresh(log_dir, max_age_seconds=_WINLOGBEAT_STALE_SECONDS)

            if winlogbeat_fresh:
                # Winlogbeat NDJSON is present and fresh — delegate entirely to
                # run_inference() which handles source selection internally and
                # will prefer Winlogbeat when its files are fresh.
                result = await asyncio.to_thread(
                    _run_inference,
                    lookback_minutes=self.lookback_minutes,
                    usb_override_threshold=self.usb_override_threshold,
                )
                events_count = result.get("events_count", 0)
                if events_count > 0:
                    result.setdefault("status", "winlogbeat")
                    logger.debug(
                        "User behavior: reading from Winlogbeat (%d events)", events_count
                    )
                else:
                    # Fresh file but no recent events in the lookback window —
                    # fall through to Get-WinEvent below.
                    winlogbeat_fresh = False

            if not winlogbeat_fresh:
                # Get-WinEvent is the PRIMARY source when Winlogbeat is absent,
                # stale, or returned no events.  This is the expected path on
                # any Windows machine without Winlogbeat configured.
                logger.debug(
                    "User behavior: reading from Get-WinEvent (Winlogbeat not configured)"
                )
                ps_events = await self._collect_via_powershell(lookback_minutes=self.lookback_minutes)
                if ps_events:
                    result = await self.run_once_from_events(
                        events=ps_events,
                        usb_override_threshold=self.usb_override_threshold,
                    )
                    result["status"] = "get_winevent"
                    result["reason"] = (
                        "Events collected via PowerShell Get-WinEvent "
                        "(Winlogbeat is an optional enhancement)"
                    )
                else:
                    # PowerShell returned no events — no admin rights, or the
                    # Security log is empty for the lookback window.
                    result = {
                        "threshold": 0.5,
                        "lookback_minutes": self.lookback_minutes,
                        "events_count": 0,
                        "log_files_count": 0,
                        "rows": [],
                        "summary": {"total_users": 0, "normal": 0, "anomaly": 0, "avg_score": 0.0},
                        "status": "no_events",
                        "reason": (
                            "PowerShell Get-WinEvent returned no Security events — "
                            "ensure the backend is running with sufficient privileges "
                            "or configure Winlogbeat as an optional data source."
                        ),
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                    logger.warning(
                        "UserBehaviorAgent: Get-WinEvent returned no events — "
                        "the backend may lack privileges to read the Security log. "
                        "Run as Administrator or configure Winlogbeat (START_WINLOGBEAT=true)."
                    )

            self.last_result = result
            logger.debug(
                f"UserBehaviorAgent: {result.get('summary', {}).get('total_users', 0)} users, "
                f"{result.get('summary', {}).get('anomaly', 0)} anomalies "
                f"[source={result.get('status', 'unknown')}]"
            )
            if self.on_result:
                await self.on_result(result)
        except asyncio.CancelledError:
            raise
        except Exception as e:
            logger.error(f"UserBehaviorAgent inference error: {e}", exc_info=True)

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        return {
            "running": self._running,
            "runtime_available": self.runtime_available,
            "interval_seconds": self.interval_seconds,
            "last_result_summary": self.last_result.get("summary") if self.last_result else None,
        }
