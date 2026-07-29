"""
Event-Driven Correlation and Fusion Engine — Cyber Sentinel XDR
===============================================================
This module is an *additional* layer on top of the existing weighted-linear
FusionEngineAgent (agents/fusion_engine_agent.py).  It does NOT replace that
agent; backend.py continues to use the agent for per-event numeric scoring.

Architecture
------------
EventBuffer     — Thread-safe sliding time-window ring of raw detection events
CorrelationEngine — Stateless rule set: detects multi-domain attack chains
FusionDecisionEngine — Orchestrates buffer + correlation → final decision dict

Module-level singletons (ingest_event / fuse) are the expected call-sites.

Data contract — every event dict must carry:
    {
        "source":     "network | user | system | malware",
        "timestamp":  "<ISO-8601 string>",
        "host":       "<hostname>",
        "severity":   "LOW | MEDIUM | HIGH | CRITICAL",
        "confidence": <float 0.0-1.0>,
        "prediction": "<attack label>",          # optional but recommended
        "features":   {<feature dict>},          # optional — passed to SHAP
    }

All public methods are thread-safe.  The module-level functions are the
intended integration points for backend.py coroutines.
"""

from __future__ import annotations

import logging
import threading
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# How long events live in the buffer (seconds)
_BUFFER_WINDOW_SECONDS: int = 300

# Default correlation look-behind window (seconds)
_CORRELATION_WINDOW_SECONDS: int = 120

# Severity string → numeric weight mapping
_SEVERITY_WEIGHTS: dict[str, float] = {
    "LOW":      0.25,
    "MEDIUM":   0.50,
    "HIGH":     0.75,
    "CRITICAL": 1.00,
}

# Ordered severity levels for comparison
_SEVERITY_ORDER: list[str] = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Minimum response threshold (HIGH or CRITICAL)
_RESPOND_SEVERITIES: frozenset[str] = frozenset({"HIGH", "CRITICAL"})

# Required fields that every ingested event must carry
_REQUIRED_FIELDS: tuple[str, ...] = ("source", "timestamp", "host", "severity", "confidence")

# Valid source labels
_VALID_SOURCES: frozenset[str] = frozenset({"network", "user", "system", "malware"})

# Mapping from raw SystemMonitorAgent behavioral_attack_type values to
# human-readable attack labels used in correlated-attack output.
_BEHAVIORAL_ATTACK_TYPE_MAP: dict[str, str] = {
    "Backdoored-Executable": "Backdoor Execution",
    "CesarFTP":              "FTP Exploit",
    "OS-SMB":                "SMB Exploit",
    "OS-Print-Spool":        "Print Spooler Exploit",
    "Browser-Attack":        "Browser Exploit",
    "PDF":                   "PDF Exploit",
    "Infectious-Media":      "Removable Media Attack",
    "Tomcat":                "Web Server Exploit",
    "WebDAV":                "WebDAV Exploit",
    "PMWiki":                "Wiki CMS Exploit",
    "Icecast":               "Media Server Exploit",
    "Wireless-Karma":        "Rogue AP Attack",
}

# ---------------------------------------------------------------------------
# Helper utilities
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _clamp(value: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(value)))


def _severity_gte(a: str, b: str) -> bool:
    """Return True when severity *a* is greater-than-or-equal-to severity *b*."""
    return _SEVERITY_ORDER.index(a) >= _SEVERITY_ORDER.index(b)


def _max_severity(severities: list[str]) -> str:
    """Return the highest severity string from a list."""
    if not severities:
        return "LOW"
    return max(severities, key=lambda s: _SEVERITY_ORDER.index(s))


def _parse_timestamp(ts_str: str) -> Optional[datetime]:
    """
    Parse an ISO-8601 timestamp string into an aware datetime.
    Returns None on failure so callers can degrade gracefully.
    """
    if not ts_str:
        return None
    try:
        # Python 3.11+ fromisoformat handles 'Z' suffix; handle older runtimes too
        ts_str = ts_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# EventBuffer
# ---------------------------------------------------------------------------

class EventBuffer:
    """
    Thread-safe sliding time-window buffer of detection events.

    Events older than *window_seconds* are purged automatically on every
    call to add_event().  This keeps memory bounded even under sustained
    high event rates.

    Parameters
    ----------
    window_seconds : int
        Maximum age of events retained in the buffer (default: 300 s / 5 min).
    """

    def __init__(self, window_seconds: int = _BUFFER_WINDOW_SECONDS) -> None:
        self._window_seconds = window_seconds
        self._events: list[dict] = []
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_event(self, event: dict) -> None:
        """
        Append *event* to the buffer and expire any events older than the
        configured window.  The event must already be validated and
        normalised before being passed here.
        """
        with self._lock:
            self._events.append(event)
            self._expire()

    def get_recent(self, seconds: int = 120) -> list[dict]:
        """
        Return a snapshot of events received within the last *seconds* seconds.
        The list is a copy — callers may safely iterate or mutate it.
        """
        cutoff = datetime.now(timezone.utc).timestamp() - seconds
        with self._lock:
            return [
                e for e in self._events
                if self._event_ts_epoch(e) >= cutoff
            ]

    def clear(self) -> None:
        """Remove all events (useful for testing)."""
        with self._lock:
            self._events.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._events)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _expire(self) -> None:
        """Remove events older than _window_seconds.  Must be called under lock."""
        cutoff = datetime.now(timezone.utc).timestamp() - self._window_seconds
        self._events = [e for e in self._events if self._event_ts_epoch(e) >= cutoff]

    @staticmethod
    def _event_ts_epoch(event: dict) -> float:
        """
        Extract the epoch timestamp from an event dict.
        Falls back to 0.0 (always expired) if the timestamp cannot be parsed,
        ensuring malformed events never accumulate indefinitely.
        """
        dt = _parse_timestamp(event.get("timestamp", ""))
        if dt is None:
            return 0.0
        return dt.timestamp()


# ---------------------------------------------------------------------------
# CorrelationEngine
# ---------------------------------------------------------------------------

class CorrelationEngine:
    """
    Stateless rule engine that analyses a list of recent events and produces
    a correlation result dict describing any detected attack chains.

    Rules implemented
    -----------------
    1. Pairwise domain correlation (within a 120-second window):
       - network + system  → Lateral Movement           T1021
       - user   + malware  → Insider Threat w/ Malicious Execution  T1204
       - network + malware → Drive-by Compromise / C2 Beaconing  T1189/T1071
       - user   + network  → Credential Abuse / Exfiltration  T1078/T1041
       - system + malware  → Ransomware Activity T1486 (requires confirmed malicious label + HIGH/CRITICAL system anomaly)

    2. 3+ distinct sources → Advanced Persistent Threat  TA0001

    3. Host-level corroboration escalates severity.

    4. Confidence is a weighted average of individual confidences, boosted
       by the corroboration count.

    5. Final severity escalation:
       - 1 source HIGH                → keep HIGH
       - 2+ sources any HIGH          → escalate to CRITICAL
       - attack_chain detected        → escalate to at least HIGH
    """

    # (source_a, source_b) → (attack_type, mitre_id, mitre_tactic)
    _CHAIN_RULES: dict[frozenset, tuple[str, str, str]] = {
        frozenset({"network", "system"}):  (
            "Lateral Movement",
            "T1021",
            "Lateral Movement",
        ),
        frozenset({"user", "malware"}): (
            "Insider Threat with Malicious Execution",
            "T1204",
            "Execution",
        ),
        frozenset({"network", "malware"}): (
            "Drive-by Compromise / C2 Beaconing",
            "T1189/T1071",
            "Initial Access / Command and Control",
        ),
        frozenset({"user", "network"}): (
            "Credential Abuse / Exfiltration",
            "T1078/T1041",
            "Defense Evasion / Exfiltration",
        ),
        frozenset({"system", "user"}): (
            "Suspicious System Activity with User Anomaly",
            "T1078",
            "Defense Evasion",
        ),
    }

    _APT_ATTACK_TYPE = "Advanced Persistent Threat"
    _APT_MITRE_ID    = "TA0001"
    _APT_TACTIC      = "Initial Access (APT Campaign)"

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def correlate(self, events: list[dict]) -> dict:
        """
        Analyse *events* and return a correlation result dict.

        Parameters
        ----------
        events : list[dict]
            Recent events from EventBuffer.get_recent().  May be empty.

        Returns
        -------
        dict
            Correlation result with all keys specified in the module docstring.
        """
        empty_result = self._empty_result()

        if not events:
            return empty_result

        try:
            return self._run_correlation(events)
        except Exception as exc:
            logger.error(f"CorrelationEngine.correlate() raised unexpectedly: {exc}", exc_info=True)
            return empty_result

    # ------------------------------------------------------------------
    # Internal implementation
    # ------------------------------------------------------------------

    def _run_correlation(self, events: list[dict]) -> dict:
        # Collect metadata
        sources_present: set[str] = set()
        hosts_present: set[str] = set()
        confidences: list[float] = []
        severity_weights: list[float] = []
        severities_seen: list[str] = []
        timestamps: list[float] = []

        for evt in events:
            src = evt.get("source", "")
            if src in _VALID_SOURCES:
                sources_present.add(src)
            host = evt.get("host", "")
            if host:
                hosts_present.add(host)
            conf = _clamp(float(evt.get("confidence", 0.0)))
            confidences.append(conf)
            sev = evt.get("severity", "LOW").upper()
            if sev not in _SEVERITY_WEIGHTS:
                sev = "LOW"
            severity_weights.append(_SEVERITY_WEIGHTS[sev])
            severities_seen.append(sev)
            ts_epoch = EventBuffer._event_ts_epoch(evt)
            if ts_epoch > 0:
                timestamps.append(ts_epoch)

        # Time span
        if len(timestamps) >= 2:
            time_span = max(timestamps) - min(timestamps)
        else:
            time_span = 0.0

        # -----------------------------------------------------------------
        # Rule 1: Detect pairwise attack chains
        # -----------------------------------------------------------------
        attack_chain = False
        attack_type  = ""
        mitre_id     = ""
        mitre_tactic = ""

        for pair, (chain_name, mid, tactic) in self._CHAIN_RULES.items():
            if pair.issubset(sources_present):
                attack_chain = True
                attack_type  = chain_name
                mitre_id     = mid
                mitre_tactic = tactic
                logger.info(
                    f"CorrelationEngine: attack chain detected — "
                    f"{chain_name} [{mid}] (sources={sources_present})"
                )
                break  # First matching rule wins; APT check may override below

        # -----------------------------------------------------------------
        # Ransomware: only when confirmed malicious file + behavioral system signal
        # -----------------------------------------------------------------
        if not attack_chain:
            is_ransomware, rw_confidence = self._detect_ransomware(events)
            if is_ransomware:
                attack_chain = True
                attack_type  = "Ransomware Activity"
                mitre_id     = "T1486"
                mitre_tactic = "Impact"
                confidences.append(rw_confidence)
                logger.info(
                    "CorrelationEngine: Ransomware Activity detected "
                    f"[T1486] (confidence={rw_confidence:.4f})"
                )

        # -----------------------------------------------------------------
        # Rule 2: APT — 3 or more distinct sources
        # -----------------------------------------------------------------
        if len(sources_present) >= 3:
            attack_chain = True
            attack_type  = self._APT_ATTACK_TYPE
            mitre_id     = self._APT_MITRE_ID
            mitre_tactic = self._APT_TACTIC
            logger.info(
                f"CorrelationEngine: APT detected — {len(sources_present)} "
                f"active sources: {sources_present}"
            )

        # Require ≥2 sources OR an explicit chain rule for attack_detected
        # A single source HIGH/CRITICAL event is an alert but not a "detected attack chain"
        multi_source_high = (
            len(sources_present) >= 2
            and any(_severity_gte(s, "HIGH") for s in severities_seen)
        )
        attack_detected = attack_chain or multi_source_high

        # When multi-source high fired but no chain rule matched, fill in a meaningful
        # fallback so the Correlated Attacks table never shows blank MITRE/type columns.
        if attack_detected and not attack_type:
            attack_type  = "Multi-Domain Threat"
            mitre_id     = "T1059"
            mitre_tactic = "Execution"

        # -----------------------------------------------------------------
        # Rule 4: Confidence — weighted average, boosted by corroboration
        # -----------------------------------------------------------------
        if not confidences:
            base_confidence = 0.0
        else:
            # Weight each confidence by the severity of that event
            weighted_sum = sum(c * w for c, w in zip(confidences, severity_weights))
            weight_total = sum(severity_weights) or 1.0
            base_confidence = weighted_sum / weight_total

        corroboration_count = len(sources_present)
        if corroboration_count >= 3:
            boosted_confidence = _clamp(base_confidence * 1.20)
        elif corroboration_count >= 2:
            boosted_confidence = _clamp(base_confidence * 1.10)
        else:
            boosted_confidence = base_confidence

        # -----------------------------------------------------------------
        # Rule 5: Final severity escalation
        # -----------------------------------------------------------------
        base_severity = _max_severity(severities_seen) if severities_seen else "LOW"

        high_count = sum(1 for s in severities_seen if _severity_gte(s, "HIGH"))

        # Only auto-escalate to CRITICAL when malware is absent from the sources,
        # OR when at least one malware event in the window is confirmed malicious.
        malware_is_confirmed = (
            "malware" not in sources_present
            or any(
                evt.get("source") == "malware"
                and str(evt.get("label", "")).lower() == "malicious"
                and not evt.get("trusted", True)
                for evt in events
            )
        )

        if len(sources_present) >= 2 and high_count >= 1 and malware_is_confirmed:
            final_severity = "CRITICAL"
        elif attack_chain:
            final_severity = _max_severity([base_severity, "HIGH"])
        elif high_count == 1 and len(sources_present) == 1:
            final_severity = "HIGH"
        else:
            final_severity = base_severity

        # -----------------------------------------------------------------
        # Rule 3: Host-level corroboration — single host with multi-source
        # escalation has already been factored into source_count above.
        # If all events come from ONE host with ≥2 sources, bump one level.
        # -----------------------------------------------------------------
        if len(hosts_present) == 1 and len(sources_present) >= 2:
            idx = _SEVERITY_ORDER.index(final_severity)
            if idx < len(_SEVERITY_ORDER) - 1:
                final_severity = _SEVERITY_ORDER[idx + 1]
                logger.debug(
                    f"CorrelationEngine: single-host multi-source escalation → {final_severity}"
                )

        # -----------------------------------------------------------------
        # Response suggestions
        # -----------------------------------------------------------------
        response_suggestions = self._build_response_suggestions(
            sources_present, severities_seen, attack_type, events
        )

        return {
            "attack_detected":    attack_detected,
            "attack_chain":       attack_chain,
            "attack_type":        attack_type,
            "mitre_id":           mitre_id,
            "mitre_tactic":       mitre_tactic,
            "involved_sources":   sorted(sources_present),
            "involved_hosts":     sorted(hosts_present),
            "confidence":         round(boosted_confidence, 4),
            "final_severity":     final_severity,
            "event_count":        len(events),
            "time_span_seconds":  round(time_span, 2),
            "response_suggestions": response_suggestions,
        }

    def _detect_ransomware(self, events: list[dict]) -> tuple[bool, float]:
        """
        Determine whether the current event window constitutes Ransomware Activity.

        Both of the following conditions must be satisfied:

        1. At least one malware event where:
           - ``event.get("label") == "malicious"`` OR
             ``event.get("prediction") == "MALICIOUS"``
           - AND ``event.get("trusted", True)`` is ``False``
             (trusted/signed files cannot trigger this rule)

        2. At least one system event where:
           - ``event.get("source") == "system"``
           - AND ``event.get("severity")`` is ``"HIGH"`` or ``"CRITICAL"``

        Returns
        -------
        tuple[bool, float]
            ``(True, avg_confidence)`` when both conditions are met, where
            ``avg_confidence`` is the mean of the malware score(s) and system
            confidence(s) from the matching events.
            ``(False, 0.0)`` otherwise.
        """
        malware_confidences: list[float] = []
        system_confidences:  list[float] = []

        for evt in events:
            source = evt.get("source", "")

            if source == "malware":
                label      = str(evt.get("label", "")).lower()
                prediction = str(evt.get("prediction", "")).upper()
                is_malicious = (label == "malicious" or prediction == "MALICIOUS")
                is_trusted   = bool(evt.get("trusted", True))
                if is_malicious and not is_trusted:
                    malware_confidences.append(_clamp(float(evt.get("confidence", 0.0))))

            elif source == "system":
                sev = str(evt.get("severity", "LOW")).upper()
                if sev in {"HIGH", "CRITICAL"}:
                    system_confidences.append(_clamp(float(evt.get("confidence", 0.0))))

        if malware_confidences and system_confidences:
            all_scores = malware_confidences + system_confidences
            avg_confidence = sum(all_scores) / len(all_scores)
            return True, _clamp(avg_confidence)

        return False, 0.0

    def _build_response_suggestions(
        self,
        sources: set[str],
        severities: list[str],
        attack_type: str,
        events: list[dict],
    ) -> list[str]:
        """
        Map detected sources + attack context to SOAR response actions.

        Mapping:
          malware present              → quarantine_file
          network HIGH or CRITICAL     → block_ip
          lateral movement or system   → isolate_host
          malware + process indicator  → kill_process
        """
        suggestions: list[str] = []

        has_malware = "malware" in sources
        has_network = "network" in sources
        has_system  = "system"  in sources

        # Only trigger SOAR quarantine/kill actions for files confirmed malicious,
        # not merely "suspicious" malware events.
        has_confirmed_malware = any(
            evt.get("source") == "malware"
            and str(evt.get("label", "")).lower() == "malicious"
            and not evt.get("trusted", True)
            for evt in events
        )

        # High/critical network events
        network_high = any(
            evt.get("source") == "network" and _severity_gte(
                evt.get("severity", "LOW").upper(), "HIGH"
            )
            for evt in events
        )

        if has_confirmed_malware:
            suggestions.append("quarantine_file")

        if has_network and network_high:
            suggestions.append("block_ip")

        # isolate_host only for confirmed HIGH/CRITICAL system activity or specific attack types
        system_high = any(
            evt.get("source") == "system"
            and evt.get("severity", "LOW").upper() in {"HIGH", "CRITICAL"}
            and evt.get("is_genuinely_anomalous", False)
            for evt in events
        )
        if system_high or "Lateral Movement" in attack_type or "Ransomware Activity" in attack_type:
            suggestions.append("isolate_host")

        # Kill process when confirmed malware is associated with a running process
        if has_confirmed_malware:
            process_indicators = any(
                bool(evt.get("process") or evt.get("pid"))
                for evt in events
                if evt.get("source") == "malware"
            )
            if process_indicators:
                suggestions.append("kill_process")

        # De-duplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for s in suggestions:
            if s not in seen:
                seen.add(s)
                unique.append(s)
        return unique

    @staticmethod
    def _empty_result() -> dict:
        return {
            "attack_detected":    False,
            "attack_chain":       False,
            "attack_type":        "",
            "mitre_id":           "",
            "mitre_tactic":       "",
            "involved_sources":   [],
            "involved_hosts":     [],
            "confidence":         0.0,
            "final_severity":     "LOW",
            "event_count":        0,
            "time_span_seconds":  0.0,
            "response_suggestions": [],
        }


# ---------------------------------------------------------------------------
# FusionDecisionEngine
# ---------------------------------------------------------------------------

class FusionDecisionEngine:
    """
    Orchestrates EventBuffer + CorrelationEngine into a single fuse() call.

    Parameters
    ----------
    buffer : EventBuffer
        The shared sliding-window event store.
    correlator : CorrelationEngine
        Stateless rule evaluator.
    high_threshold : float
        Confidence threshold above which should_respond is True (default 0.80).
    """

    def __init__(
        self,
        buffer: EventBuffer,
        correlator: CorrelationEngine,
        high_threshold: float = 0.80,
    ) -> None:
        self._buffer      = buffer
        self._correlator  = correlator
        self._high_threshold = high_threshold
        self._lock        = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def ingest_event(self, event: dict) -> dict:
        """
        Validate, normalise, buffer, and immediately run correlation.

        Parameters
        ----------
        event : dict
            Raw event dict from any detection module.

        Returns
        -------
        dict
            Full fusion output (same schema as fuse()).
        """
        try:
            validated = self._validate_and_normalise(event)
        except ValueError as exc:
            logger.warning(f"FusionDecisionEngine.ingest_event(): invalid event — {exc}: {event}")
            return self._zero_output()

        self._buffer.add_event(validated)
        recent = self._buffer.get_recent(seconds=_CORRELATION_WINDOW_SECONDS)
        correlation = self._correlator.correlate(recent)
        return self._build_output(recent, correlation)

    def fuse(self, recent_events: Optional[list[dict]] = None) -> dict:
        """
        Produce a fusion decision from *recent_events* (or the buffer's last
        120 seconds if None).

        Parameters
        ----------
        recent_events : list[dict] or None
            If provided, correlation is run on this list instead of the buffer.

        Returns
        -------
        dict
            Full fusion output.
        """
        try:
            if recent_events is None:
                events = self._buffer.get_recent(seconds=_CORRELATION_WINDOW_SECONDS)
            else:
                events = list(recent_events)

            if not events:
                return self._zero_output()

            correlation = self._correlator.correlate(events)
            return self._build_output(events, correlation)

        except Exception as exc:
            logger.error(f"FusionDecisionEngine.fuse() raised unexpectedly: {exc}", exc_info=True)
            return self._zero_output()

    # ------------------------------------------------------------------
    # Event validation and normalisation
    # ------------------------------------------------------------------

    def _validate_and_normalise(self, event: dict) -> dict:
        """
        Validate required fields and normalise confidence to [0.0, 1.0].

        Raises ValueError when a required field is missing or unparseable.
        """
        for field in _REQUIRED_FIELDS:
            if field not in event:
                raise ValueError(f"Missing required field '{field}'")

        source = str(event["source"]).lower()
        if source not in _VALID_SOURCES:
            raise ValueError(
                f"Unknown source '{source}'. "
                f"Expected one of: {sorted(_VALID_SOURCES)}"
            )

        # Validate timestamp is parseable (do not reject — use now() as fallback)
        ts_str = event.get("timestamp", "")
        if not _parse_timestamp(ts_str):
            logger.warning(
                f"FusionDecisionEngine: unparseable timestamp '{ts_str}' "
                f"— substituting UTC now"
            )
            ts_str = _now_iso()

        # Normalise confidence: values > 1.0 are treated as 0-100 scale
        raw_conf = float(event.get("confidence", 0.0))
        if raw_conf > 1.0:
            raw_conf = raw_conf / 100.0
        confidence = _clamp(raw_conf)

        severity = str(event.get("severity", "LOW")).upper()
        if severity not in _SEVERITY_WEIGHTS:
            logger.debug(
                f"FusionDecisionEngine: unknown severity '{severity}' → 'LOW'"
            )
            severity = "LOW"

        # For system events: if the behavioral detector fired with a specific
        # attack type, translate it to a human-readable label and use it as
        # the prediction so correlated-attack output shows a meaningful name.
        prediction = str(event.get("prediction", ""))
        if source == "system":
            raw_behavioral = str(event.get("behavioral_attack_type", "")).strip()
            if raw_behavioral and raw_behavioral != "Background":
                prediction = _BEHAVIORAL_ATTACK_TYPE_MAP.get(raw_behavioral, raw_behavioral)

        normalised: dict = {
            **event,
            "source":     source,
            "timestamp":  ts_str,
            "confidence": confidence,
            "severity":   severity,
            "host":       str(event.get("host", "unknown")),
            "prediction": prediction,
        }
        return normalised

    # ------------------------------------------------------------------
    # Output construction
    # ------------------------------------------------------------------

    def _build_output(self, events: list[dict], correlation: dict) -> dict:
        """
        Combine the per-event alert list with the correlation result to
        produce the full fusion output dict.
        """
        # Build alert list from events
        alerts = [self._event_to_alert(evt) for evt in events]

        # Final decision
        final_decision = self._compute_final_decision(events, correlation)

        return {
            "alerts":       alerts,
            "correlation":  correlation,
            "final_decision": final_decision,
        }

    def _event_to_alert(self, evt: dict) -> dict:
        """Project an internal event dict into the public alert schema."""
        return {
            "source":           evt.get("source", ""),
            "timestamp":        evt.get("timestamp", ""),
            "host":             evt.get("host", ""),
            "severity":         evt.get("severity", "LOW"),
            "confidence":       evt.get("confidence", 0.0),
            "prediction":       evt.get("prediction", ""),
            "shap_explanation": evt.get("features", None),
        }

    def _compute_final_decision(self, events: list[dict], correlation: dict) -> dict:
        """
        Derive threat_score, severity, should_respond, primary_threat, and
        sources_active from the event list and correlation result.

        Threat score computation
        ------------------------
        Base score = average of (confidence × severity_weight) for each event.
        Corroboration multiplier applied when ≥2 sources are active:
          2 sources → ×1.10
          3+ sources → ×1.20
        Result clamped to [0.0, 1.0].
        """
        if not events:
            return {
                "threat_score":  0.0,
                "severity":      "LOW",
                "should_respond": False,
                "primary_threat": "",
                "mitre_id":      "",
                "timestamp":     _now_iso(),
                "sources_active": [],
            }

        # Weighted component scores per event
        components: list[float] = []
        for evt in events:
            conf = _clamp(float(evt.get("confidence", 0.0)))
            sev  = evt.get("severity", "LOW").upper()
            sev_weight = _SEVERITY_WEIGHTS.get(sev, 0.25)
            components.append(conf * sev_weight)

        base_score = sum(components) / len(components) if components else 0.0

        # Corroboration boost
        source_count = len(set(evt.get("source", "") for evt in events))
        if source_count >= 3:
            base_score = _clamp(base_score * 1.20)
        elif source_count >= 2:
            base_score = _clamp(base_score * 1.10)

        threat_score = round(_clamp(base_score), 4)

        # Severity: take the higher of the correlated severity and our score-derived one
        corr_severity  = correlation.get("final_severity", "LOW")
        score_severity = self._score_to_severity(threat_score)
        final_severity = _max_severity([corr_severity, score_severity])

        # Cap severity so the label never exceeds what the numeric score justifies.
        # The CorrelationEngine can escalate based on source-pattern alone; this guard
        # ensures the displayed severity is always grounded in the actual score.
        if final_severity == "CRITICAL" and threat_score < 0.85:
            if threat_score >= 0.70:
                final_severity = "HIGH"   # score justifies HIGH but not CRITICAL
            elif threat_score >= 0.35:
                final_severity = "MEDIUM"
            else:
                final_severity = "LOW"
        elif final_severity == "HIGH" and threat_score < 0.70:
            final_severity = "MEDIUM" if threat_score >= 0.35 else "LOW"

        should_respond = final_severity in _RESPOND_SEVERITIES and threat_score >= self._high_threshold

        # Primary threat: attack_type from correlation, or highest-confidence prediction
        attack_type = correlation.get("attack_type", "")
        if attack_type:
            primary_threat = attack_type
        else:
            best_event = max(events, key=lambda e: float(e.get("confidence", 0.0)))
            primary_threat = best_event.get("prediction", "")

        mitre_id = correlation.get("mitre_id", "")
        sources_active = sorted(set(evt.get("source", "") for evt in events if evt.get("source")))

        return {
            "threat_score":   threat_score,
            "severity":       final_severity,
            "should_respond": should_respond,
            "primary_threat": primary_threat,
            "mitre_id":       mitre_id,
            "timestamp":      _now_iso(),
            "sources_active": sources_active,
        }

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_severity(score: float) -> str:
        """Map a numeric score to a severity label using standard XDR thresholds."""
        if score >= 0.85:
            return "CRITICAL"
        if score >= 0.65:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _zero_output() -> dict:
        """Return the canonical empty fusion output."""
        return {
            "alerts": [],
            "correlation": {
                "attack_detected":    False,
                "attack_chain":       False,
                "attack_type":        "",
                "mitre_id":           "",
                "mitre_tactic":       "",
                "involved_sources":   [],
                "involved_hosts":     [],
                "confidence":         0.0,
                "final_severity":     "LOW",
                "event_count":        0,
                "time_span_seconds":  0.0,
                "response_suggestions": [],
            },
            "final_decision": {
                "threat_score":   0.0,
                "severity":       "LOW",
                "should_respond": False,
                "primary_threat": "",
                "mitre_id":       "",
                "timestamp":      _now_iso(),
                "sources_active": [],
            },
        }


# ---------------------------------------------------------------------------
# Module-level singletons and convenience functions
# ---------------------------------------------------------------------------

_buffer:    EventBuffer          = EventBuffer(window_seconds=_BUFFER_WINDOW_SECONDS)
_correlator: CorrelationEngine   = CorrelationEngine()
_engine:    FusionDecisionEngine = FusionDecisionEngine(_buffer, _correlator)


def ingest_event(event: dict) -> dict:
    """
    Validate, buffer, and immediately correlate a single detection event.

    This is the primary integration point for backend.py coroutines.
    Call this once per detection event from any model (network, user,
    system, or malware) to get an up-to-date fusion decision.

    Parameters
    ----------
    event : dict
        Must carry: source, timestamp, host, severity, confidence.
        Optional: prediction, features.

    Returns
    -------
    dict
        Full fusion output — keys: alerts, correlation, final_decision.
    """
    return _engine.ingest_event(event)


def fuse(events: Optional[list[dict]] = None) -> dict:
    """
    Produce a fusion decision for *events* (or the last 120 s from the buffer).

    Use this when you want a point-in-time snapshot without adding new events,
    e.g. for periodic dashboard polling or SOAR trigger evaluation.

    Parameters
    ----------
    events : list[dict] or None
        If None, uses the module-level buffer's last 120-second window.

    Returns
    -------
    dict
        Full fusion output — keys: alerts, correlation, final_decision.
    """
    return _engine.fuse(events)
