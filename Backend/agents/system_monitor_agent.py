"""
System Monitor Agent — Cyber Sentinel XDR
Collects live endpoint telemetry via psutil, maintains a 60-second rolling
window, and runs an LSTM Autoencoder to produce an anomaly score [0.0, 1.0].

Second detection path (BehavioralDetector):
    Loads detector.pkl (WindowsAnomalyDetector — TF-IDF + IsolationForest +
    RandomForest/XGBoost ensemble trained on GHC DLL-call-stack traces and
    Sysmon token sequences).  When Sysmon events are available the behavioral
    score is fused with the LSTM score by taking the maximum (worst-case).

Architecture:
    psutil (1 Hz) → deque(maxlen=60) → LSTMAutoencoder → reconstruction error
    → normalised score                                         ↘
                                                          max() → final_score
    Sysmon events → token sequence → detector.pkl → anomaly_score ↗

Dependencies (optional — graceful degradation if absent):
    pip install torch
    pip install joblib   (already in project venv)
    sklearn / numpy      (already in project venv)

Artifacts expected in model_dir:
    system_model.pt       — PyTorch state dict from train_system_model.py
    system_scaler.pkl     — joblib-dumped sklearn StandardScaler
    system_metadata.json  — {"n_features":20,"window_size":60,"anomaly_threshold":float,...}

Behavioral detector artifact (separate path):
    D:/Cyber Sentinal/System Behavior/System_Behavior_Model/DETECTOR1/saved_model_v3/detector.pkl
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Optional heavy imports — graceful fallback when PyTorch is absent
# ---------------------------------------------------------------------------
try:
    import torch
    import torch.nn as nn
    _TORCH_AVAILABLE = True
except ImportError:
    torch = None  # type: ignore[assignment]
    nn = None     # type: ignore[assignment]
    _TORCH_AVAILABLE = False
    logger.warning(
        "PyTorch not installed — SystemMonitorAgent will start but produce no scores. "
        "Install with: pip install torch"
    )

try:
    import psutil
    _PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None  # type: ignore[assignment]
    _PSUTIL_AVAILABLE = False
    logger.warning("psutil not installed — SystemMonitorAgent cannot collect telemetry.")

try:
    import joblib
    _JOBLIB_AVAILABLE = True
except ImportError:
    joblib = None  # type: ignore[assignment]
    _JOBLIB_AVAILABLE = False
    logger.warning("joblib not installed — SystemMonitorAgent cannot load scaler.")

try:
    import numpy as np
    _NUMPY_AVAILABLE = True
except ImportError:
    np = None  # type: ignore[assignment]
    _NUMPY_AVAILABLE = False

# ---------------------------------------------------------------------------
# Behavioral detector constants — mirrored from windows_detector_final.py
# so we never import from that file at runtime (it has its own argparse main
# which would collide if imported as a module in some Python versions).
# Resolved from config.settings.sysmon_model_dir (env-overridable, defaults to
# <repo>/System Behavior/System_Behavior_Model/DETECTOR1/saved_model_v3) so this
# works regardless of which drive/path the repo is checked out to.
# ---------------------------------------------------------------------------
try:
    from config import settings as _settings
    _SYSMON_MODEL_DIR = _settings.sysmon_model_dir
except Exception:
    # agents/ -> Backend/ -> repo root, then into the System Behavior model tree.
    _SYSMON_MODEL_DIR = str(
        Path(__file__).resolve().parent.parent.parent
        / "System Behavior" / "System_Behavior_Model" / "DETECTOR1" / "saved_model_v3"
    )

_DETECTOR_PKL_PATH = str(Path(_SYSMON_MODEL_DIR) / "detector.pkl")
_DETECTOR_SRC_PATH = str(Path(_SYSMON_MODEL_DIR).parent / "windows_detector_final.py")

# Sysmon EventID → readable name (subset used for token generation)
_SYSMON_EVENTS: dict[str, str] = {
    "1":  "ProcessCreate",
    "2":  "FileCreationTimeChanged",
    "3":  "NetworkConnect",
    "5":  "ProcessTerminate",
    "6":  "DriverLoad",
    "7":  "ImageLoad",
    "8":  "CreateRemoteThread",
    "10": "ProcessAccess",
    "11": "FileCreate",
    "12": "RegistryObjectAddedOrDeleted",
    "13": "RegistryValueSet",
    "15": "FileCreateStreamHash",
    "17": "PipeCreated",
    "22": "DNSQuery",
    "23": "FileDelete",
    "25": "ProcessTampering",
    "26": "FileDeleteDetected",
}

# Benign Windows process names — scoring is suppressed for these unless
# EventID 8 (CreateRemoteThread) or 25 (ProcessTampering) is involved.
_BENIGN_WHITELIST: frozenset[str] = frozenset({
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
    "mpdefendercoreservice.exe", "msmpeng.exe", "nissrv.exe",
    "securityhealthservice.exe", "powershell_ise.exe", "unknown",
})

_HIGH_RISK_EIDS: frozenset[str] = frozenset({"8", "25"})


def _sysmon_event_to_token(event: dict) -> tuple[str | None, dict]:
    """
    Convert a Sysmon event dict (Winlogbeat NDJSON format or flat format from
    SysmonFileReader) into a TF-IDF token string matching the vocabulary used
    during detector.pkl training.

    Mirrors sysmon_event_to_token() in windows_detector_final.py exactly so
    the token representation is identical to the training corpus.

    Returns (token_str, meta_dict).  Returns (None, {}) for unknown EventIDs
    or on any parse error.
    """
    try:
        # Support both Winlogbeat nested format {"winlog": {...}} and the flat
        # format produced by SysmonFileReader {"event_id": "1", "process": ...}
        winlog = event.get("winlog", event)
        event_id = str(
            winlog.get("event_id")
            or winlog.get("EventID")
            or event.get("event_id")
            or ""
        )
        if event_id not in _SYSMON_EVENTS:
            return None, {}

        data = winlog.get("event_data", winlog.get("EventData", {}))
        # Flat-format fields also live at top level
        if not data and event_id == "1":
            data = {
                "Image": event.get("process", ""),
                "CommandLine": event.get("command_line", ""),
            }
        eid_name = _SYSMON_EVENTS[event_id]

        if event_id == "7":
            img = data.get("ImageLoaded", data.get("Image", ""))
            base = os.path.basename(img).lower()
            token = f"{base}+{eid_name}"
        elif event_id == "3":
            port = data.get("DestinationPort", "0")
            proto = data.get("Protocol", "tcp")
            token = f"net+{eid_name}_{proto}_{port}"
        elif event_id in ("12", "13"):
            key = data.get("TargetObject", "")
            hive = key.split("\\")[0].lower() if "\\" in key else "registry"
            token = f"{hive}+{eid_name}"
        else:
            img = data.get("Image", data.get("ParentImage", ""))
            if not img:
                img = event.get("process", "")
            base = os.path.basename(img).lower() if img else "unknown.exe"
            token = f"{base}+{eid_name}"

        meta = {
            "event_id":    event_id,
            "pid":         str(data.get("ProcessId",
                               data.get("SourceProcessId",
                               event.get("pid", "0")))),
            "image":       data.get("Image",
                           data.get("ParentImage",
                           event.get("process", "unknown"))),
            "commandline": data.get("CommandLine",
                           event.get("command_line", "")),
            "high_risk":   event_id in _HIGH_RISK_EIDS,
        }
        return token, meta
    except Exception:
        return None, {}


# ---------------------------------------------------------------------------
# BehavioralDetector — wraps detector.pkl
# ---------------------------------------------------------------------------
class BehavioralDetector:
    """
    Thin wrapper around the pre-trained WindowsAnomalyDetector from
    DETECTOR1/saved_model_v3/detector.pkl.

    The detector was trained on TF-IDF(ngram 1-3) of GHC DLL call-stack
    traces + Sysmon token sequences.  It exposes a single method:

        score(sysmon_events) -> {"behavioral_score": float,
                                  "attack_type": str,
                                  "is_anomaly": bool,
                                  "confidence": float,
                                  "features": dict}

    Scoring requires at least 10 Sysmon event tokens to produce a meaningful
    result (matches the MIN_WINDOW in SysmonMonitor).  Fewer events return a
    zero score.
    """

    # Minimum token count before we trust the TF-IDF score
    MIN_TOKENS = 10
    # Headroom multiplier: anomaly_score must exceed iso_threshold × this
    MARGIN = 0.005
    # Score ceiling for normalisation (maps raw anomaly_score → [0, 1])
    # The detector's raw anomaly_score is -iso_decision_function which is
    # typically in the range [-1, +2].  We cap normalisation at 2.0.
    _SCORE_CEIL = 2.0

    def __init__(self, pkl_path: str = _DETECTOR_PKL_PATH):
        self._model = None
        self._loaded = False
        self._pkl_path = pkl_path
        self._load(pkl_path)

    def _load(self, path: str) -> None:
        """Attempt to load detector.pkl.  Logs a warning and stays in
        degraded mode on any failure — never raises.

        detector.pkl was pickled with the WindowsAnomalyDetector class from
        windows_detector_final.py.  Python's pickle requires that class to be
        importable at load time.  We inject it into sys.modules temporarily so
        pickle.load finds it without permanently polluting the namespace.
        """
        if not _JOBLIB_AVAILABLE:
            logger.warning(
                "BehavioralDetector: joblib not available — "
                "behavioral detection disabled."
            )
            return
        try:
            import pickle
            import sys
            import importlib.util

            # detector.pkl was pickled when windows_detector_final.py ran as
            # __main__, so pickle stored the class as __main__.WindowsAnomalyDetector.
            # To deserialise, we load windows_detector_final.py as a module and
            # inject its WindowsAnomalyDetector class into sys.modules["__main__"]
            # temporarily so pickle.load can find it.
            _DETECTOR_SRC = _DETECTOR_SRC_PATH
            _INJECTED = False
            _main_mod = sys.modules.get("__main__")
            if _main_mod is not None and not hasattr(_main_mod, "WindowsAnomalyDetector"):
                # Load windows_detector_final as a side module, grab its class,
                # and inject it into __main__ for pickle's benefit.
                try:
                    _spec = importlib.util.spec_from_file_location(
                        "_wdf_temp", _DETECTOR_SRC
                    )
                    if _spec is not None:
                        _wdf = importlib.util.module_from_spec(_spec)
                        # Suppress argparse-related side effects by ensuring the
                        # module is not loaded as __main__
                        _spec.loader.exec_module(_wdf)
                        _main_mod.WindowsAnomalyDetector = _wdf.WindowsAnomalyDetector
                        _INJECTED = True
                except Exception as _imp_exc:
                    logger.debug(
                        f"BehavioralDetector: could not inject WindowsAnomalyDetector "
                        f"into __main__: {_imp_exc}"
                    )

            with open(path, "rb") as fh:
                model = pickle.load(fh)

            # Clean up the temporary injection so we don't pollute __main__
            if _INJECTED and _main_mod is not None:
                try:
                    del _main_mod.WindowsAnomalyDetector
                except AttributeError:
                    pass

            # Basic sanity check — must have vectorizer + iso_forest attributes
            if not (hasattr(model, "vectorizer") and hasattr(model, "iso_forest")):
                raise ValueError(
                    "detector.pkl does not look like a WindowsAnomalyDetector "
                    f"(missing vectorizer or iso_forest attributes). "
                    f"Loaded type: {type(model)}"
                )
            self._model = model
            self._loaded = True
            vocab_size = len(getattr(model.vectorizer, "vocabulary_", {}))
            threshold = getattr(model, "iso_threshold", 0.0)
            logger.info(
                f"BehavioralDetector: detector.pkl loaded — "
                f"vocab={vocab_size} iso_threshold={threshold:.4f}"
            )
        except FileNotFoundError:
            logger.warning(
                f"BehavioralDetector: detector.pkl not found at {path}. "
                "Behavioral detection disabled (LSTM-only mode)."
            )
        except Exception as exc:
            logger.warning(
                f"BehavioralDetector: failed to load detector.pkl: {exc}. "
                "Behavioral detection disabled (LSTM-only mode).",
                exc_info=True,
            )

    @property
    def loaded(self) -> bool:
        return self._loaded

    def score(self, sysmon_events: list) -> dict:
        """
        Score a batch of Sysmon event dicts.

        Args:
            sysmon_events: list of Sysmon event dicts (Winlogbeat NDJSON or
                           flat SysmonFileReader format).

        Returns dict with keys:
            behavioral_score  float [0.0, 1.0]
            attack_type       str — predicted class label or "Benign"
            is_anomaly        bool
            confidence        float [0.0, 1.0]
            features          dict — diagnostic metadata
        """
        _zero = {
            "behavioral_score": 0.0,
            "attack_type": "Benign",
            "is_anomaly": False,
            "confidence": 0.0,
            "features": {},
        }

        if not self._loaded or self._model is None:
            return _zero

        try:
            # Convert events to tokens
            tokens = []
            high_risk = False
            images = []
            for ev in sysmon_events:
                token, meta = _sysmon_event_to_token(ev)
                if token is not None:
                    tokens.append(token)
                    if meta.get("high_risk"):
                        high_risk = True
                    img = meta.get("image", "")
                    if img:
                        images.append(os.path.basename(img).lower())

            if len(tokens) < self.MIN_TOKENS:
                # Not enough data for a reliable score
                return {
                    **_zero,
                    "features": {
                        "token_count": len(tokens),
                        "reason": "insufficient_tokens",
                    },
                }

            tokens_str = " ".join(tokens)
            result = self._model.predict([tokens_str])[0]

            raw_score = float(result.get("anomaly_score", 0.0))
            label = str(result.get("label", "Background"))
            confidence = float(result.get("confidence", 0.0))
            nz = int(result.get("nonzero_feats", 0))
            is_raw_anomaly = bool(result.get("is_anomaly", False))

            # Apply the same suppression logic as SysmonMonitor._score():
            # whitelist check — if ALL images are benign and no high-risk event,
            # suppress the alert.
            all_benign_images = bool(images) and all(
                img in _BENIGN_WHITELIST for img in images
            )
            iso_threshold = float(getattr(self._model, "iso_threshold", 0.0))
            score_ok = raw_score > ((-iso_threshold) + self.MARGIN)
            low_feats = nz < 5

            is_anomaly = (
                high_risk
                or (is_raw_anomaly and score_ok and not all_benign_images and not low_feats)
            )

            # Normalise raw anomaly_score to [0.0, 1.0].
            # raw_score = -iso_decision_function; higher = more anomalous.
            # Clamp negative values (more normal than training average) to 0.
            normalised = max(0.0, min(1.0, raw_score / self._SCORE_CEIL))

            # If suppression applies, floor the normalised score at 0.1
            # (the event still happened, just not alert-worthy)
            if not is_anomaly:
                normalised = min(normalised, 0.10)

            attack_type = label if (is_anomaly and label != "Background") else "Benign"

            return {
                "behavioral_score": round(normalised, 4),
                "attack_type": attack_type,
                "is_anomaly": is_anomaly,
                "confidence": round(confidence, 4),
                "features": {
                    "token_count": len(tokens),
                    "nonzero_feats": nz,
                    "raw_anomaly_score": round(raw_score, 4),
                    "iso_threshold": round(iso_threshold, 4),
                    "high_risk_event": high_risk,
                    "all_benign_images": all_benign_images,
                },
            }

        except Exception as exc:
            logger.debug(f"BehavioralDetector.score error: {exc}")
            return _zero


# ---------------------------------------------------------------------------
# Feature names — 20 features, order is the contract for SHAP compatibility
# ---------------------------------------------------------------------------
FEATURE_NAMES: list[str] = [
    "cpu_percent",
    "mem_percent",
    "disk_read_bytes_norm",
    "disk_write_bytes_norm",
    "net_bytes_sent_norm",
    "net_bytes_recv_norm",
    "num_processes",
    "num_threads",
    "cpu_freq_current",
    "swap_percent",
    "open_files_count",
    "ctx_switches_norm",
    "interrupts_norm",
    "disk_read_count_norm",
    "disk_write_count_norm",
    "net_packets_sent_norm",
    "net_packets_recv_norm",
    "net_errin_norm",
    "net_errout_norm",
    "mem_available_norm",
]

N_FEATURES: int = len(FEATURE_NAMES)   # 20
WINDOW_SIZE: int = 60                  # seconds


# ---------------------------------------------------------------------------
# LSTM Autoencoder definition
# Must match the architecture used in train_system_model.py exactly.
# ---------------------------------------------------------------------------
def _build_model_class():
    """Return the LSTMAutoencoder class only if torch is available."""
    if not _TORCH_AVAILABLE:
        return None

    class LSTMAutoencoder(nn.Module):
        """
        Encoder:  LSTM(n_features → hidden_dim, return_sequences=False)
                  → Linear(hidden_dim → bottleneck_dim)   [bottleneck]
        Decoder:  Linear(bottleneck_dim → hidden_dim)
                  → repeat seq_len times
                  → LSTM(hidden_dim → hidden_dim, return_sequences=True)
                  → Linear(hidden_dim → n_features)  per timestep
        """

        def __init__(
            self,
            n_features: int = N_FEATURES,
            hidden_dim: int = 64,
            bottleneck_dim: int = 32,
            seq_len: int = WINDOW_SIZE,
        ):
            super().__init__()
            self.seq_len = seq_len
            self.hidden_dim = hidden_dim
            self.bottleneck_dim = bottleneck_dim

            # Encoder
            self.encoder_lstm = nn.LSTM(
                input_size=n_features,
                hidden_size=hidden_dim,
                num_layers=1,
                batch_first=True,
            )
            self.encoder_fc = nn.Linear(hidden_dim, bottleneck_dim)

            # Decoder
            self.decoder_fc = nn.Linear(bottleneck_dim, hidden_dim)
            self.decoder_lstm = nn.LSTM(
                input_size=hidden_dim,
                hidden_size=hidden_dim,
                num_layers=1,
                batch_first=True,
            )
            self.output_fc = nn.Linear(hidden_dim, n_features)

        def forward(self, x: "torch.Tensor") -> "torch.Tensor":
            # x: (batch, seq_len, n_features)
            _, (h_n, _) = self.encoder_lstm(x)        # h_n: (1, batch, hidden_dim)
            h_n = h_n.squeeze(0)                       # (batch, hidden_dim)
            bottleneck = self.encoder_fc(h_n)          # (batch, bottleneck_dim)

            # Decode: expand bottleneck to seq_len timesteps
            dec_input = self.decoder_fc(bottleneck)    # (batch, hidden_dim)
            dec_input = dec_input.unsqueeze(1).repeat(1, self.seq_len, 1)  # (batch, seq, hidden)
            dec_out, _ = self.decoder_lstm(dec_input)  # (batch, seq, hidden)
            reconstruction = self.output_fc(dec_out)   # (batch, seq, n_features)
            return reconstruction

    return LSTMAutoencoder


LSTMAutoencoder = _build_model_class()


# ---------------------------------------------------------------------------
# Telemetry collector — pure psutil, no torch dependency
# ---------------------------------------------------------------------------
class _TelemetryCollector:
    """Collects one feature vector per call to sample()."""

    def __init__(self):
        # Previous-tick counters for delta calculations
        self._prev_disk_read: int = 0
        self._prev_disk_write: int = 0
        self._prev_net_sent: int = 0
        self._prev_net_recv: int = 0
        self._prev_ctx: int = 0
        self._prev_interrupts: int = 0
        self._prev_disk_read_count: int = 0
        self._prev_disk_write_count: int = 0
        self._prev_pkt_sent: int = 0
        self._prev_pkt_recv: int = 0
        self._prev_errin: int = 0
        self._prev_errout: int = 0
        self._initialised = False

    def _init_counters(self) -> None:
        if not _PSUTIL_AVAILABLE:
            return
        try:
            d = psutil.disk_io_counters()
            n = psutil.net_io_counters()
            c = psutil.cpu_stats()
            if d:
                self._prev_disk_read = d.read_bytes
                self._prev_disk_write = d.write_bytes
                self._prev_disk_read_count = d.read_count
                self._prev_disk_write_count = d.write_count
            if n:
                self._prev_net_sent = n.bytes_sent
                self._prev_net_recv = n.bytes_recv
                self._prev_pkt_sent = n.packets_sent
                self._prev_pkt_recv = n.packets_recv
                self._prev_errin = n.errin
                self._prev_errout = n.errout
            if c:
                self._prev_ctx = c.ctx_switches
                self._prev_interrupts = c.interrupts
            self._initialised = True
        except Exception as exc:
            logger.debug(f"TelemetryCollector init counters error: {exc}")

    def sample(self) -> list[float]:
        """Return a list of N_FEATURES floats, or zeros on error."""
        if not _PSUTIL_AVAILABLE:
            return [0.0] * N_FEATURES

        if not self._initialised:
            self._init_counters()
            # First sample: deltas are zero — still valid, just conservative
            return [0.0] * N_FEATURES

        try:
            # --- psutil reads ---
            cpu = psutil.cpu_percent(interval=None)
            mem = psutil.virtual_memory()
            swap = psutil.swap_memory()
            disk_io = psutil.disk_io_counters()
            net_io = psutil.net_io_counters()
            cpu_stats = psutil.cpu_stats()
            cpu_freq = psutil.cpu_freq()

            # Thread count — sum across all processes, skip inaccessible ones
            thread_count = 0
            try:
                for p in psutil.process_iter(["num_threads"]):
                    try:
                        thread_count += p.info["num_threads"] or 0
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass
            except Exception:
                thread_count = 0

            # Open files for this process (non-critical)
            open_files = 0
            try:
                open_files = len(psutil.Process(os.getpid()).open_files())
            except Exception:
                open_files = 0

            # --- Deltas ---
            dr = disk_io.read_bytes if disk_io else self._prev_disk_read
            dw = disk_io.write_bytes if disk_io else self._prev_disk_write
            drc = disk_io.read_count if disk_io else self._prev_disk_read_count
            dwc = disk_io.write_count if disk_io else self._prev_disk_write_count
            ns = net_io.bytes_sent if net_io else self._prev_net_sent
            nr = net_io.bytes_recv if net_io else self._prev_net_recv
            nps = net_io.packets_sent if net_io else self._prev_pkt_sent
            npr = net_io.packets_recv if net_io else self._prev_pkt_recv
            nei = net_io.errin if net_io else self._prev_errin
            neo = net_io.errout if net_io else self._prev_errout
            ctx = cpu_stats.ctx_switches if cpu_stats else self._prev_ctx
            intr = cpu_stats.interrupts if cpu_stats else self._prev_interrupts

            disk_read_delta = max(0, dr - self._prev_disk_read)
            disk_write_delta = max(0, dw - self._prev_disk_write)
            disk_rc_delta = max(0, drc - self._prev_disk_read_count)
            disk_wc_delta = max(0, dwc - self._prev_disk_write_count)
            net_sent_delta = max(0, ns - self._prev_net_sent)
            net_recv_delta = max(0, nr - self._prev_net_recv)
            pkt_sent_delta = max(0, nps - self._prev_pkt_sent)
            pkt_recv_delta = max(0, npr - self._prev_pkt_recv)
            errin_delta = max(0, nei - self._prev_errin)
            errout_delta = max(0, neo - self._prev_errout)
            ctx_delta = max(0, ctx - self._prev_ctx)
            intr_delta = max(0, intr - self._prev_interrupts)

            # Update previous counters
            self._prev_disk_read = dr
            self._prev_disk_write = dw
            self._prev_disk_read_count = drc
            self._prev_disk_write_count = dwc
            self._prev_net_sent = ns
            self._prev_net_recv = nr
            self._prev_pkt_sent = nps
            self._prev_pkt_recv = npr
            self._prev_errin = nei
            self._prev_errout = neo
            self._prev_ctx = ctx
            self._prev_interrupts = intr

            freq = (cpu_freq.current / 3600.0) if cpu_freq else 0.0

            features = [
                float(cpu),                          # cpu_percent
                float(mem.percent),                  # mem_percent
                disk_read_delta / 1e6,               # disk_read_bytes_norm  (MB)
                disk_write_delta / 1e6,              # disk_write_bytes_norm (MB)
                net_sent_delta / 1e6,                # net_bytes_sent_norm   (MB)
                net_recv_delta / 1e6,                # net_bytes_recv_norm   (MB)
                float(len(psutil.pids())),           # num_processes
                float(thread_count),                 # num_threads
                float(freq),                         # cpu_freq_current (normalised ~1.0)
                float(swap.percent),                 # swap_percent
                float(open_files),                   # open_files_count
                ctx_delta / 1000.0,                  # ctx_switches_norm
                intr_delta / 1000.0,                 # interrupts_norm
                disk_rc_delta / 100.0,               # disk_read_count_norm
                disk_wc_delta / 100.0,               # disk_write_count_norm
                pkt_sent_delta / 100.0,              # net_packets_sent_norm
                pkt_recv_delta / 100.0,              # net_packets_recv_norm
                float(errin_delta) / 10.0,           # net_errin_norm
                float(errout_delta) / 10.0,          # net_errout_norm
                mem.available / (1024 ** 3),         # mem_available_norm (GB)
            ]
            return features

        except Exception as exc:
            logger.debug(f"TelemetryCollector.sample error: {exc}")
            return [0.0] * N_FEATURES


# ---------------------------------------------------------------------------
# Module-level Sysmon event ring buffer
# ---------------------------------------------------------------------------
# backend.py appends raw Sysmon event dicts here inside _handle_sysmon_result
# so the SystemMonitorAgent._collect_loop() can consume them on its next tick
# and pass them to the behavioral detector.
#
# maxlen=50 means at most 50 events are kept between consecutive 1-second
# psutil ticks.  At the observed Sysmon event rate (~5-20 events/s during
# normal operation) this covers 2-10 seconds of context.
_sysmon_event_ring: deque = deque(maxlen=50)


# ---------------------------------------------------------------------------
# SystemMonitorAgent
# ---------------------------------------------------------------------------
class SystemMonitorAgent:
    """
    Async background agent that collects system telemetry at 1 Hz, maintains
    a 60-second rolling window, and scores each window using an LSTM Autoencoder.

    Usage:
        agent = SystemMonitorAgent(
            model_dir="D:/Cyber Sentinal/Backend",
            on_result=my_async_callback,
        )
        await agent.start()
        # ... later ...
        await agent.stop()

    Callback signature:
        async def my_async_callback(result: dict): ...

        result keys:
            anomaly_score  float [0.0, 1.0]
            severity       str   "LOW"|"MEDIUM"|"HIGH"|"CRITICAL"
            features_snapshot  list[float]  — last raw feature vector
            ts             str   ISO-8601 UTC
            source         str   "system_monitor"
    """

    def __init__(
        self,
        model_dir: str = r"D:\Cyber Sentinal\Backend",
        interval_seconds: int = 1,
        window_size: int = WINDOW_SIZE,
        on_result: Optional[Callable] = None,
    ):
        self.model_dir = Path(model_dir)
        self.interval_seconds = interval_seconds
        self.window_size = window_size
        self.on_result = on_result

        self._buffer: deque = deque(maxlen=window_size)
        self._task: Optional[asyncio.Task] = None
        self._running = False

        self._model = None
        self._scaler = None
        self._anomaly_threshold: float = 1.0   # 99th-pct training error; 1.0 = no normalisation
        self._model_loaded = False
        self._last_score: float = 0.0
        self._last_degraded_fire: float = 0.0
        self._collector = _TelemetryCollector()

        # Rolling self-calibration — tracks last 300 MSE values (~5 min at 1/s)
        # After the first 60 windows the threshold adapts to the running system's
        # actual reconstruction error distribution so heavy ML workloads are not
        # falsely flagged as CRITICAL.
        self._mse_history: deque = deque(maxlen=300)
        self._calibration_windows: int = 0

        self._load_artifacts()

        # Behavioral detector — second detection path using detector.pkl.
        # Loaded unconditionally; BehavioralDetector degrades gracefully if the
        # file is missing or sklearn version mismatches.
        self._behavioral: BehavioralDetector = BehavioralDetector(_DETECTOR_PKL_PATH)

    # ------------------------------------------------------------------
    # Artifact loading
    # ------------------------------------------------------------------

    def _load_artifacts(self) -> None:
        """Load model, scaler, and metadata.  Logs warnings on failure."""
        meta_path = self.model_dir / "system_metadata.json"
        scaler_path = self.model_dir / "system_scaler.pkl"
        model_path = self.model_dir / "system_model.pt"

        # Load metadata first to get hyperparameters
        hidden_dim = 64
        bottleneck_dim = 32
        n_features = N_FEATURES
        window_size = self.window_size

        if meta_path.exists():
            try:
                with open(meta_path, "r", encoding="utf-8") as fh:
                    meta = json.load(fh)
                self._anomaly_threshold = float(meta.get("anomaly_threshold", 1.0))
                hidden_dim = int(meta.get("hidden_dim", 64))
                bottleneck_dim = int(meta.get("bottleneck_dim", 32))
                n_features = int(meta.get("n_features", N_FEATURES))
                window_size = int(meta.get("window_size", self.window_size))
                logger.info(
                    f"SystemMonitorAgent: metadata loaded — "
                    f"threshold={self._anomaly_threshold:.6f}"
                )
            except Exception as exc:
                logger.warning(f"SystemMonitorAgent: failed to load metadata: {exc}")
        else:
            logger.warning(
                f"SystemMonitorAgent: system_metadata.json not found in {self.model_dir}. "
                "Run train_system_model.py to generate model artifacts."
            )

        # Load scaler
        if scaler_path.exists() and _JOBLIB_AVAILABLE:
            try:
                self._scaler = joblib.load(str(scaler_path))
                logger.info("SystemMonitorAgent: scaler loaded")
            except Exception as exc:
                logger.warning(f"SystemMonitorAgent: failed to load scaler: {exc}")
        elif not scaler_path.exists():
            logger.warning(
                f"SystemMonitorAgent: system_scaler.pkl not found in {self.model_dir}."
            )

        # Load PyTorch model
        if not _TORCH_AVAILABLE:
            return
        if not model_path.exists():
            logger.warning(
                f"SystemMonitorAgent: system_model.pt not found in {self.model_dir}."
            )
            return

        try:
            model_cls = LSTMAutoencoder
            if model_cls is None:
                return
            model = model_cls(
                n_features=n_features,
                hidden_dim=hidden_dim,
                bottleneck_dim=bottleneck_dim,
                seq_len=window_size,
            )
            state_dict = torch.load(str(model_path), map_location="cpu", weights_only=True)
            model.load_state_dict(state_dict)
            model.eval()
            self._model = model
            self._model_loaded = True
            logger.info("SystemMonitorAgent: LSTM Autoencoder loaded successfully")
        except Exception as exc:
            logger.error(f"SystemMonitorAgent: failed to load model: {exc}", exc_info=True)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def start(self) -> None:
        """Start the background telemetry collection and scoring loop."""
        if self._running:
            return
        if not _PSUTIL_AVAILABLE:
            logger.warning(
                "SystemMonitorAgent: psutil not available — cannot start collection loop."
            )
            return
        self._running = True
        self._task = asyncio.create_task(
            self._collect_loop(), name="system_monitor_agent"
        )
        logger.info(
            f"SystemMonitorAgent started "
            f"(model_loaded={self._model_loaded}, interval={self.interval_seconds}s)"
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
        logger.info("SystemMonitorAgent stopped")

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def score(self) -> float:
        """Return the most recent anomaly score, or 0.0 if buffer not yet full."""
        return self._last_score

    def status(self) -> dict:
        return {
            "running": self._running,
            "model_loaded": self._model_loaded,
            "buffer_fill": len(self._buffer),
            "window_size": self.window_size,
            "last_score": self._last_score,
            "psutil_available": _PSUTIL_AVAILABLE,
            "torch_available": _TORCH_AVAILABLE,
            "behavioral_detector_loaded": self._behavioral.loaded,
            "sysmon_ring_size": len(_sysmon_event_ring),
        }

    def get_last_window(self) -> "list | None":
        """
        Return the last complete window of raw (unscaled) feature vectors.

        Each element is a list of N_FEATURES floats as produced by
        _TelemetryCollector.sample().  Returns None when the buffer has not
        yet accumulated a full window_size of samples.

        This method exists specifically to feed the SHAP explain_system()
        method, which needs the unscaled window so it can re-scale internally
        (matching the exact transform applied during _infer()).
        """
        if len(self._buffer) < self.window_size:
            return None
        # Materialise the deque slice — deque slicing is O(k) not O(n)
        return [list(row) for row in list(self._buffer)[-self.window_size:]]

    @property
    def feature_names(self) -> list:
        """Ordered list of feature name strings (FEATURE_NAMES module constant)."""
        return list(FEATURE_NAMES)

    def predict_from_metrics(
        self,
        metrics: dict,
        sysmon_events: Optional[list] = None,
    ) -> dict:
        """
        Score a single endpoint telemetry snapshot using the resource-aware
        heuristic path, optionally fused with behavioral detection from
        detector.pkl when Sysmon events are provided.

        The LSTM Autoencoder is trained on *this server's* own psutil data.
        Applying it to a remote endpoint would yield inaccurate reconstruction
        errors, so this method intentionally uses _heuristic_score() +
        _resource_aware_severity() instead.  The LSTM continues to monitor the
        local server via the normal _collect_loop() path.

        Args:
            metrics: dict from endpoint agent system_collector.py with keys:
                cpu_percent, memory_percent, disk_percent, process_count,
                processes (list of per-process dicts).
            sysmon_events: optional list of Sysmon event dicts (Winlogbeat
                NDJSON or flat SysmonFileReader format).  When provided and
                detector.pkl is loaded, behavioral detection runs and the
                final score = max(heuristic_score, behavioral_score).
                The behavioral attack_type label dominates when
                behavioral_score > heuristic_score.

        Returns:
            dict with keys: system_score, anomaly_score, severity,
            is_genuinely_anomalous, features_snapshot, feature_names,
            source, ts, and (when behavioral detection ran) behavioral_score,
            behavioral_attack_type, behavioral_confidence.
            On any error returns a safe fallback dict with system_score=0.0.
        """
        try:
            cpu = float(metrics.get("cpu_percent", 0.0))
            mem = float(metrics.get("memory_percent", 0.0))

            # Build a 20-element feature vector in FEATURE_NAMES order.
            # Delta-based I/O counters are unavailable from an endpoint snapshot
            # (they require two consecutive readings); default those to 0.0.
            features: list[float] = [
                cpu,                                        # cpu_percent
                mem,                                        # mem_percent
                0.0,                                        # disk_read_bytes_norm
                0.0,                                        # disk_write_bytes_norm
                0.0,                                        # net_bytes_sent_norm
                0.0,                                        # net_bytes_recv_norm
                float(metrics.get("process_count", 0)),     # num_processes
                0.0,                                        # num_threads
                0.0,                                        # cpu_freq_current
                0.0,                                        # swap_percent
                0.0,                                        # open_files_count
                0.0,                                        # ctx_switches_norm
                0.0,                                        # interrupts_norm
                0.0,                                        # disk_read_count_norm
                0.0,                                        # disk_write_count_norm
                0.0,                                        # net_packets_sent_norm
                0.0,                                        # net_packets_recv_norm
                0.0,                                        # net_errin_norm
                0.0,                                        # net_errout_norm
                0.0,                                        # mem_available_norm
            ]

            heuristic_score = self._heuristic_score(features)

            # --- Behavioral detection path ---
            behavioral_result: dict = {}
            behavioral_score: float = 0.0
            if sysmon_events and self._behavioral.loaded:
                behavioral_result = self._behavioral.score(sysmon_events)
                behavioral_score = float(behavioral_result.get("behavioral_score", 0.0))

            # Fuse: take the worst-case score.  Behavioral dominates label
            # when it produces a higher score than the heuristic.
            if behavioral_score > heuristic_score:
                final_score = behavioral_score
                attack_type = behavioral_result.get("attack_type", "Behavioral Anomaly")
                logger.debug(
                    f"[endpoint_system] behavioral score dominates: "
                    f"heuristic={heuristic_score:.4f} behavioral={behavioral_score:.4f} "
                    f"attack_type={attack_type}"
                )
            else:
                final_score = heuristic_score
                attack_type = "System Resource Anomaly"

            severity = _resource_aware_severity(final_score, features)

            logger.debug(
                f"[endpoint_system] cpu={cpu:.1f}% mem={mem:.1f}% "
                f"heuristic={heuristic_score:.4f} behavioral={behavioral_score:.4f} "
                f"final={final_score:.4f} severity={severity}"
            )

            result: dict = {
                "system_score": round(final_score, 4),
                "anomaly_score": round(final_score, 4),
                "severity": severity,
                "is_genuinely_anomalous": severity in ("HIGH", "CRITICAL"),
                "features_snapshot": [round(f, 4) for f in features],
                "feature_names": FEATURE_NAMES,
                "source": "system_monitor_endpoint",
                "ts": datetime.now(timezone.utc).isoformat(),
            }

            # Include behavioral fields when they ran so the frontend and
            # SHAP agent can use them for richer explanations.
            if behavioral_result:
                result["behavioral_score"] = round(behavioral_score, 4)
                result["behavioral_attack_type"] = behavioral_result.get("attack_type", "Benign")
                result["behavioral_confidence"] = round(
                    float(behavioral_result.get("confidence", 0.0)), 4
                )
                result["behavioral_is_anomaly"] = bool(behavioral_result.get("is_anomaly", False))

            return result

        except Exception as exc:  # noqa: BLE001
            logger.debug(f"predict_from_metrics error: {exc}")
            return {
                "system_score": 0.0,
                "severity": "LOW",
                "is_genuinely_anomalous": False,
                "source": "system_monitor_endpoint",
                "error": str(exc),
            }

    # ------------------------------------------------------------------
    # Sysmon event ring buffer — backend.py appends recent Sysmon events here
    # so the server-side _infer() path can score them alongside psutil data.
    # Exposed as a module-level list so backend.py can do:
    #   from agents.system_monitor_agent import _sysmon_event_ring
    #   _sysmon_event_ring.append(event)
    # This attribute must only be accessed by one coroutine at a time (the
    # GIL protects simple list.append / list() copies in CPython).
    # ------------------------------------------------------------------

    def _consume_sysmon_ring(self) -> list:
        """
        Return a snapshot of the current sysmon event ring buffer and clear it.
        Thread-safe under CPython's GIL for simple list operations.
        """
        return list(_sysmon_event_ring)

    # ------------------------------------------------------------------
    # Internal loop
    # ------------------------------------------------------------------

    async def _collect_loop(self) -> None:
        while self._running:
            t0 = time.monotonic()
            try:
                features = await asyncio.to_thread(self._collector.sample)
                self._buffer.append(features)

                # Warmup path: emit heuristic every 5 s while buffer is filling
                # (model loaded or not).  Fires only when buffer < window_size, so
                # it stops as soon as the model-inference branch below takes over.
                # The two conditions are mutually exclusive (< vs ==), preventing
                # dual-fire for the first tick where the buffer reaches window_size.
                if len(self._buffer) > 0 and len(self._buffer) < self.window_size:
                    now = time.monotonic()
                    if now - self._last_degraded_fire >= 5.0:
                        h_score = self._heuristic_score(features)
                        self._last_score = h_score
                        self._last_degraded_fire = now
                        await self._fire_result(h_score, features)

                if len(self._buffer) == self.window_size:
                    # Snapshot and pass any buffered Sysmon events so behavioral
                    # detection can fuse with the LSTM score in the same tick.
                    recent_sysmon = self._consume_sysmon_ring()
                    score, behavioral = await asyncio.to_thread(
                        self._infer, recent_sysmon if recent_sysmon else None
                    )
                    self._last_score = score
                    await self._fire_result(score, features, behavioral or None)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                logger.debug(f"SystemMonitorAgent collect tick error: {exc}")

            elapsed = time.monotonic() - t0
            sleep_for = max(0.0, self.interval_seconds - elapsed)
            await asyncio.sleep(sleep_for)

    def _heuristic_score(self, features: list[float]) -> float:
        """
        Rule-based anomaly score derived from raw psutil features.
        Used when the LSTM model is not yet trained/loaded (degraded mode).

        features[0] = cpu_percent  (0-100)
        features[1] = mem_percent  (0-100)

        Returns float in [0.0, 1.0].
        """
        cpu = features[0] if len(features) > 0 else 0.0
        mem = features[1] if len(features) > 1 else 0.0

        if cpu > 95:
            cpu_score = 1.0
        elif cpu > 85:
            cpu_score = 0.80
        elif cpu > 75:
            cpu_score = 0.60
        elif cpu > 65:
            cpu_score = 0.40
        else:
            cpu_score = 0.0

        if mem > 95:
            mem_score = 0.85
        elif mem > 90:
            mem_score = 0.60
        elif mem > 85:
            mem_score = 0.40
        else:
            mem_score = 0.0

        return min(1.0, max(cpu_score, mem_score))

    def _infer(self, sysmon_events: Optional[list] = None) -> tuple[float, dict]:
        """
        Run LSTM Autoencoder on the current 60-second buffer, then fuse with
        behavioral detection if sysmon_events are provided.

        Returns (final_score, behavioral_result_dict).
        final_score is in [0.0, 1.0].
        behavioral_result_dict is empty when behavioral detection did not run.

        Falls back to heuristic score if the LSTM model is not loaded.
        """
        lstm_score: float = 0.0
        last_features = list(self._buffer)[-1] if self._buffer else [0.0] * N_FEATURES

        if not self._model_loaded or self._model is None or not _TORCH_AVAILABLE:
            lstm_score = self._heuristic_score(last_features)
        else:
            try:
                import numpy as _np

                # Build (60, 20) array from buffer
                window = list(self._buffer)                   # list of 60 × list[float]
                arr = _np.array(window, dtype=_np.float32)    # (60, 20)

                # Scale features if scaler is available
                if self._scaler is not None:
                    arr = self._scaler.transform(arr).astype(_np.float32)

                # Add batch dimension → (1, 60, 20)
                tensor = torch.from_numpy(arr).unsqueeze(0)   # (1, 60, 20)

                with torch.no_grad():
                    reconstruction = self._model(tensor)      # (1, 60, 20)

                # MSE reconstruction error per timestep, then mean over window
                mse = ((tensor - reconstruction) ** 2).mean().item()

                # Track rolling MSE history for self-calibration
                self._mse_history.append(mse)
                self._calibration_windows += 1

                # After 60 windows adapt the threshold to the running system so
                # that heavy-workload machines are not falsely flagged CRITICAL.
                _CALIBRATION_WARMUP = 60
                if (self._calibration_windows >= _CALIBRATION_WARMUP
                        and len(self._mse_history) >= 20):
                    running_99th = float(_np.percentile(list(self._mse_history), 99))
                    effective_threshold = max(
                        self._anomaly_threshold, running_99th * 1.5
                    )
                else:
                    effective_threshold = self._anomaly_threshold

                if effective_threshold > 0:
                    lstm_score = min(1.0, mse / effective_threshold)
                else:
                    lstm_score = 0.0

            except Exception as exc:
                logger.debug(f"SystemMonitorAgent LSTM inference error: {exc}")
                lstm_score = self._heuristic_score(last_features)

        # --- Behavioral detection path (server loop) ---
        behavioral_result: dict = {}
        behavioral_score: float = 0.0
        if sysmon_events and self._behavioral.loaded:
            try:
                behavioral_result = self._behavioral.score(sysmon_events)
                behavioral_score = float(behavioral_result.get("behavioral_score", 0.0))
            except Exception as exc:
                logger.debug(f"SystemMonitorAgent behavioral score error: {exc}")

        # Fuse: worst-case wins
        final_score = max(lstm_score, behavioral_score)

        if behavioral_score > lstm_score and behavioral_score > 0:
            logger.debug(
                f"[server_system] BEHAVIORAL dominates: "
                f"lstm={lstm_score:.4f} behavioral={behavioral_score:.4f} "
                f"attack_type={behavioral_result.get('attack_type','?')}"
            )

        return float(final_score), behavioral_result

    async def _fire_result(
        self,
        score: float,
        features: list[float],
        behavioral_result: Optional[dict] = None,
    ) -> None:
        """Build result dict and invoke on_result callback."""
        severity = _resource_aware_severity(score, features)
        # is_genuinely_anomalous is True when either:
        # (a) the severity label from _resource_aware_severity is HIGH or CRITICAL, OR
        # (b) the behavioral detector fired (is_anomaly=True) regardless of how
        #     _resource_aware_severity capped the label — a confirmed behavioral
        #     detection must always flow through to SHAP and fusion correlation.
        behavioral_fired = bool(
            behavioral_result and behavioral_result.get("is_anomaly", False)
        )
        result: dict = {
            "anomaly_score": round(score, 4),
            "severity": severity,
            "is_genuinely_anomalous": severity in ("HIGH", "CRITICAL") or behavioral_fired,
            "features_snapshot": [round(f, 4) for f in features],
            "feature_names": FEATURE_NAMES,
            "buffer_fill": len(self._buffer),
            "ts": datetime.now(timezone.utc).isoformat(),
            "source": "system_monitor",
        }
        # Attach behavioral fields when they contributed to the score
        if behavioral_result:
            result["behavioral_score"] = round(
                float(behavioral_result.get("behavioral_score", 0.0)), 4
            )
            result["behavioral_attack_type"] = behavioral_result.get("attack_type", "Benign")
            result["behavioral_confidence"] = round(
                float(behavioral_result.get("confidence", 0.0)), 4
            )
            result["behavioral_is_anomaly"] = bool(
                behavioral_result.get("is_anomaly", False)
            )
        if self.on_result is not None:
            try:
                await self.on_result(result)
            except Exception as exc:
                logger.error(f"SystemMonitorAgent on_result callback error: {exc}", exc_info=True)


# ---------------------------------------------------------------------------
# Severity mapping (shared with backend result handler)
# ---------------------------------------------------------------------------
def _score_to_severity(score: float) -> str:
    if score >= 0.85:
        return "CRITICAL"
    if score >= 0.65:
        return "HIGH"
    if score >= 0.35:
        return "MEDIUM"
    return "LOW"


def _resource_aware_severity(score: float, features: list[float]) -> str:
    """
    Override pure-ML severity with resource-based thresholds.
    features[0] = cpu_percent, features[1] = mem_percent (from FEATURE_NAMES).
    """
    cpu = features[0] if len(features) > 0 else 0.0
    mem = features[1] if len(features) > 1 else 0.0

    # Hard thresholds for genuine hardware stress
    if cpu > 85.0 or mem > 95.0:
        if score >= 0.65:
            return "CRITICAL"
        elif score >= 0.35:
            return "HIGH"
        else:
            return "MEDIUM"   # hardware stressed but model shows no validated anomaly
    if cpu > 80.0 and mem > 80.0:
        return "HIGH" if score >= 0.35 else "MEDIUM"
    if cpu > 70.0 or mem > 90.0:
        return "MEDIUM" if score >= 0.35 else "LOW"

    # Below hardware stress thresholds — cap ML score at MEDIUM
    ml_sev = _score_to_severity(score)
    if ml_sev == "CRITICAL":
        return "MEDIUM"   # model is likely wrong (e.g. scaler mismatch)
    if ml_sev == "HIGH":
        return "MEDIUM"
    return ml_sev          # LOW or MEDIUM pass through
