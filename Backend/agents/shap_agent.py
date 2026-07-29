"""
SHAP Explainability Agent
Generates human-readable explanations for model predictions using SHAP
TreeExplainer.  Supports three models:
  - network: CIC-IDS2017 RandomForest classifier (network_classifier.pkl)
  - malware: LightGBM binary classifier (malware_model.pkl)
  - system:  LSTM Autoencoder (reconstruction-error decomposition proxy)
"""
import logging
from pathlib import Path
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

try:
    import shap as _shap
    _SHAP_AVAILABLE = True
except ImportError:
    _SHAP_AVAILABLE = False
    logger.warning("shap library not installed. Run: pip install shap")

try:
    import joblib as _joblib
    _JOBLIB_AVAILABLE = True
except ImportError:
    _JOBLIB_AVAILABLE = False


class SHAPAgent:
    """
    Wraps shap.TreeExplainer around the CIC RandomForest classifier.

    Produces a dict with:
      - top_features: ordered list of (feature_name, shap_value) for the predicted class
      - reason: human-readable list of the top contributing factors
      - base_value: model base (expected) output
      - predicted_class: the attack type being explained
    """

    def __init__(
        self,
        model_path: Optional[str] = None,
        features_path: Optional[str] = None,
        malware_model_path: Optional[str] = None,
        malware_features_path: Optional[str] = None,
    ):
        if not _SHAP_AVAILABLE:
            raise ImportError("shap is required: pip install shap")
        if not _JOBLIB_AVAILABLE:
            raise ImportError("joblib is required: pip install joblib")

        # Network RandomForest explainer — optional until network_classifier.pkl is trained
        self.model = None
        self.feature_names: list[str] = []
        self.label_encoder = None
        self.explainer = None
        self._is_multiclass = False

        if model_path is not None and features_path is not None:
            try:
                self.model = _joblib.load(model_path)
                self.feature_names = _joblib.load(features_path)

                label_encoder_path = Path(model_path).parent / "network_label_encoder.pkl"
                if label_encoder_path.exists():
                    try:
                        self.label_encoder = _joblib.load(label_encoder_path)
                    except Exception as e:
                        logger.warning(f"Could not load label encoder: {e}")

                logger.info("Building SHAP TreeExplainer for network model…")
                self.explainer = _shap.TreeExplainer(self.model)
                self._is_multiclass = hasattr(self.model, "classes_") and len(self.model.classes_) > 2
                logger.info("SHAP TreeExplainer (network) ready")
            except Exception as e:
                logger.warning(f"SHAPAgent: network model unavailable — {e}")
        else:
            logger.info("SHAPAgent: network model paths not provided — network SHAP disabled until network_classifier.pkl is trained")

        # Malware LightGBM explainer — built on demand or at init if paths provided
        self._malware_explainer = None
        self._malware_feature_names: list[str] = []
        if malware_model_path is not None and malware_features_path is not None:
            self.load_malware_model(malware_model_path, malware_features_path)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explain(
        self,
        features: dict,
        attack_type: Optional[str] = None,
        top_n: int = 8,
        model: str = "network",
        **kwargs,
    ) -> dict:
        """
        Explain a single prediction.

        Args:
            features:    Dict mapping feature_name → float value (alert doc for network)
                         OR a pre-scaled list/array of 280 floats (malware).
                         Ignored for model="system" — pass window/model/scaler/feature_names
                         as keyword arguments instead.
            attack_type: Predicted class label (e.g. "DoS", "PortScan", "malware").
                         Ignored for malware and system models.
            top_n:       Number of top contributing features to return.
            model:       "network" (default), "malware", or "system".  Routes to
                         the appropriate explainer.
            **kwargs:    Forwarded to explain_system() when model="system".
                         Required keys: features_window, model (torch Module),
                         scaler, feature_names.

        Returns:
            For network model:
                {
                    "predicted_class": str,
                    "base_value": float,
                    "top_features": [{"feature": str, "shap_value": float,
                                      "feature_value": float}, ...],
                    "reason": [str, ...],
                }
            For malware model: see ``explain_malware`` docstring.
            For system model:  see ``explain_system`` docstring.
        """
        if model == "malware":
            # features may be passed as a list/array when routing through here
            feature_list = features if isinstance(features, (list, np.ndarray)) else list(features.values())
            return self.explain_malware(feature_list, prediction=attack_type or "malware", top_n=top_n)

        if model == "system":
            return self.explain_system(top_n=top_n, **kwargs)

        try:
            X = self._build_feature_row(features)
            shap_values = self.explainer.shap_values(X)

            class_idx = self._resolve_class_idx(attack_type)
            row_shap = self._select_class_shap(shap_values, class_idx)

            # Sort by absolute SHAP value descending
            ranked = sorted(
                zip(self.feature_names, row_shap[0], X[0]),
                key=lambda t: abs(t[1]),
                reverse=True,
            )[:top_n]

            top_features = [
                {"feature": name, "shap_value": round(float(sv), 5), "feature_value": round(float(fv), 4)}
                for name, sv, fv in ranked
            ]
            reason = self._features_to_reason(top_features)

            base_value = self._get_base_value(shap_values, class_idx)

            return {
                "predicted_class": attack_type or self._idx_to_label(class_idx),
                "base_value": round(float(base_value), 5),
                "top_features": top_features,
                "reason": reason,
            }

        except Exception as e:
            logger.error(f"SHAP explanation failed: {e}", exc_info=True)
            return {"predicted_class": attack_type or "unknown", "base_value": 0.0,
                    "top_features": [], "reason": [f"Explanation unavailable: {e}"]}

    # ------------------------------------------------------------------
    # Malware explainability
    # ------------------------------------------------------------------

    def load_malware_model(self, model_path: str, features_path: str) -> None:
        """
        Load the LightGBM malware classifier and build its TreeExplainer.

        Can be called at init (via constructor params) or lazily at runtime.
        Silently degrades on any error so the network explainer keeps working.

        Args:
            model_path:    Path to malware_model.pkl (LGBMClassifier).
            features_path: Path to malware_feature_names.pkl (list of 280 names).
        """
        try:
            malware_model = _joblib.load(model_path)
            self._malware_feature_names = _joblib.load(features_path)
            logger.info("Building SHAP TreeExplainer for malware model (this may take a moment)…")
            self._malware_explainer = _shap.TreeExplainer(malware_model)
            logger.info("SHAP TreeExplainer (malware) ready — %d features", len(self._malware_feature_names))
        except Exception as e:
            logger.warning("Malware SHAP explainer could not be initialised: %s", e)
            self._malware_explainer = None
            self._malware_feature_names = []

    def explain_malware(
        self,
        features: "list | np.ndarray",
        prediction: str = "malware",
        top_n: int = 5,
    ) -> dict:
        """
        Explain a malware model prediction.

        Args:
            features:   280-dim feature vector — already scaled, as produced by
                        MalwareAnalysisAgent._run_inference before predict_proba.
                        Accepts a Python list or a 1-D / 2-D numpy array.
            prediction: Human-readable prediction label ("malware" / "benign").
            top_n:      Number of top features to include (default 5).

        Returns:
            {
                "model": "malware",
                "prediction": str,
                "top_features": [
                    {
                        "feature": str,         # raw feature name
                        "shap_value": float,    # positive = pushes toward malware
                        "direction": str,       # "increases_risk" | "decreases_risk"
                    },
                    ...
                ],
                "reason": [str, ...],           # human-readable, max top_n items
            }
        """
        if self._malware_explainer is None:
            logger.error("Malware SHAP explainer not initialised — call load_malware_model() first")
            return {
                "model": "malware",
                "prediction": prediction,
                "top_features": [],
                "reason": ["Malware SHAP explainer not available"],
            }

        try:
            # Normalise input to shape (1, 280)
            arr = np.array(features, dtype=np.float64)
            if arr.ndim == 1:
                arr = arr.reshape(1, -1)

            shap_values = self._malware_explainer.shap_values(arr)

            # LightGBM binary classifier: shap_values may be a list [class0, class1]
            # or a single array of shape (1, n_features).  We always want class-1
            # (malware) SHAP values.
            if isinstance(shap_values, list):
                if len(shap_values) == 2:
                    row_shap = shap_values[1][0]   # class 1, first (only) row
                else:
                    row_shap = shap_values[0][0]
            else:
                # Single array from modern shap versions for binary classifiers
                row_shap = shap_values[0]

            feature_names = self._malware_feature_names
            # Guard against length mismatch
            n = min(len(feature_names), len(row_shap))

            ranked = sorted(
                zip(feature_names[:n], row_shap[:n], arr[0][:n]),
                key=lambda t: abs(t[1]),
                reverse=True,
            )[:top_n]

            top_features = [
                {
                    "feature": name,
                    "shap_value": round(float(sv), 5),
                    "direction": "increases_risk" if sv >= 0 else "decreases_risk",
                }
                for name, sv, _fv in ranked
            ]

            reason = self._malware_features_to_reason(top_features)

            return {
                "model": "malware",
                "prediction": prediction,
                "top_features": top_features,
                "reason": reason,
            }

        except Exception as e:
            logger.error("Malware SHAP explanation failed: %s", e, exc_info=True)
            return {
                "model": "malware",
                "prediction": prediction,
                "top_features": [],
                "reason": [f"Explanation unavailable: {e}"],
            }

    # ------------------------------------------------------------------
    # System Monitor LSTM Autoencoder explainability
    # Uses reconstruction-error decomposition as a SHAP proxy.
    # For each feature, the squared difference between the LSTM's input and
    # reconstructed output (averaged over the 60-second time window) measures
    # how anomalous that feature's behaviour was — an exact, fast attribution
    # that requires no additional SHAP passes through the model.
    # ------------------------------------------------------------------

    #: Human-readable labels for all 20 system telemetry feature names.
    _SYSTEM_FEATURE_LABELS: dict = {
        "cpu_percent":           "CPU usage",
        "mem_percent":           "Memory usage",
        "disk_read_bytes_norm":  "Disk read rate",
        "disk_write_bytes_norm": "Disk write rate",
        "net_bytes_sent_norm":   "Network bytes sent",
        "net_bytes_recv_norm":   "Network bytes received",
        "num_processes":         "Process count",
        "num_threads":           "Thread count",
        "cpu_freq_current":      "CPU frequency",
        "swap_percent":          "Swap usage",
        "open_files_count":      "Open file handles",
        "ctx_switches_norm":     "Context switches",
        "interrupts_norm":       "Hardware interrupts",
        "disk_read_count_norm":  "Disk read ops",
        "disk_write_count_norm": "Disk write ops",
        "net_packets_sent_norm": "Network packets sent",
        "net_packets_recv_norm": "Network packets received",
        "net_errin_norm":        "Network receive errors",
        "net_errout_norm":       "Network send errors",
        "mem_available_norm":    "Available memory",
    }

    def explain_system(
        self,
        features_window: list,
        model,
        scaler,
        feature_names: list,
        top_n: int = 5,
    ) -> dict:
        """
        Produce a SHAP-style attribution for a system anomaly using
        reconstruction-error decomposition over the LSTM Autoencoder's output.

        This is the recommended approach for LSTM autoencoders: rather than
        running shap.DeepExplainer (which requires a representative background
        dataset and is significantly slower), we compute the per-feature mean
        squared reconstruction error directly.  The error for each feature is
        proportional to its contribution to the anomaly score, making it an
        exact and interpretable attribution — not an approximation.

        Args:
            features_window: Raw (unscaled) feature window, shape
                             (window_size, n_features).  Accepts a list of
                             lists or a 2-D numpy array.
            model:           The LSTMAutoencoder torch.nn.Module instance.
                             Must already be in eval() mode.
            scaler:          The fitted sklearn StandardScaler used during
                             training.  Pass None to skip scaling (not
                             recommended — errors will be in raw units and
                             not directly comparable across features).
            feature_names:   Ordered list of feature name strings matching
                             the columns in features_window.
            top_n:           Number of top features to include in the output.

        Returns:
            {
                "method": "reconstruction_error",
                "feature_importances": [
                    {
                        "feature":    str,    # raw feature name
                        "label":      str,    # human-readable label
                        "importance": float,  # relative share of total error
                        "error":      float,  # raw per-feature MSE
                        "direction":  str,    # "high" | "low" | "unknown"
                    },
                    ...  # top_n entries, sorted by importance descending
                ],
                "top_features": [str, ...],  # top_n feature names only
                "reason":        [str, ...],  # up to top_n human-readable strings
                "raw_errors":    {feature_name: float, ...},
            }

        Gracefully returns an empty explanation dict if torch is unavailable,
        the model is None, or the window is too short.
        """
        _empty = {
            "method": "reconstruction_error",
            "feature_importances": [],
            "top_features": [],
            "reason": [],
            "raw_errors": {},
        }

        # Guard: torch must be importable at call time
        try:
            import torch as _torch
        except ImportError:
            logger.debug("explain_system: torch not available — skipping")
            return _empty

        if model is None:
            logger.debug("explain_system: model is None — skipping")
            return _empty

        if not features_window or len(features_window) < 2:
            logger.debug("explain_system: window too short (%d rows) — skipping", len(features_window) if features_window else 0)
            return _empty

        try:
            import numpy as np

            # ── Step 1: scale the window ─────────────────────────────────────
            arr = np.array(features_window, dtype=np.float32)  # (window_size, n_features)
            if scaler is not None:
                arr = scaler.transform(arr).astype(np.float32)

            # ── Step 2: build tensor (1, window_size, n_features) ───────────
            x = _torch.tensor(arr, dtype=_torch.float32).unsqueeze(0)

            # ── Step 3: forward pass (no grad needed) ───────────────────────
            model.eval()
            with _torch.no_grad():
                x_recon = model(x)

            # ── Step 4: per-feature reconstruction error ─────────────────────
            # Shape: (1, window_size, n_features) → squeeze → (window_size, n_features)
            # Mean over the time axis → (n_features,) — one MSE per feature.
            errors_t = ((x - x_recon) ** 2).squeeze(0).mean(dim=0)  # (n_features,)
            errors_np = errors_t.cpu().numpy()                        # plain numpy array

            # ── Step 5: relative importance ──────────────────────────────────
            total_error = float(errors_np.sum()) + 1e-9
            importances = errors_np / total_error                     # sums to 1.0

            # ── Step 6: direction — compare last 10-timestep mean to scaler mean ──
            n_feat = len(feature_names)
            raw_window_arr = np.array(features_window, dtype=np.float32)  # unscaled
            last_10 = raw_window_arr[-10:] if raw_window_arr.shape[0] >= 10 else raw_window_arr
            last_10_mean = last_10.mean(axis=0)   # (n_features,) unscaled means

            # Reference "normal" mean — use scaler.mean_ if available, else overall mean
            if scaler is not None and hasattr(scaler, "mean_"):
                ref_mean = scaler.mean_            # shape (n_features,)
            else:
                ref_mean = raw_window_arr.mean(axis=0)

            directions: list[str] = []
            for i in range(min(n_feat, len(last_10_mean))):
                ref = ref_mean[i] if i < len(ref_mean) else 0.0
                val = last_10_mean[i]
                if abs(ref) < 1e-9:
                    directions.append("unknown")
                elif val > ref * 1.05:
                    directions.append("high")
                else:
                    directions.append("low")

            # ── Step 7: rank and pick top_n ──────────────────────────────────
            indexed = sorted(
                range(min(n_feat, len(errors_np))),
                key=lambda i: importances[i],
                reverse=True,
            )[:top_n]

            feature_importances = []
            raw_errors: dict[str, float] = {}

            for i in range(min(n_feat, len(errors_np))):
                raw_errors[feature_names[i]] = round(float(errors_np[i]), 6)

            for i in indexed:
                fname = feature_names[i]
                label = self._SYSTEM_FEATURE_LABELS.get(fname, fname.replace("_", " "))
                direction = directions[i] if i < len(directions) else "unknown"
                feature_importances.append({
                    "feature":    fname,
                    "label":      label,
                    "importance": round(float(importances[i]), 4),
                    "error":      round(float(errors_np[i]), 6),
                    "direction":  direction,
                })

            # ── Step 8: human-readable reason strings ────────────────────────
            top_feature_names = [fi["feature"] for fi in feature_importances]
            reason = self._system_features_to_reason(feature_importances)

            return {
                "method": "reconstruction_error",
                "feature_importances": feature_importances,
                "top_features": top_feature_names,
                "reason": reason,
                "raw_errors": raw_errors,
            }

        except Exception as exc:
            logger.error("explain_system failed: %s", exc, exc_info=True)
            return _empty

    @staticmethod
    def _system_features_to_reason(feature_importances: list[dict]) -> list[str]:
        """
        Convert ranked system feature importances into plain-English reason strings.

        Only features with importance > 1% of total error are surfaced.
        Up to 5 unique labels are returned.
        """
        seen: set[str] = set()
        reasons: list[str] = []

        for fi in feature_importances:
            if fi["importance"] < 0.01:
                # Less than 1% contribution — not worth surfacing
                continue
            label = fi["label"]
            direction = fi["direction"]
            pct = fi["importance"] * 100.0
            if direction == "high":
                phrase = f"Elevated {label} (reconstruction error: {pct:.0f}%)"
            elif direction == "low":
                phrase = f"Abnormal {label} — below expected baseline ({pct:.0f}%)"
            else:
                phrase = f"Unusual {label} pattern ({pct:.0f}% of anomaly)"

            if label not in seen:
                seen.add(label)
                reasons.append(phrase)

        return reasons[:5] if reasons else ["No dominant system features identified"]

    # ------------------------------------------------------------------
    # Fusion explainability (no SHAP math — pure contribution accounting)
    # ------------------------------------------------------------------

    def explain_fusion(self, fusion_result: dict, top_n: int = 3) -> dict:
        """
        Produce a human-readable explanation for a Fusion Engine decision.

        Unlike the network and malware methods, this does NOT use SHAP
        mathematics.  The Fusion Engine is a weighted sum, so the
        contribution of each component model is already an exact,
        interpretable number.  This method simply ranks those contributions
        and formats them as reasons.

        Args:
            fusion_result: Dict produced by FusionResult.to_dict().  Must
                           contain a "components" key whose value maps each
                           model name to a sub-dict with at minimum the
                           keys "score", "weight", and "contribution".
            top_n:         Maximum number of component-level reason strings
                           to include (not counting escalation reasons
                           appended from "contributing_reasons").

        Returns:
            {
                "model": "fusion",
                "threat_score": float,
                "severity": str,
                "top_features": [
                    {
                        "feature":    str,    # model name, e.g. "network"
                        "shap_value": float,  # contribution (alias for compat)
                        "pct_share":  float,  # % of total contribution
                        "score":      float,  # raw model score 0-1
                    },
                    ...  # all models, sorted by contribution descending
                ],
                "reason": [str, ...],  # up to top_n component reasons
                                       # + all contributing_reasons strings
            }
        """
        components: dict = fusion_result.get("components", {})

        # --- contribution accounting -----------------------------------------
        total_contribution = sum(
            float(v.get("contribution", 0.0)) for v in components.values()
        )

        # Build and sort feature rows
        rows = []
        for model_name, comp in components.items():
            contribution = float(comp.get("contribution", 0.0))
            score = float(comp.get("score", 0.0))

            if total_contribution > 0:
                pct_share = contribution / total_contribution * 100.0
            else:
                pct_share = 0.0

            rows.append({
                "feature": model_name,
                "shap_value": round(contribution, 4),
                "pct_share": round(pct_share, 1),
                "score": round(score, 4),
            })

        rows.sort(key=lambda r: r["shap_value"], reverse=True)

        # --- reason list -------------------------------------------------------
        reason: list[str] = []

        # Component-level reasons (up to top_n)
        for row in rows[:top_n]:
            reason.append(
                f"{row['feature'].capitalize()} detection: "
                f"{row['pct_share']:.0f}% contribution "
                f"(score={row['score']:.2f})"
            )

        # Escalation / corroboration reasons from the Fusion Engine itself
        for extra in fusion_result.get("contributing_reasons", []):
            if isinstance(extra, str):
                reason.append(extra)

        if not reason:
            reason.append("No significant model contributions recorded")

        return {
            "model": "fusion",
            "threat_score": float(fusion_result.get("threat_score", 0.0)),
            "severity": str(fusion_result.get("severity", "LOW")),
            "top_features": rows,
            "reason": reason,
        }

    # ------------------------------------------------------------------
    # Sysmon Behavior explainability
    # Pure heuristic — no ML inference required (works even without detector.pkl).
    # Analyses raw Sysmon event fields and ranks suspicious indicators by weight.
    # Completes in <1 ms (dict lookups + string scans only).
    # ------------------------------------------------------------------

    #: (base_weight, human_label) for executable basenames (without .exe extension).
    _SUSPICIOUS_PROCESSES: dict = {
        "powershell":     (0.60, "PowerShell execution"),
        "powershell_ise": (0.70, "PowerShell ISE"),
        "cmd":            (0.40, "Command prompt"),
        "wscript":        (0.80, "Windows Script Host"),
        "cscript":        (0.80, "Windows Script Host (cscript)"),
        "mshta":          (0.90, "HTML Application Host (living-off-the-land)"),
        "certutil":       (0.85, "CertUtil (often used for download)"),
        "regsvr32":       (0.85, "RegSvr32 (COM execution bypass)"),
        "rundll32":       (0.70, "RunDLL32 execution"),
        "schtasks":       (0.75, "Scheduled task creation"),
        "psexec":         (0.95, "PsExec (lateral movement tool)"),
        "mimikatz":       (1.00, "Mimikatz (credential dumping tool)"),
        "net":            (0.60, "Net command (user/share enumeration)"),
        "netstat":        (0.40, "Network state inspection"),
        "whoami":         (0.50, "User identity enumeration"),
        "ipconfig":       (0.35, "Network config inspection"),
        "tasklist":       (0.45, "Process enumeration"),
        "reg":            (0.65, "Registry manipulation"),
        "bitsadmin":      (0.80, "BITS admin (download bypass)"),
        "curl":           (0.50, "HTTP client"),
        "wget":           (0.55, "HTTP download"),
        "nc":             (0.85, "Netcat"),
        "nmap":           (0.90, "Network scanner"),
    }

    #: (base_weight, human_label) for substrings found in command lines (lowercased).
    _SUSPICIOUS_CMD_TOKENS: dict = {
        "-enc":              (0.90, "Encoded command (obfuscation)"),
        "-encodedcommand":   (0.95, "Encoded PowerShell command"),
        "bypass":            (0.85, "Execution policy bypass"),
        "-hidden":           (0.80, "Hidden window"),
        "downloadstring":    (0.90, "In-memory download execution"),
        "invoke-expression": (0.90, "Dynamic code execution (IEX)"),
        "iex ":              (0.90, "IEX shorthand"),
        "base64":            (0.75, "Base64 encoding (obfuscation)"),
        "frombase64string":  (0.85, "Base64 decode (obfuscation)"),
        "webclient":         (0.80, "WebClient download"),
        "net.webclient":     (0.85, "Net.WebClient download"),
        "start-process":     (0.60, "Process spawning"),
        "invoke-mimikatz":   (1.00, "Mimikatz invocation"),
        "sekurlsa":          (1.00, "Mimikatz module"),
        "invoke-shellcode":  (1.00, "Shellcode injection"),
        "-nop":              (0.70, "No profile (stealth PowerShell)"),
        "-noninteractive":   (0.60, "Non-interactive (automated)"),
        "\\temp\\":          (0.70, "Execution from temp directory"),
        "\\appdata\\":       (0.65, "Execution from AppData"),
        "\\public\\":        (0.80, "Execution from Public folder"),
    }

    #: (parent_set, child_set, weight, mitre_id, label)
    #: Empty child_set means ANY child of that parent is suspicious.
    _SUSPICIOUS_PARENT_CHILD: list = [
        ({"winword", "excel", "powerpnt", "outlook"},
         {"powershell", "cmd", "wscript", "mshta"},
         0.95, "T1566", "Office app spawning shell (macro execution)"),
        ({"explorer"},
         {"powershell", "cmd"},
         0.55, "T1059", "Explorer spawning shell"),
        ({"svchost"},
         {"powershell", "cmd", "wscript"},
         0.85, "T1055", "Service host spawning shell (process injection)"),
        ({"lsass"},
         set(),
         0.99, "T1003", "LSASS child process (credential dumping)"),
        ({"winlogon"},
         {"powershell", "cmd"},
         0.90, "T1078", "Winlogon spawning shell (auth bypass)"),
    ]

    def explain_sysmon(
        self,
        raw_event: dict,
        anomaly_score: float = 0.0,
        top_n: int = 5,
    ) -> dict:
        """
        Produce a human-readable explanation for a Sysmon behavioral alert.

        This method uses pure heuristic analysis — no ML inference path.
        It works even when the Sysmon detector.pkl model is not loaded.
        Expected completion time: <1 ms (dict lookups + string scans only).

        Args:
            raw_event:     The raw Sysmon event dict as produced by
                           SysmonBehaviorAgent._score_pid() or the result
                           dict passed to the on_result callback.  Key fields
                           consumed: ``process_name``, ``commandline`` /
                           ``command_line``, ``image``, ``parent_image``,
                           ``event_type`` / ``event_id``, ``destination_ip``,
                           ``target_filename``, ``high_risk``, ``label``.
            anomaly_score: Normalised IsolationForest anomaly score [0.0, 1.0].
                           Used to scale indicator weights.
            top_n:         Maximum number of indicators to include in the output.

        Returns:
            {
                "method": "sysmon_indicator_analysis",
                "indicators": [
                    {
                        "indicator": str,   # human-readable label
                        "weight":    float, # 0.0–1.0 suspicion weight
                        "field":     str,   # which event field triggered this
                        "value":     str,   # the raw field value
                    },
                    ...  # up to top_n, sorted by weight descending
                ],
                "top_features": [str, ...],  # field names of top indicators
                "reason":       [str, ...],  # plain-English strings, max 5
                "mitre_hints":  [str, ...],  # MITRE technique IDs, deduplicated
            }
        """
        _empty = {
            "method": "sysmon_indicator_analysis",
            "indicators": [],
            "top_features": [],
            "reason": [],
            "mitre_hints": [],
        }

        try:
            # ── Field extraction ─────────────────────────────────────────────
            # Support both the result dict from _score_pid (process_name / commandline)
            # and the raw event dict from _sysmon_event_to_token (image / commandline).
            proc_name_raw = (
                raw_event.get("process_name")
                or raw_event.get("image", "")
            )
            # Basename + strip extension for matching against lookup tables
            import os as _os
            proc_base = _os.path.basename(proc_name_raw).lower()
            if proc_base.endswith(".exe"):
                proc_base = proc_base[:-4]

            parent_raw = raw_event.get("parent_image", "")
            parent_base = _os.path.basename(parent_raw).lower()
            if parent_base.endswith(".exe"):
                parent_base = parent_base[:-4]

            cmdline = (
                raw_event.get("commandline")
                or raw_event.get("command_line")
                or raw_event.get("cmdline", "")
            ).lower()

            event_id = str(raw_event.get("event_id", raw_event.get("event_type", "")))
            dest_ip = raw_event.get("destination_ip", raw_event.get("dest_ip", ""))
            target_file = raw_event.get("target_filename", raw_event.get("file", "")).lower()
            high_risk = bool(raw_event.get("high_risk", False))

            # ── Indicator accumulator ─────────────────────────────────────────
            # Each entry: (weight, field_name, field_value, human_label, mitre_id_or_None)
            raw_indicators: list[tuple] = []

            # 1. Process name check
            for stem, (base_w, label) in self._SUSPICIOUS_PROCESSES.items():
                if proc_base == stem or proc_base.startswith(stem):
                    # Scale weight upward if the anomaly score is high
                    w = min(1.0, base_w + anomaly_score * 0.15)
                    raw_indicators.append((w, "process_name", proc_name_raw, label, None))
                    break  # only the best match per field

            # 2. Command-line token scan
            best_cmd_hit: Optional[tuple] = None
            for token, (base_w, label) in self._SUSPICIOUS_CMD_TOKENS.items():
                if token in cmdline:
                    w = min(1.0, base_w + anomaly_score * 0.10)
                    if best_cmd_hit is None or w > best_cmd_hit[0]:
                        # Surface the cmdline value truncated to 120 chars
                        display_cmd = raw_event.get("commandline") or raw_event.get("cmdline", "")
                        display_cmd = (display_cmd[:120] + "...") if len(display_cmd) > 120 else display_cmd
                        best_cmd_hit = (w, "command_line", display_cmd, label, "T1059")
            if best_cmd_hit:
                raw_indicators.append(best_cmd_hit)

            # 3. Parent-child relationship check
            if parent_base:
                for parent_set, child_set, base_w, mitre_id, label in self._SUSPICIOUS_PARENT_CHILD:
                    parent_match = any(parent_base == p or parent_base.startswith(p)
                                       for p in parent_set)
                    if parent_match:
                        child_match = (
                            not child_set  # empty = any child is suspicious
                            or any(proc_base == c or proc_base.startswith(c) for c in child_set)
                        )
                        if child_match:
                            w = min(1.0, base_w + anomaly_score * 0.05)
                            detail = f"{_os.path.basename(parent_raw)} -> {_os.path.basename(proc_name_raw)}"
                            raw_indicators.append((w, "parent_image", detail, label, mitre_id))
                            break

            # 4. High-risk EventID (CreateRemoteThread=8, ProcessTampering=25)
            if high_risk or event_id in ("8", "25"):
                eid_labels = {
                    "8":  ("CreateRemoteThread detected (code injection)", "T1055", 0.88),
                    "25": ("Process tampering / hollowing detected", "T1055.012", 0.92),
                }
                eid_w, eid_mitre, eid_base_w = eid_labels.get(event_id, (
                    "High-risk Sysmon event detected", "T1055", 0.75
                ))
                raw_indicators.append((
                    min(1.0, eid_base_w + anomaly_score * 0.08),
                    "event_id", event_id, eid_w, eid_mitre
                ))

            # 5. Network connection from non-browser process (EventID 3)
            if event_id == "3" and dest_ip:
                non_net_procs = {"powershell", "cmd", "wscript", "cscript", "mshta",
                                 "rundll32", "regsvr32", "certutil", "bitsadmin"}
                if proc_base in non_net_procs:
                    w = min(1.0, 0.75 + anomaly_score * 0.10)
                    raw_indicators.append((
                        w, "destination_ip", dest_ip,
                        f"Non-browser process making network connection to {dest_ip}",
                        "T1071"
                    ))

            # 6. File write to suspicious locations (EventID 11)
            if event_id == "11" and target_file:
                suspicious_paths = {
                    "\\temp\\":    (0.65, "File written to temp directory", "T1074"),
                    "\\startup\\":  (0.85, "File written to Startup folder (persistence)", "T1547"),
                    "\\appdata\\": (0.60, "File written to AppData", "T1074"),
                    "\\public\\":  (0.75, "File written to Public folder", "T1074"),
                    "\\system32\\": (0.70, "File written to System32", "T1036"),
                }
                for path_tok, (base_w, label, mitre_id) in suspicious_paths.items():
                    if path_tok in target_file:
                        w = min(1.0, base_w + anomaly_score * 0.10)
                        raw_indicators.append((w, "target_filename", target_file[:80], label, mitre_id))
                        break

            # 7. Registry modification to run keys (EventIDs 12, 13)
            if event_id in ("12", "13"):
                run_key_tokens = {"\\run\\", "\\runonce\\", "\\currentversion\\run"}
                target_obj = raw_event.get("target_filename", raw_event.get("TargetObject", "")).lower()
                if any(tok in target_obj for tok in run_key_tokens):
                    w = min(1.0, 0.82 + anomaly_score * 0.10)
                    raw_indicators.append((
                        w, "target_filename", target_obj[:80],
                        "Registry Run key modification (persistence)", "T1547.001"
                    ))
                else:
                    # Any registry event from a suspicious process is notable
                    if proc_base in self._SUSPICIOUS_PROCESSES:
                        w = min(1.0, 0.55 + anomaly_score * 0.10)
                        raw_indicators.append((
                            w, "event_id", event_id,
                            "Registry modification by suspicious process", "T1112"
                        ))

            # 8. Anomaly score itself as a fallback indicator
            if anomaly_score >= 0.50 and not raw_indicators:
                raw_indicators.append((
                    anomaly_score,
                    "anomaly_score",
                    f"{anomaly_score:.3f}",
                    f"High behavioral anomaly score ({anomaly_score:.0%})",
                    None
                ))

            # ── Sort and deduplicate ──────────────────────────────────────────
            raw_indicators.sort(key=lambda t: t[0], reverse=True)
            raw_indicators = raw_indicators[:top_n]

            # ── Build output structures ───────────────────────────────────────
            indicators = []
            top_features: list[str] = []
            mitre_seen: set[str] = set()
            mitre_hints: list[str] = []

            for weight, field, value, ind_label, mitre_id in raw_indicators:
                indicators.append({
                    "indicator": ind_label,
                    "weight":    round(float(weight), 3),
                    "field":     field,
                    "value":     str(value),
                })
                if field not in top_features:
                    top_features.append(field)
                if mitre_id and mitre_id not in mitre_seen:
                    mitre_seen.add(mitre_id)
                    mitre_hints.append(mitre_id)

            reason = self._sysmon_indicators_to_reason(
                indicators,
                proc_name_raw,
                anomaly_score,
            )

            return {
                "method": "sysmon_indicator_analysis",
                "indicators": indicators,
                "top_features": top_features,
                "reason": reason,
                "mitre_hints": mitre_hints,
            }

        except Exception as exc:
            logger.error("explain_sysmon failed: %s", exc, exc_info=True)
            return _empty

    @staticmethod
    def _sysmon_indicators_to_reason(
        indicators: list[dict],
        proc_name: str,
        anomaly_score: float,
    ) -> list[str]:
        """Convert ranked Sysmon indicators into plain-English reason strings."""
        import os as _os
        reasons: list[str] = []
        seen_labels: set[str] = set()

        for ind in indicators:
            label = ind["indicator"]
            field = ind["field"]
            value = ind["value"]
            weight = ind["weight"]

            if label in seen_labels:
                continue
            seen_labels.add(label)

            if field == "parent_image":
                reasons.append(f"Suspicious parent process: {value}")
            elif field == "command_line":
                reasons.append(f"{label} in: {value[:60]}..." if len(value) > 60 else f"{label} detected")
            elif field == "process_name":
                reasons.append(f"{label}: {_os.path.basename(proc_name)}")
            elif field == "destination_ip":
                reasons.append(label)
            elif field == "target_filename":
                reasons.append(label)
            elif field == "event_id":
                reasons.append(label)
            elif field == "anomaly_score":
                reasons.append(label)
            else:
                reasons.append(label)

        if not reasons and anomaly_score >= 0.35:
            proc_display = _os.path.basename(proc_name) if proc_name else "unknown process"
            reasons.append(f"Behavioral anomaly detected for {proc_display} (score: {anomaly_score:.0%})")

        return reasons[:5]

    # ------------------------------------------------------------------
    # User Behavior OC-SVM explainability
    # Uses leave-one-out sensitivity analysis as a SHAP-style proxy.
    # OC-SVM does not support TreeExplainer — this method approximates each
    # feature's contribution by measuring how much the decision_function
    # output changes when that feature is set to its anomalous value vs the
    # scaled-space baseline (all-zeros after StandardScaler normalisation).
    # Completes in <10 ms for a 19-feature model.
    # ------------------------------------------------------------------

    #: Human-readable labels for all known user behavior feature names.
    _USER_FEATURE_REASONS: dict = {
        # File activity
        "file_ops_count":        "high file operation count",
        "file_write_count":      "elevated file write count",
        "file_read_count":       "elevated file read count",
        "unique_files_accessed": "access to many unique files",
        "file_ops_rate":         "high file operation rate",
        # Logon/logoff events
        "logon_count":           "high login frequency",
        "logoff_count":          "high logoff frequency",
        "failed_logon_count":    "multiple failed logins",
        # Time-of-day and session patterns
        "after_hours_activity":  "after-hours activity detected",
        # Device / USB events
        "device_connects":       "unusual device connection count",
        "device_disconnects":    "unusual device disconnect count",
        "device_events":         "elevated removable-media events",
        # Email activity
        "emails_sent":           "high email volume",
        "unique_recipients":     "large number of email recipients",
        # OCEAN personality features (hardcoded to 0 when no HR feed available)
        "O":                     "atypical behavioral diversity",
        "C":                     "inconsistent work schedule",
        "E":                     "elevated network/social activity",
        "A":                     "irregular collaborative pattern",
        "N":                     "irregular access pattern",
    }

    def explain_user(
        self,
        feature_values: dict,
        decision_score: float,
        feature_columns: list,
        top_n: int = 5,
        user_model_path: Optional[str] = None,
        user_scaler_path: Optional[str] = None,
    ) -> list:
        """
        Sensitivity-based SHAP-style explanation for an OC-SVM / XGBoost
        user anomaly.

        For each feature, we compute the decision_function difference when
        that feature is set to its anomalous value versus the scaled-space
        baseline (all-zeros, i.e. the StandardScaler mean).  Features that
        push the model further into anomaly territory (more negative
        decision_function) are ranked highest.

        Args:
            feature_values:   Dict mapping feature_name → raw (unscaled) value
                              for the anomalous user row.
            decision_score:   Raw OC-SVM decision_function value for this row.
                              Negative means anomaly (returned by xdr_runtime).
            feature_columns:  Ordered list of feature names as stored in
                              feature_columns.json.
            top_n:            Number of top reason strings to return (default 5).
            user_model_path:  Absolute path to user_model.pkl.  If None the
                              method uses pure delta-from-zero attribution
                              (no model reload needed).
            user_scaler_path: Absolute path to user_scaler.pkl.

        Returns:
            List of human-readable reason strings (up to top_n, may be fewer).
            Returns a single-item fallback list on any error.
        """
        _fallback = ["Anomalous user behavior pattern detected"]

        # Guard: nothing to explain for an empty feature set
        if not feature_values and not feature_columns:
            return _fallback

        try:
            import numpy as np

            # ── Step 1: try to load model + scaler for sensitivity analysis ──
            model = None
            scaler = None
            if user_model_path and user_scaler_path:
                try:
                    model = _joblib.load(user_model_path)
                    scaler = _joblib.load(user_scaler_path)
                except Exception as load_err:
                    logger.debug("explain_user: could not load model/scaler — %s", load_err)

            # ── Step 2: build the raw feature vector for this row ───────────
            n_features = len(feature_columns)
            if n_features == 0:
                return _fallback

            raw_vec = np.array(
                [float(feature_values.get(f, 0.0)) for f in feature_columns],
                dtype=np.float64,
            )

            # ── Step 3: compute per-feature sensitivity scores ───────────────
            # Strategy A — model available: leave-one-out sensitivity
            # Build a baseline row (all zeros in scaled space = scaler mean in
            # raw space).  For each feature i, replace baseline[i] with the
            # anomalous value and measure the drop in decision_function.
            # A larger drop (more negative delta) → feature contributes more.
            #
            # Strategy B — no model: use |raw_value - 0| as a proxy (works
            # because StandardScaler centres to 0 mean, so deviation from 0
            # in the raw direction that caused the anomaly flag is informative).

            contributions: list[float] = []

            if model is not None and scaler is not None:
                try:
                    # Baseline in raw space: scaler.mean_ (scaled → 0 vector)
                    if hasattr(scaler, "mean_") and scaler.mean_ is not None:
                        baseline_raw = np.array(scaler.mean_, dtype=np.float64)
                    else:
                        baseline_raw = np.zeros(n_features, dtype=np.float64)

                    # Clip baseline length to feature count in case of mismatch
                    if len(baseline_raw) < n_features:
                        baseline_raw = np.concatenate([
                            baseline_raw,
                            np.zeros(n_features - len(baseline_raw))
                        ])
                    baseline_raw = baseline_raw[:n_features]

                    # Scale the full anomalous row once
                    scaled_full = scaler.transform(raw_vec.reshape(1, -1))

                    # Scaled baseline (should be all-zeros after StandardScaler)
                    scaled_baseline = scaler.transform(baseline_raw.reshape(1, -1))

                    # Get baseline decision score (reference point)
                    if hasattr(model, "decision_function"):
                        base_decision = float(model.decision_function(scaled_baseline)[0])
                    else:
                        base_decision = 0.0

                    # Leave-one-out: set one feature at a time to the anomalous value
                    for i in range(n_features):
                        probe = scaled_baseline.copy()
                        probe[0, i] = scaled_full[0, i]
                        if hasattr(model, "decision_function"):
                            probe_decision = float(model.decision_function(probe)[0])
                        else:
                            probe_decision = base_decision
                        # Negative delta = this feature pushes model toward anomaly
                        delta = base_decision - probe_decision  # positive when anomalous
                        contributions.append(delta)

                except Exception as sens_err:
                    logger.debug("explain_user: sensitivity analysis failed — %s", sens_err)
                    # Fall back to Strategy B
                    contributions = []

            # Strategy B fallback: use absolute deviation from zero (scaler mean)
            if not contributions:
                if model is not None and scaler is not None and hasattr(scaler, "mean_"):
                    try:
                        scaled = scaler.transform(raw_vec.reshape(1, -1))[0]
                        # |scaled value| measures how far from the scaler mean
                        contributions = [abs(float(v)) for v in scaled]
                    except Exception:
                        contributions = [abs(float(v)) for v in raw_vec]
                else:
                    contributions = [abs(float(v)) for v in raw_vec]

            # ── Step 4: rank features by absolute contribution ───────────────
            indexed = sorted(
                range(n_features),
                key=lambda i: abs(contributions[i]) if i < len(contributions) else 0.0,
                reverse=True,
            )

            # ── Step 5: map to human-readable reasons ────────────────────────
            reasons: list[str] = []
            seen_labels: set[str] = set()

            for i in indexed[:top_n]:
                if i >= len(contributions):
                    continue
                contrib = contributions[i]
                # Skip features with negligible contribution
                if abs(contrib) < 1e-6:
                    continue
                feature_name = feature_columns[i]
                label = self._USER_FEATURE_REASONS.get(
                    feature_name,
                    feature_name.replace("_", " ").lower(),
                )
                if label not in seen_labels:
                    seen_labels.add(label)
                    reasons.append(label)

            return reasons[:top_n] if reasons else _fallback

        except Exception as exc:
            logger.error("explain_user failed: %s", exc, exc_info=True)
            return _fallback

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------

    def status(self) -> dict:
        """Return a summary dict describing which explainers are operational."""
        return {
            "network_explainer": self.explainer is not None,
            "malware_explainer": self._malware_explainer is not None,
            "system_explainer": "reconstruction_error",
            "sysmon_explainer": "sysmon_indicator_analysis",
            "user_explainer": "sensitivity_leave_one_out",
            "network_feature_count": len(self.feature_names),
            "malware_feature_count": len(self._malware_feature_names),
            "system_feature_count": len(self._SYSTEM_FEATURE_LABELS),
            "user_feature_count": len(self._USER_FEATURE_REASONS),
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _build_feature_row(self, features: dict) -> np.ndarray:
        row = [float(features.get(f, 0.0)) for f in self.feature_names]
        return np.array([row], dtype=np.float64)

    def _resolve_class_idx(self, attack_type: Optional[str]) -> int:
        if attack_type and self.label_encoder is not None:
            try:
                return int(self.label_encoder.transform([attack_type])[0])
            except Exception:
                pass
        if attack_type and hasattr(self.model, "classes_"):
            classes = list(self.model.classes_)
            if attack_type in classes:
                return classes.index(attack_type)
        return 0

    def _select_class_shap(self, shap_values, class_idx: int) -> np.ndarray:
        if self._is_multiclass and isinstance(shap_values, list):
            idx = min(class_idx, len(shap_values) - 1)
            return shap_values[idx]
        if isinstance(shap_values, list) and len(shap_values) == 2:
            return shap_values[1]
        return shap_values if not isinstance(shap_values, list) else shap_values[0]

    def _get_base_value(self, shap_values, class_idx: int) -> float:
        try:
            ev = self.explainer.expected_value
            if isinstance(ev, (list, np.ndarray)):
                idx = min(class_idx, len(ev) - 1)
                return float(ev[idx])
            return float(ev)
        except Exception:
            return 0.0

    def _idx_to_label(self, class_idx: int) -> str:
        try:
            if self.label_encoder is not None:
                return str(self.label_encoder.inverse_transform([class_idx])[0])
            if hasattr(self.model, "classes_"):
                return str(self.model.classes_[class_idx])
        except Exception:
            pass
        return str(class_idx)

    @staticmethod
    def _features_to_reason(top_features: list[dict]) -> list[str]:
        """Convert SHAP feature values into plain-English reason strings."""
        _labels = {
            "Flow Bytes/s": "high byte rate",
            "Flow Packets/s": "high packet rate",
            "SYN Flag Count": "elevated SYN count",
            "ACK Flag Count": "ACK pattern anomaly",
            "RST Flag Count": "elevated RST count",
            "FIN Flag Count": "elevated FIN count",
            "Destination Port": "suspicious destination port",
            "Flow Duration": "unusual flow duration",
            "Total Fwd Packets": "large forward packet count",
            "Total Backward Packets": "large backward packet count",
            "Fwd Packets/s": "high forward packet rate",
            "Bwd Packets/s": "high backward packet rate",
            "Down/Up Ratio": "abnormal download/upload ratio",
            "Average Packet Size": "unusual average packet size",
            "Total Length of Fwd Packets": "large forward payload",
            "Total Length of Bwd Packets": "large backward payload",
        }
        reasons = []
        for item in top_features:
            if item["shap_value"] > 0:
                label = _labels.get(item["feature"], item["feature"].lower().replace("_", " "))
                reasons.append(label)
        return reasons[:5] if reasons else ["no dominant features identified"]

    @staticmethod
    def _malware_features_to_reason(top_features: list[dict]) -> list[str]:
        """Convert malware SHAP top-features into plain-English reason strings.

        Only features with direction == "increases_risk" are surfaced (positive
        SHAP values push the model toward the malware class).  Up to 5 unique
        labels are returned.
        """
        def _label(name: str) -> str:
            if name.startswith("hist_"):
                return "unusual byte distribution"
            _map = {
                "mean_byte_entropy": "high file entropy (likely packed)",
                "file_size": "suspicious file size",
                "max_section_entropy": "high section entropy",
                "avg_section_entropy": "high section entropy",
                "num_imported_libs": "suspicious import count",
                "num_imported_funcs_norm": "suspicious import count",
                "num_exported_funcs_norm": "unusual export count",
                "strings_entropy": "suspicious string entropy",
                "is_64bit": "architecture indicator",
                "subsystem": "architecture indicator",
            }
            return _map.get(name, name.replace("_", " "))

        seen: set[str] = set()
        reasons: list[str] = []
        for item in top_features:
            if item.get("direction") == "increases_risk":
                label = _label(item["feature"])
                if label not in seen:
                    seen.add(label)
                    reasons.append(label)
        return reasons[:5] if reasons else ["no dominant risk features identified"]
