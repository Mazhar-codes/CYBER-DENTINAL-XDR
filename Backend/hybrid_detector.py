# hybrid_detector.py
# Drop this file in D:\Cyber Sentinal\Network model\
# Import and use HybridDetector in backend.py

import logging
import os

import joblib
import numpy as np

logger = logging.getLogger(__name__)


# ── Detection logic ───────────────────────────────────────────────────────────
#
#  The hybrid uses TWO models in sequence:
#
#  GATE 1 — Personal Baseline Model (IsolationForest on YOUR traffic)
#    If score > personal_threshold → NORMAL for you → skip further checks
#    If score < personal_threshold → unusual for you → pass to Gate 2
#
#  GATE 2 — CIC-IDS2017 RandomForest Classifier
#    Classifies what TYPE of attack it looks like
#    If classified as BENIGN with high confidence → NORMAL
#    If classified as attack → ATTACK with type name
#
#  This means:
#    YouTube  → passes Gate 1 → NORMAL  (never reaches Gate 2)
#    PortScan → fails Gate 1  → Gate 2 → ATTACK: PortScan
#    New unknown attack → fails Gate 1 → Gate 2 → may still catch it
#
# ─────────────────────────────────────────────────────────────────────────────


class HybridDetector:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        self._load_models()

    def _load_models(self) -> None:
        # ── CIC classifier (attack type recognition) ──────────────────────
        cic_path = os.path.join(self.base_dir, "network_classifier.pkl")
        if os.path.exists(cic_path):
            self.cic_classifier = joblib.load(cic_path)
            self.cic_scaler = joblib.load(os.path.join(self.base_dir, "network_scaler.pkl"))
            self.cic_label_encoder = joblib.load(
                os.path.join(self.base_dir, "network_label_encoder.pkl")
            )
            self.cic_features = joblib.load(os.path.join(self.base_dir, "network_features.pkl"))
            # Force single-threaded inference. n_jobs=8 spins up a joblib
            # ThreadingBackend on EVERY predict; with endpoint telemetry arriving
            # every 5s this thrashed the CPU (18-38s per call, server starved and
            # unresponsive). For the small batches scored at runtime, n_jobs=1
            # runs in milliseconds with no thread contention.
            try:
                self.cic_classifier.n_jobs = 1
            except Exception:
                pass
            self.has_cic = True
            logger.info(
                "✅ CIC classifier loaded — classes: %s",
                list(self.cic_label_encoder.classes_),
            )
        else:
            self.has_cic = False
            logger.warning(
                "⚠️  CIC classifier not found — falling back to isolation forest only"
            )
            # Fall back to old isolation forest
            self.iso_model = joblib.load(
                os.path.join(self.base_dir, "network_model_isolation.pkl")
            )
            self.iso_scaler = joblib.load(
                os.path.join(self.base_dir, "network_scaler.pkl")
            )
            self.iso_features = joblib.load(
                os.path.join(self.base_dir, "network_features.pkl")
            )
            try:
                self.iso_model.n_jobs = 1
            except Exception:
                pass

        # ── Personal baseline model (YOUR normal traffic) ──────────────────
        personal_path = os.path.join(self.base_dir, "personal_baseline_model.pkl")
        if os.path.exists(personal_path):
            artifacts = joblib.load(personal_path)
            self.personal_model = artifacts["model"]
            try:
                self.personal_model.n_jobs = 1
            except Exception:
                pass
            self.personal_scaler = artifacts["scaler"]
            self.personal_threshold = artifacts["threshold"]
            self.personal_features = artifacts["features"]
            self.personal_stats = artifacts["stats"]
            self.has_personal = True
            logger.info(
                "✅ Personal baseline loaded — %s training flows, threshold=%.4f",
                f"{self.personal_stats['n_training_flows']:,}",
                self.personal_threshold,
            )
        else:
            self.has_personal = False
            logger.warning(
                "⚠️  Personal baseline not found — "
                "run collect_baseline.py + train_personal_model.py to reduce false positives"
            )

    def predict(self, df_features) -> list[dict]:
        """
        Runs hybrid detection on a DataFrame of extracted features.
        Returns a list of dicts, one per row, with keys:
            prediction, attack_type, confidence, severity,
            gate_used, personal_score, cic_confidence, top3
        """
        import pandas as pd

        results: list[dict] = []
        n = len(df_features)

        # ── Prepare feature arrays ─────────────────────────────────────────
        if self.has_personal:
            df_personal = df_features.reindex(
                columns=self.personal_features, fill_value=0
            )
            df_personal = df_personal.apply(pd.to_numeric, errors="coerce").fillna(0)
            X_personal = self.personal_scaler.transform(df_personal)
            personal_scores = self.personal_model.decision_function(X_personal)
        else:
            personal_scores = np.zeros(n)

        if self.has_cic:
            df_cic = df_features.reindex(columns=self.cic_features, fill_value=0)
            df_cic = df_cic.apply(pd.to_numeric, errors="coerce").fillna(0)
            X_cic = self.cic_scaler.transform(df_cic)
            cic_preds = self.cic_classifier.predict(X_cic)
            cic_probas = self.cic_classifier.predict_proba(X_cic)
            cic_classes = self.cic_label_encoder.classes_
        else:
            df_iso = df_features.reindex(columns=self.iso_features, fill_value=0)
            df_iso = df_iso.apply(pd.to_numeric, errors="coerce").fillna(0)
            X_iso = self.iso_scaler.transform(df_iso)
            iso_scores = self.iso_model.decision_function(X_iso)

        # ── Per-row hybrid decision ────────────────────────────────────────
        for i in range(n):
            p_score = float(personal_scores[i]) if self.has_personal else 0.0

            # ── GATE 1: Personal baseline check ───────────────────────────
            if self.has_personal and p_score >= self.personal_threshold:
                # Traffic looks like YOUR normal → mark as normal
                result = {
                    "prediction": "NORMAL",
                    "attack_type": "BENIGN",
                    "confidence": self._personal_normal_confidence(p_score),
                    "severity": "LOW",
                    "gate_used": "personal_baseline",
                    "personal_score": round(p_score, 4),
                    "cic_confidence": 0.0,
                    "top3": [{"type": "BENIGN", "confidence": 99.0}],
                }
                results.append(result)
                continue

            # ── GATE 2: CIC classifier (or fallback IsolationForest) ───────
            if self.has_cic:
                attack_type = self.cic_label_encoder.inverse_transform([cic_preds[i]])[0]
                probas = cic_probas[i]
                confidence = float(probas.max()) * 100.0

                top3_idx = probas.argsort()[::-1][:3]
                top3 = [
                    {
                        "type": cic_classes[j],
                        "confidence": round(float(probas[j]) * 100.0, 1),
                    }
                    for j in top3_idx
                ]

                is_attack = attack_type != "BENIGN"

                if not is_attack:
                    result = {
                        "prediction": "NORMAL",
                        "attack_type": "BENIGN",
                        "confidence": round(confidence, 1),
                        "severity": "LOW",
                        "gate_used": "cic_benign",
                        "personal_score": round(p_score, 4),
                        "cic_confidence": round(confidence, 1),
                        "top3": top3,
                    }
                else:
                    severity = self._get_severity(attack_type, confidence)
                    result = {
                        "prediction": "ATTACK",
                        "attack_type": attack_type,
                        "confidence": round(confidence, 1),
                        "severity": severity,
                        "gate_used": "cic_attack",
                        "personal_score": round(p_score, 4),
                        "cic_confidence": round(confidence, 1),
                        "top3": top3,
                    }
            else:
                # Fallback: raw IsolationForest only
                score = float(iso_scores[i])
                is_anomaly = score < 0
                result = {
                    "prediction": "ATTACK" if is_anomaly else "NORMAL",
                    "attack_type": "Unknown" if is_anomaly else "BENIGN",
                    "confidence": round(
                        max(0.0, min(100.0, (-score + 0.5) * 100.0)), 1
                    ),
                    "severity": "MEDIUM" if is_anomaly else "LOW",
                    "gate_used": "isolation_forest_fallback",
                    "personal_score": round(p_score, 4),
                    "cic_confidence": 0.0,
                    "top3": [],
                }

            results.append(result)

        return results

    def _personal_normal_confidence(self, score: float) -> float:
        """Convert personal model score to a 'normal confidence' percentage."""
        if not self.has_personal:
            return 95.0
        stats = self.personal_stats
        score_range = stats["score_max"] - stats["score_min"]
        if score_range == 0:
            return 95.0
        normalised = (score - stats["score_min"]) / score_range
        return round(min(99.9, max(80.0, normalised * 100.0)), 1)

    def _get_severity(self, attack_type: str, confidence: float) -> str:
        critical = {"DoS", "DDoS", "Botnet", "Heartbleed", "Infiltration"}
        high = {"PortScan", "BruteForce", "WebAttack"}
        if attack_type in critical:
            return "CRITICAL"
        if attack_type in high:
            return "HIGH" if confidence > 70.0 else "MEDIUM"
        return "MEDIUM"

    def is_ready(self) -> dict:
        return {
            "cic_model": self.has_cic,
            "personal_model": self.has_personal,
            "fully_optimised": self.has_cic and self.has_personal,
            "message": (
                "✅ Fully optimised — personal baseline active"
                if self.has_cic and self.has_personal
                else "⚠️ Personal baseline missing — run collect_baseline.py to reduce false positives"
                if self.has_cic
                else "⚠️ CIC model missing — run train_classifier.py"
            ),
        }

