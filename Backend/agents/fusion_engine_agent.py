"""
Fusion Engine Agent
Combines scores from all detection models into a single weighted threat score,
assigns severity, and flags when the response engine should be triggered.
"""
import logging
from dataclasses import dataclass, field, asdict
from typing import Optional

logger = logging.getLogger(__name__)

_SEVERITY_LABELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


@dataclass
class FusionResult:
    threat_score: float                          # 0.0 – 1.0
    severity: str                                # LOW | MEDIUM | HIGH | CRITICAL
    should_respond: bool                         # True when score ≥ high_threshold
    endpoint_id: str = ""                        # originating endpoint; "" means global/unknown
    attack_type: str = "Unknown"                 # attack classification label
    confidence: float = 0.0                      # alias for threat_score — convenience for callers
    components: dict = field(default_factory=dict)
    contributing_models: list[str] = field(default_factory=list)
    contributing_reasons: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class FusionEngineAgent:
    """
    Weighted linear fusion:
        threat_score = Σ (weight_i * score_i)  for all active models

    Weights must sum to 1.0.  Models not yet implemented (system, malware)
    default to score=0.0 and are excluded from contributing_models.
    """

    def __init__(
        self,
        weights: Optional[dict] = None,
        high_threshold: float = 0.70,
        critical_threshold: float = 0.85,
    ):
        self.weights = weights or {
            "network": 0.35,
            "user":    0.30,
            "system":  0.15,
            "malware": 0.20,
        }
        self.high_threshold = high_threshold
        self.critical_threshold = critical_threshold
        self._validate_weights()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def fuse(
        self,
        network_score: float = 0.0,
        user_score: float = 0.0,
        system_score: float = 0.0,
        malware_score: float = 0.0,
        endpoint_id: str = "",
    ) -> FusionResult:
        """
        All scores are expected in [0.0, 1.0].
        A score of 0.0 means the model found nothing anomalous (or isn't implemented).

        Scoring pipeline:
            Step 1 — Weighted base score (clamped)
            Step 2 — Corroboration bonus when 2+ models exceed 0.30
            Step 3 — Escalation hard-overrides for high-confidence signal combinations
            Step 4 — Corroboration reason string recorded
            Step 5 — Final clamp to [0, 1]
        """
        scores = {
            "network": self._clamp(network_score),
            "user":    self._clamp(user_score),
            "system":  self._clamp(system_score),
            "malware": self._clamp(malware_score),
        }

        # Step 1 — weighted base score
        base = self._clamp(sum(self.weights[k] * scores[k] for k in scores))

        reasons: list[str] = []

        # Step 2 — corroboration bonus
        active_count = sum(1 for v in scores.values() if v > 0.30)
        if active_count >= 3:
            base = min(1.0, base * 1.20)
        elif active_count >= 2:
            base = min(1.0, base * 1.10)

        # Step 3 — escalation hard-overrides
        threat_score = base

        # Rule A: confirmed malware
        if scores["malware"] >= 0.85:
            threat_score = max(threat_score, 0.93)
            reasons.append(
                f"Confirmed malware detection (score={scores['malware']:.2f}) "
                "— CRITICAL escalation"
            )

        # Rule B: synchronized network attack + system impact
        if scores["network"] >= 0.80 and scores["system"] >= 0.50:
            threat_score = max(threat_score, 0.82)
            reasons.append(
                "Synchronized network attack + system impact — HIGH escalation"
            )

        # Rule C: critical insider threat
        if scores["user"] >= 0.80:
            threat_score = max(threat_score, 0.75)
            reasons.append(
                f"Critical insider threat indicator (score={scores['user']:.2f})"
            )

        # Rule D: malware + network correlation
        if scores["malware"] >= 0.60 and scores["network"] >= 0.50:
            threat_score = max(threat_score, 0.75)
            reasons.append(
                "Malware + network activity correlation — HIGH escalation"
            )

        # Step 4 — corroboration reason
        if active_count >= 3:
            reasons.append(
                f"{active_count} detection models corroborating "
                "— confidence boost +20%"
            )
        elif active_count >= 2:
            reasons.append(
                f"{active_count} detection models corroborating "
                "— confidence boost +10%"
            )

        # Step 5 — final clamp
        threat_score = self._clamp(threat_score)

        contributing = [k for k, v in scores.items() if v > 0.0]
        severity = self._score_to_severity(threat_score)
        should_respond = threat_score >= self.high_threshold

        rounded_score = round(threat_score, 4)
        return FusionResult(
            threat_score=rounded_score,
            severity=severity,
            should_respond=should_respond,
            endpoint_id=endpoint_id,
            attack_type="Unknown",
            confidence=rounded_score,
            components={
                k: {
                    "score": scores[k],
                    "weight": self.weights[k],
                    "contribution": round(self.weights[k] * scores[k], 4),
                }
                for k in scores
            },
            contributing_models=contributing,
            contributing_reasons=reasons,
        )

    def fuse_from_network_result(
        self,
        network_result: dict,
        endpoint_id: str = "",
    ) -> FusionResult:
        """
        Convenience wrapper: extract a normalised network score from a
        NetworkDetectionAgent result dict (confidence is 0-100).
        """
        score = 0.0
        ml_results = network_result.get("ml_results", [])
        if ml_results:
            # Use the highest confidence attack score from ML results
            attack_confidences = [
                r.get("confidence", 0) / 100.0
                for r in ml_results
                if r.get("prediction") == "ATTACK"
            ]
            if attack_confidences:
                score = max(attack_confidences)

        rule_hits = network_result.get("rule_hits", [])
        if rule_hits:
            # Rule hits are high-confidence; map severity to score
            severity_scores = {"LOW": 0.55, "MEDIUM": 0.70, "HIGH": 0.85, "CRITICAL": 0.95}
            rule_score = max(
                severity_scores.get(h.get("severity", "LOW"), 0.55) for h in rule_hits
            )
            score = max(score, rule_score)

        return self.fuse(network_score=score, endpoint_id=endpoint_id)

    def update_weights(self, weights: dict):
        self.weights.update(weights)
        self._validate_weights()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_to_severity(self, score: float) -> str:
        if score >= self.critical_threshold:
            return "CRITICAL"
        if score >= self.high_threshold:
            return "HIGH"
        if score >= 0.35:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _clamp(value: float) -> float:
        return max(0.0, min(1.0, float(value)))

    def _validate_weights(self):
        total = sum(self.weights.values())
        if abs(total - 1.0) > 0.01:
            logger.warning(
                f"Fusion weights sum to {total:.3f} (expected 1.0). "
                "Threat scores will be scaled accordingly."
            )
