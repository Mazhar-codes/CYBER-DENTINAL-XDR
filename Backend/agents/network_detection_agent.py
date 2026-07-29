"""
Network Detection Agent
Orchestrates Stage 1 (RuleDetector) and Stage 2 (HybridDetector) in a single call.
"""
import sys
import logging
from dataclasses import asdict
from pathlib import Path
from typing import Optional

import pandas as pd

sys.path.insert(0, str(Path(__file__).parent.parent))
from rule_detector import RuleDetector, RuleHit, FlowSummary
from hybrid_detector import HybridDetector

logger = logging.getLogger(__name__)


def _parse_addr(addr: str, fallback_ip: str = "0.0.0.0") -> tuple[str, int]:
    """
    Parse a psutil address string into (ip, port).

    Handles all three forms produced by psutil:
      - IPv4  "192.168.1.5:52341"
      - IPv6  "[::1]:8080"   or  "::1:8080"  (latter is non-standard but observed)
      - bare  "" or "0.0.0.0:0"

    Returns (fallback_ip, 0) when the string is empty or unparseable.
    """
    addr = addr.strip()
    if not addr:
        return fallback_ip, 0
    try:
        # IPv6 bracketed form: "[::1]:port"
        if addr.startswith("["):
            bracket_end = addr.index("]")
            ip = addr[1:bracket_end]
            port_part = addr[bracket_end + 1:]          # ":port" or ""
            port = int(port_part.lstrip(":")) if port_part.lstrip(":") else 0
            return ip, port
        # IPv4 form: "a.b.c.d:port"
        if addr.count(":") == 1:
            ip, port_str = addr.rsplit(":", 1)
            return ip or fallback_ip, int(port_str)
        # Bare IPv6 without brackets — treat everything as IP, port = 0
        return addr, 0
    except (ValueError, IndexError):
        return fallback_ip, 0


class NetworkDetectionAgent:
    """
    Wraps the 3-stage network detection pipeline:
      Stage 1 — Rule-based detection (instant, deterministic)
      Stage 2 — Gate 1: Personal IsolationForest baseline
              — Gate 2: CIC-IDS2017 RandomForest classifier
    """

    def __init__(self, model_dir: str, eve_path: str):
        self.eve_path = eve_path
        self.rule_detector = RuleDetector()
        self.hybrid_detector = HybridDetector(model_dir)
        self._cic_features: Optional[list] = None
        self._personal_features: Optional[list] = None
        self._load_feature_lists()

    def _load_feature_lists(self):
        try:
            import joblib
            features_path = Path(self.hybrid_detector.base_dir) / "network_features.pkl"
            if features_path.exists():
                self._cic_features = joblib.load(features_path)
        except Exception as e:
            logger.warning(f"Could not load CIC feature list: {e}")

        try:
            if hasattr(self.hybrid_detector, "personal_features"):
                self._personal_features = self.hybrid_detector.personal_features
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def detect(self) -> dict:
        """Read the configured Suricata eve.json and run both stages."""
        return self._run_pipeline(self.eve_path)

    def detect_from_eve(self, eve_path: str) -> dict:
        """Run detection on an arbitrary eve.json file."""
        return self._run_pipeline(eve_path)

    def detect_from_flows(self, flows: list[dict]) -> dict:
        """
        Run Stage 2 ML detection on pre-extracted flow dicts (from /ingest).
        Skips the rule detector since raw rule inputs come from eve.json, not flow dicts.
        """
        if not flows:
            return {"rule_hits": [], "ml_results": [], "clean_flow_count": 0}
        df = self._dicts_to_features(flows)
        ml_results = self._run_hybrid(df, original_dicts=flows)
        return {"rule_hits": [], "ml_results": ml_results, "clean_flow_count": len(flows)}

    def detect_from_endpoint_network(
        self, network_data: dict, hostname: str = ""
    ) -> dict:
        """
        Route psutil endpoint network telemetry through the full RandomForest
        classifier pipeline and return a scalar network_score.

        Parameters
        ----------
        network_data : dict
            Payload from the endpoint agent's network_collector, containing:
              - connections   : list of {laddr, raddr, status, pid} dicts
              - bytes_sent    : aggregate bytes sent since last poll
              - bytes_recv    : aggregate bytes received since last poll
              - packets_sent  : aggregate packets sent
              - packets_recv  : aggregate packets received
              - suspicious_ports : list[int] (informational, not used here)
        hostname : str
            Endpoint hostname — used only for debug logging.

        Returns
        -------
        dict with keys:
          network_score  float  0.0–1.0 (max attack confidence across all flows)
          rule_hits      list   always [] (rule engine needs eve.json)
          ml_results     list   per-flow HybridDetector output
          flow_count     int    number of synthetic flows analysed
        """
        connections = network_data.get("connections", [])
        bytes_sent = float(network_data.get("bytes_sent", 0))
        bytes_recv = float(network_data.get("bytes_recv", 0))
        packets_sent = float(network_data.get("packets_sent", 0))
        packets_recv = float(network_data.get("packets_recv", 0))

        # ── Step 1: filter to active connections only ──────────────────────
        active_conns = []
        for conn in connections:
            try:
                raddr = str(conn.get("raddr", "")).strip()
                if not raddr:
                    continue
                status = str(conn.get("status", "")).upper()
                # Skip purely local listening sockets with no peer
                if status in ("LISTEN", "TIME_WAIT") and not raddr:
                    continue
                active_conns.append(conn)
            except Exception:
                continue  # malformed entry — skip silently

        if not active_conns:
            return {
                "network_score": 0.0,
                "rule_hits": [],
                "ml_results": [],
                "flow_count": 0,
            }

        # Cap at 50 flows to bound processing time
        active_conns = active_conns[:50]
        n = len(active_conns)

        # Distribute aggregate totals evenly across all active connections
        bytes_sent_per = bytes_sent / n
        bytes_recv_per = bytes_recv / n
        pkts_sent_per = packets_sent / n
        pkts_recv_per = packets_recv / n

        # ── Step 2: build synthetic flow dicts ────────────────────────────
        flow_dicts = []
        for conn in active_conns:
            try:
                laddr_raw = str(conn.get("laddr", "")).strip()
                raddr_raw = str(conn.get("raddr", "")).strip()
                status = str(conn.get("status", "")).upper()

                src_ip, _src_port = _parse_addr(laddr_raw, fallback_ip=hostname or "127.0.0.1")
                dest_ip, dest_port = _parse_addr(raddr_raw, fallback_ip="0.0.0.0")

                flow_dicts.append({
                    "src_ip": src_ip,
                    "dest_ip": dest_ip,
                    "dest_port": dest_port,
                    "bytes_sent": bytes_sent_per,
                    "bytes_received": bytes_recv_per,
                    "packets_sent": pkts_sent_per,
                    "packets_received": pkts_recv_per,
                    "duration": 5.0,   # psutil poll interval — conservative estimate
                    "syn_flag": 1 if status == "SYN_SENT" else 0,
                    "fin_flag": 1 if status in (
                        "CLOSE_WAIT", "TIME_WAIT", "FIN_WAIT1", "FIN_WAIT2"
                    ) else 0,
                    "rst_flag": 0,
                    "ack_flag": 1 if status == "ESTABLISHED" else 0,
                })
            except Exception:
                continue  # malformed entry — skip silently

        if not flow_dicts:
            return {
                "network_score": 0.0,
                "rule_hits": [],
                "ml_results": [],
                "flow_count": 0,
            }

        # ── Step 3: run full HybridDetector pipeline ──────────────────────
        result = self.detect_from_flows(flow_dicts)

        # ── Step 4: compute scalar network_score from ML results ──────────
        ml_results = result.get("ml_results", [])
        attack_scores = []
        for r in ml_results:
            if r.get("prediction") == "ATTACK":
                # confidence is 0–100; normalise to 0–1
                attack_scores.append(r.get("confidence", 50.0) / 100.0)

        if attack_scores:
            network_score = max(attack_scores)
        elif ml_results:
            network_score = 0.05  # flows analysed, all benign
        else:
            network_score = 0.0   # no ML output (model not loaded)

        # ── Step 5: annotate and return ───────────────────────────────────
        result["network_score"] = round(network_score, 4)
        result["flow_count"] = len(flow_dicts)
        logger.debug(
            "[endpoint_network] hostname=%s flows=%d network_score=%.4f",
            hostname,
            len(flow_dicts),
            network_score,
        )
        return result

    def is_ready(self) -> dict:
        return {
            "rule_detector": True,
            "hybrid_detector": self.hybrid_detector.is_ready(),
        }

    # ------------------------------------------------------------------
    # Internal pipeline
    # ------------------------------------------------------------------

    def _run_pipeline(self, eve_path: str) -> dict:
        try:
            rule_hits, clean_flows = self.rule_detector.analyse(eve_path)
        except FileNotFoundError:
            logger.warning(f"eve.json not found at {eve_path}")
            return {"rule_hits": [], "ml_results": [], "clean_flow_count": 0}
        except Exception as e:
            logger.error(f"Rule detector error: {e}")
            return {"rule_hits": [], "ml_results": [], "clean_flow_count": 0}

        ml_results = []
        if clean_flows:
            df = self._flows_to_features(clean_flows)
            ml_results = self._run_hybrid(df, original_flows=clean_flows)

        return {
            "rule_hits": [self._rule_hit_to_dict(h) for h in rule_hits],
            "ml_results": ml_results,
            "clean_flow_count": len(clean_flows),
        }

    def _run_hybrid(
        self,
        df: pd.DataFrame,
        original_flows: Optional[list] = None,
        original_dicts: Optional[list] = None,
    ) -> list[dict]:
        try:
            predictions = self.hybrid_detector.predict(df)
        except Exception as e:
            logger.error(f"HybridDetector error: {e}")
            return []

        results = []
        for i, pred in enumerate(predictions):
            base = {}
            if original_flows and i < len(original_flows):
                f = original_flows[i]
                base = {
                    "source_ip": f.src_ip,
                    "destination_ip": f.dest_ip,
                    "destination_port": f.dest_port,
                    "source_port": f.src_port,
                    "proto": f.proto,
                    "ts": str(f.ts),
                    "bytes_sent": f.bytes_fwd,
                    "bytes_received": f.bytes_bwd,
                    "packets_sent": f.pkts_fwd,
                    "packets_received": f.pkts_bwd,
                    "connection_duration": f.duration,
                    "features": {
                        col: float(df.iloc[i][col])
                        for col in (self._cic_features or [])
                        if col in df.columns
                    },
                }
            elif original_dicts and i < len(original_dicts):
                base = original_dicts[i]
                base["features"] = {
                    col: float(df.iloc[i][col])
                    for col in (self._cic_features or [])
                    if col in df.columns
                }
            results.append({**base, **pred})
        return results

    # ------------------------------------------------------------------
    # Feature conversion
    # ------------------------------------------------------------------

    def _flows_to_features(self, flows: list[FlowSummary]) -> pd.DataFrame:
        """Convert FlowSummary objects → CIC-feature DataFrame."""
        all_features = set(self._cic_features or [])
        if self._personal_features:
            all_features.update(self._personal_features)

        rows = []
        for f in flows:
            row = {feat: 0.0 for feat in all_features}
            duration = max(f.duration, 1.0)
            total_pkts = max(f.pkts_fwd + f.pkts_bwd, 1)
            total_bytes = f.bytes_fwd + f.bytes_bwd

            # Per-direction mean packet lengths — used in approximations below
            fwd_pkt_len_mean = f.bytes_fwd / max(f.pkts_fwd, 1)
            bwd_pkt_len_mean = f.bytes_bwd / max(f.pkts_bwd, 1)
            pkt_len_mean = total_bytes / total_pkts

            # ── Statistical approximations for features unavailable from eve.json ──
            #
            # Suricata only provides aggregate byte/packet counts and flow age.
            # The CIC-IDS2017 variance/IAT features are approximated with
            # coefficient-of-variation heuristics (CV ≈ 0.5 for typical TCP flows):
            #   std  ≈ mean * 0.5
            #   min  ≈ mean * 0.1  (floor at 40 B — IP+TCP header minimum)
            #
            # These are biased estimates that keep the features in a plausible
            # distribution range.  Using hard zeros would distort the scaler
            # and reduce classifier sensitivity to slow-rate / low-variance attacks.

            fwd_pkt_len_std = fwd_pkt_len_mean * 0.5
            fwd_pkt_len_min = max(40.0, fwd_pkt_len_mean * 0.1)

            bwd_pkt_len_std = bwd_pkt_len_mean * 0.5
            bwd_pkt_len_min = max(40.0, bwd_pkt_len_mean * 0.1)

            pkt_len_std = pkt_len_mean * 0.5
            pkt_len_var = pkt_len_std ** 2                    # variance = std^2
            min_pkt_len = min(fwd_pkt_len_min, bwd_pkt_len_min)

            flow_iat_mean_us = duration / max(f.pkts_fwd + f.pkts_bwd, 1) * 1_000_000
            flow_iat_std = flow_iat_mean_us * 0.5
            flow_iat_min = flow_iat_mean_us * 0.1             # burst floor

            fwd_iat_mean_us = duration / max(f.pkts_fwd, 1) * 1_000_000
            fwd_iat_std = fwd_iat_mean_us * 0.5

            bwd_iat_mean_us = duration / max(f.pkts_bwd, 1) * 1_000_000
            bwd_iat_std = bwd_iat_mean_us * 0.5

            active_mean_us = duration * 1_000_000
            active_std = active_mean_us * 0.1                 # single contiguous window

            available = {
                "Destination Port": float(f.dest_port),
                "Flow Duration": f.duration * 1_000_000,
                "Total Fwd Packets": float(f.pkts_fwd),
                "Total Backward Packets": float(f.pkts_bwd),
                "Total Length of Fwd Packets": float(f.bytes_fwd),
                "Total Length of Bwd Packets": float(f.bytes_bwd),
                "Fwd Packet Length Max": fwd_pkt_len_mean,
                "Fwd Packet Length Min": fwd_pkt_len_min,
                "Fwd Packet Length Mean": fwd_pkt_len_mean,
                "Fwd Packet Length Std": fwd_pkt_len_std,
                "Bwd Packet Length Max": bwd_pkt_len_mean,
                "Bwd Packet Length Min": bwd_pkt_len_min,
                "Bwd Packet Length Mean": bwd_pkt_len_mean,
                "Bwd Packet Length Std": bwd_pkt_len_std,
                "Flow Bytes/s": total_bytes / duration,
                "Flow Packets/s": total_pkts / duration,
                "Flow IAT Mean": flow_iat_mean_us,
                "Flow IAT Std": flow_iat_std,
                "Flow IAT Max": duration * 1_000_000,
                "Flow IAT Min": flow_iat_min,
                "Fwd IAT Total": duration * 1_000_000,
                "Fwd IAT Mean": fwd_iat_mean_us,
                "Fwd IAT Std": fwd_iat_std,
                "Bwd IAT Total": duration * 1_000_000,
                "Bwd IAT Mean": bwd_iat_mean_us,
                "Bwd IAT Std": bwd_iat_std,
                "Fwd Packets/s": f.pkts_fwd / duration,
                "Bwd Packets/s": f.pkts_bwd / duration,
                "FIN Flag Count": float(int(f.fin_flag)),
                "SYN Flag Count": float(int(f.syn_flag)),
                "RST Flag Count": float(int(f.rst_flag)),
                "ACK Flag Count": float(int(f.ack_flag)),
                "Down/Up Ratio": f.bytes_bwd / max(f.bytes_fwd, 1),
                "Average Packet Size": pkt_len_mean,
                "Avg Fwd Segment Size": fwd_pkt_len_mean,
                "Avg Bwd Segment Size": bwd_pkt_len_mean,
                "Min Packet Length": min_pkt_len,
                "Max Packet Length": pkt_len_mean,
                "Packet Length Mean": pkt_len_mean,
                "Packet Length Std": pkt_len_std,
                "Packet Length Variance": pkt_len_var,
                "Subflow Fwd Packets": float(f.pkts_fwd),
                "Subflow Fwd Bytes": float(f.bytes_fwd),
                "Subflow Bwd Packets": float(f.pkts_bwd),
                "Subflow Bwd Bytes": float(f.bytes_bwd),
                "Active Mean": active_mean_us,
                "Active Std": active_std,
                "Active Max": active_mean_us,
                "Active Min": active_mean_us,
            }
            for feat, val in available.items():
                if feat in row:
                    row[feat] = val

            # Metadata columns (not used by ML, used for event enrichment)
            row["_src_ip"] = f.src_ip
            row["_dest_ip"] = f.dest_ip
            row["_dest_port"] = f.dest_port
            row["_proto"] = f.proto
            row["_ts"] = str(f.ts)
            rows.append(row)

        return pd.DataFrame(rows)

    def _dicts_to_features(self, flows: list[dict]) -> pd.DataFrame:
        """Convert raw flow dicts from /ingest → CIC-feature DataFrame."""
        all_features = set(self._cic_features or [])
        if self._personal_features:
            all_features.update(self._personal_features)

        rows = []
        for f in flows:
            row = {feat: 0.0 for feat in all_features}
            duration = max(float(f.get("duration", 1.0)), 1.0)
            pkts_fwd = float(f.get("pkts_fwd", f.get("packets_sent", 0)))
            pkts_bwd = float(f.get("pkts_bwd", f.get("packets_received", 0)))
            bytes_fwd = float(f.get("bytes_fwd", f.get("bytes_sent", 0)))
            bytes_bwd = float(f.get("bytes_bwd", f.get("bytes_received", 0)))
            total_pkts = max(pkts_fwd + pkts_bwd, 1)
            total_bytes = bytes_fwd + bytes_bwd

            # Per-direction mean packet lengths — used in approximations below
            fwd_pkt_len_mean = bytes_fwd / max(pkts_fwd, 1)
            bwd_pkt_len_mean = bytes_bwd / max(pkts_bwd, 1)
            pkt_len_mean = total_bytes / total_pkts

            # ── Statistical approximations for features unavailable from /ingest ──
            # Callers provide only aggregate byte/packet counts, not per-packet data.
            # Same CV=0.5 heuristic as collect_baseline.py / _flows_to_features().
            fwd_pkt_len_std = fwd_pkt_len_mean * 0.5
            fwd_pkt_len_min = max(40.0, fwd_pkt_len_mean * 0.1)

            bwd_pkt_len_std = bwd_pkt_len_mean * 0.5
            bwd_pkt_len_min = max(40.0, bwd_pkt_len_mean * 0.1)

            pkt_len_std = pkt_len_mean * 0.5
            pkt_len_var = pkt_len_std ** 2
            min_pkt_len = min(fwd_pkt_len_min, bwd_pkt_len_min)

            flow_iat_mean_us = duration / total_pkts * 1_000_000
            flow_iat_std = flow_iat_mean_us * 0.5
            flow_iat_min = flow_iat_mean_us * 0.1

            fwd_iat_mean_us = duration / max(pkts_fwd, 1) * 1_000_000
            fwd_iat_std = fwd_iat_mean_us * 0.5

            bwd_iat_mean_us = duration / max(pkts_bwd, 1) * 1_000_000
            bwd_iat_std = bwd_iat_mean_us * 0.5

            active_mean_us = duration * 1_000_000
            active_std = active_mean_us * 0.1

            available = {
                "Destination Port": float(f.get("dest_port", f.get("destination_port", 0))),
                "Flow Duration": duration * 1_000_000,
                "Total Fwd Packets": pkts_fwd,
                "Total Backward Packets": pkts_bwd,
                "Total Length of Fwd Packets": bytes_fwd,
                "Total Length of Bwd Packets": bytes_bwd,
                "Fwd Packet Length Max": fwd_pkt_len_mean,
                "Fwd Packet Length Min": fwd_pkt_len_min,
                "Fwd Packet Length Mean": fwd_pkt_len_mean,
                "Fwd Packet Length Std": fwd_pkt_len_std,
                "Bwd Packet Length Max": bwd_pkt_len_mean,
                "Bwd Packet Length Min": bwd_pkt_len_min,
                "Bwd Packet Length Mean": bwd_pkt_len_mean,
                "Bwd Packet Length Std": bwd_pkt_len_std,
                "Flow Bytes/s": total_bytes / duration,
                "Flow Packets/s": total_pkts / duration,
                "Flow IAT Mean": flow_iat_mean_us,
                "Flow IAT Std": flow_iat_std,
                "Flow IAT Max": duration * 1_000_000,
                "Flow IAT Min": flow_iat_min,
                "Fwd IAT Total": duration * 1_000_000,
                "Fwd IAT Mean": fwd_iat_mean_us,
                "Fwd IAT Std": fwd_iat_std,
                "Bwd IAT Total": duration * 1_000_000,
                "Bwd IAT Mean": bwd_iat_mean_us,
                "Bwd IAT Std": bwd_iat_std,
                "Fwd Packets/s": pkts_fwd / duration,
                "Bwd Packets/s": pkts_bwd / duration,
                "FIN Flag Count": float(f.get("fin_flag", 0)),
                "SYN Flag Count": float(f.get("syn_flag", 0)),
                "RST Flag Count": float(f.get("rst_flag", 0)),
                "ACK Flag Count": float(f.get("ack_flag", 0)),
                "Down/Up Ratio": bytes_bwd / max(bytes_fwd, 1),
                "Average Packet Size": pkt_len_mean,
                "Avg Fwd Segment Size": fwd_pkt_len_mean,
                "Avg Bwd Segment Size": bwd_pkt_len_mean,
                "Min Packet Length": min_pkt_len,
                "Max Packet Length": pkt_len_mean,
                "Packet Length Mean": pkt_len_mean,
                "Packet Length Std": pkt_len_std,
                "Packet Length Variance": pkt_len_var,
                "Subflow Fwd Packets": pkts_fwd,
                "Subflow Fwd Bytes": bytes_fwd,
                "Subflow Bwd Packets": pkts_bwd,
                "Subflow Bwd Bytes": bytes_bwd,
                "Active Mean": active_mean_us,
                "Active Std": active_std,
                "Active Max": active_mean_us,
                "Active Min": active_mean_us,
            }
            for feat, val in available.items():
                if feat in row:
                    row[feat] = val

            row["_src_ip"] = f.get("src_ip", f.get("source_ip", ""))
            row["_dest_ip"] = f.get("dest_ip", f.get("destination_ip", ""))
            rows.append(row)

        return pd.DataFrame(rows)

    @staticmethod
    def _rule_hit_to_dict(hit: RuleHit) -> dict:
        try:
            return {
                "rule_name": hit.rule_name,
                "attack_type": hit.attack_type,
                "severity": hit.severity,
                "color": hit.color,
                "icon": hit.icon,
                "description": hit.description,
                "evidence": hit.evidence,
                "source_ip": hit.src_ip,
                "destination_ip": hit.dest_ip,
                "destination_port": hit.dest_port,
                "confidence": hit.confidence,
                "bytes_sent": hit.total_bytes_sent,
                "bytes_received": hit.total_bytes_recv,
                "total_packets": hit.total_pkts,
                "duration": hit.duration,
                "flow_count": hit.flow_count,
                "proto": hit.proto,
                "ts": str(hit.ts),
                "source": "rule_engine",
                "prediction": "ATTACK",
            }
        except AttributeError:
            # Fallback if RuleHit fields differ from expected
            return vars(hit) if hasattr(hit, "__dict__") else {}
