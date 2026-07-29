"""
Attack Graph Engine — persistent, event-driven graph builder.
Translates XDR telemetry events into a queryable entity-relationship graph
with correct attacker-direction edges, MITRE ATT&CK technique annotations,
and correlated incident grouping.
"""
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# MITRE ATT&CK technique lookup
# ---------------------------------------------------------------------------
_MITRE_MAP: dict[str, tuple[str, str]] = {
    "PortScan":                  ("T1046", "Discovery"),
    "PORT_SCAN_HORIZONTAL":      ("T1046", "Discovery"),
    "HOST_SWEEP":                ("T1046", "Discovery"),
    "DDoS":                      ("T1498", "Impact"),
    "SYN_FLOOD":                 ("T1498", "Impact"),
    "BruteForce":                ("T1110", "Credential Access"),
    "C2 Beaconing":              ("T1071", "Command and Control"),
    "Ransomware Activity":       ("T1486", "Impact"),
    "Ransomware Behavior":       ("T1486", "Impact"),
    "Lateral Movement":          ("T1021", "Lateral Movement"),
    "Privilege Escalation":      ("T1068", "Privilege Escalation"),
    "Insider Threat":            ("T1078", "Defense Evasion"),
    "Malware Activity":          ("T1204", "Execution"),
    "Data Exfiltration":         ("T1041", "Exfiltration"),
    "Infiltration":              ("T1190", "Initial Access"),
    "DoS":                       ("T1499", "Impact"),
    "Botnet":                    ("T1583", "Resource Development"),
    "WebAttack":                 ("T1190", "Initial Access"),
    "Heartbleed":                ("T1499", "Impact"),
    "Network Anomaly":           ("T1040", "Discovery"),
    "System Anomaly":            ("T1053", "Execution"),
    "User Anomaly":              ("T1078", "Defense Evasion"),
    "Sysmon Alert":              ("T1059", "Execution"),
}


def _mitre_for(attack_type: str) -> tuple[str, str]:
    """Return (technique_id, tactic) for any attack type. Falls back gracefully."""
    for key, val in _MITRE_MAP.items():
        if key.lower() in attack_type.lower():
            return val
    return ("T1059", "Execution")


# ---------------------------------------------------------------------------
# Attacks where an external IP IS the attacker (inbound direction)
# For these attack types the correct edge direction is ip → endpoint.
# ---------------------------------------------------------------------------
_INBOUND_ATTACKS = {
    "PortScan", "PORT_SCAN_HORIZONTAL", "HOST_SWEEP",
    "DDoS", "SYN_FLOOD",
    "BruteForce", "Infiltration", "Heartbleed",
    "WebAttack", "C2 Beaconing", "Botnet",
}

_VALID_NODE_TYPES = {
    "endpoint", "user", "process", "file", "ip", "threat_actor",
    "domain", "alert", "response_action", "technique",
}
_VALID_RELATIONS = {
    "spawned", "connected_to", "modified", "authenticated_as",
    "triggered_alert", "responded_by", "detected_on",
}

# How far back we look for an existing open incident before creating a new one.
_INCIDENT_CORRELATION_WINDOW_S = 1800  # 30 minutes


class AttackGraphEngine:
    def __init__(self, db):
        self._db = db
        # Monotonically incrementing counter used to stamp every new edge with
        # a chain_seq value.  The replay scrubber filters edges by
        # ``edge.chain_seq <= replayStep`` so this must be persisted on the
        # engine instance (not derived from the DB) to guarantee strict ordering
        # within a single server session.  On restart the counter seeds itself
        # from the highest chain_seq already stored in MongoDB so replay of
        # historical edges continues to work correctly.
        self._chain_seq: int = self._load_max_chain_seq()

    def _load_max_chain_seq(self) -> int:
        """
        Seed the in-process counter from the maximum chain_seq already stored
        in MongoDB.  Falls back to 0 when the DB is unavailable or the
        collection is empty.
        """
        if self._db is None:
            return 0
        try:
            doc = self._db["attack_graph_edges"].find_one(
                {}, {"chain_seq": 1}, sort=[("chain_seq", -1)]
            )
            if doc and isinstance(doc.get("chain_seq"), int):
                return doc["chain_seq"]
        except Exception:
            pass
        return 0

    def _next_chain_seq(self) -> int:
        """Increment and return the next chain_seq value (thread-safe-enough for
        single-process use — no cross-process coordination required)."""
        self._chain_seq += 1
        return self._chain_seq

    # ── Core upsert helpers ──────────────────────────────────────────────────

    def upsert_node(self, node_id: str, node_type: str, label: str,
                    endpoint_id: str = "", risk_score: float = 0.0,
                    severity: str = "LOW", metadata: dict = None) -> dict:
        """
        Insert or update a graph node. Returns the upserted doc.
        Risk score is always escalated (never decreased by an upsert).
        Severity is escalated using LOW < MEDIUM < HIGH < CRITICAL order.
        New fields mitre_technique, source_layer, and confidence are stored
        from metadata when present.
        """
        if self._db is None:
            return {}
        now = datetime.now(timezone.utc)
        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
        meta = metadata or {}

        existing = self._db["attack_graph_nodes"].find_one({"node_id": node_id})
        if existing:
            # Escalate risk and severity only
            new_risk = max(existing.get("risk_score", 0), risk_score)
            cur_sev = existing.get("severity", "LOW")
            new_sev = severity if sev_order.get(severity, 0) > sev_order.get(cur_sev, 0) else cur_sev
            # Merge metadata (incoming values override)
            merged_meta = {**existing.get("metadata", {}), **meta}
            update_fields: dict = {
                "risk_score": new_risk,
                "severity": new_sev,
                "metadata": merged_meta,
                "last_updated": now,
                "label": label,  # always refresh label
            }
            # Promote top-level annotation fields when provided via metadata
            if meta.get("mitre_technique"):
                update_fields["mitre_technique"] = meta["mitre_technique"]
            if meta.get("source_layer"):
                update_fields["source_layer"] = meta["source_layer"]
            self._db["attack_graph_nodes"].update_one(
                {"node_id": node_id},
                {"$set": update_fields},
            )
            existing.update(update_fields)
            return existing
        else:
            doc = {
                "node_id":         node_id,
                "type":            node_type,
                "label":           label,
                "endpoint_id":     endpoint_id,
                "risk_score":      risk_score,
                "severity":        severity,
                "metadata":        meta,
                "mitre_technique": meta.get("mitre_technique", ""),
                "source_layer":    meta.get("source_layer", ""),
                "confidence":      meta.get("confidence", 0.0),
                "timestamp":       now,
                "last_updated":    now,
            }
            self._db["attack_graph_nodes"].insert_one(doc)
            return doc

    def upsert_edge(self, source_id: str, target_id: str, relation: str,
                    endpoint_id: str = "", metadata: dict = None) -> dict:
        """
        Insert or update a graph edge.
        Edge ID is deterministic from (source, target, relation).
        New fields mitre_technique, confidence, correlation_score, attack_type,
        and label are stored from metadata when present.
        """
        if self._db is None:
            return {}
        edge_id = hashlib.sha256(f"{source_id}→{target_id}:{relation}".encode()).hexdigest()[:16]
        now = datetime.now(timezone.utc)
        meta = metadata or {}
        existing = self._db["attack_graph_edges"].find_one({"edge_id": edge_id})
        if existing:
            merged_meta = {**existing.get("metadata", {}), **meta}
            update_fields: dict = {
                "last_updated": now,
                "metadata": merged_meta,
            }
            # Promote annotation fields on update
            for field in ("mitre_technique", "attack_type", "label", "confidence", "correlation_score"):
                if meta.get(field) is not None:
                    update_fields[field] = meta[field]
            self._db["attack_graph_edges"].update_one(
                {"edge_id": edge_id},
                {"$set": update_fields},
            )
            return existing
        chain = self._next_chain_seq()
        doc = {
            "edge_id":           edge_id,
            "source":            source_id,
            "target":            target_id,
            "relation":          relation,
            "endpoint_id":       endpoint_id,
            "metadata":          meta,
            "mitre_technique":   meta.get("mitre_technique", ""),
            "attack_type":       meta.get("attack_type", relation),
            "label":             meta.get("label", relation),
            "confidence":        meta.get("confidence", 0.0),
            "correlation_score": meta.get("correlation_score", 0.0),
            "timestamp":         now,
            "last_updated":      now,
            "chain_seq":         chain,
        }
        self._db["attack_graph_edges"].insert_one(doc)
        return doc

    # ── Event processors ─────────────────────────────────────────────────────

    def process_network_anomaly(self, event: dict) -> tuple:
        """
        Build graph nodes and edges for a network anomaly event.

        Attacker direction is corrected:
          - Inbound attacks (PortScan, DDoS, BruteForce, …): external IP IS the
            threat actor; edge goes threat_actor → endpoint.
          - Outbound activity (C2 exfil leaving the network): endpoint → ip.

        Returns (new_or_updated_nodes, new_or_updated_edges).
        """
        nodes, edges = [], []
        ep_id    = event.get("endpoint_id", "server")
        src_ip   = event.get("source_ip", event.get("src_ip", ""))
        dst_ip   = event.get("destination_ip", "")
        severity = event.get("severity", "LOW")
        score    = float(event.get("threat_score", event.get("score", 0.5))) * 100
        attack   = event.get("attack_type", "Network Anomaly")
        hostname = event.get("hostname", ep_id)
        confidence = float(event.get("confidence", score / 100))
        mitre_id, tactic = _mitre_for(attack)

        ep_node_id = f"endpoint_{ep_id}"
        self.upsert_node(ep_node_id, "endpoint", hostname,
                         endpoint_id=ep_id, risk_score=score, severity=severity,
                         metadata={"ip": src_ip, "attack_type": attack,
                                   "mitre_technique": mitre_id, "source_layer": "network"})
        nodes.append({"node_id": ep_node_id})

        # Determine if this is an inbound attack (external → endpoint) or outbound
        is_inbound = any(k.lower() in attack.lower() for k in _INBOUND_ATTACKS)
        external_ip = src_ip if is_inbound else dst_ip
        if not external_ip:
            external_ip = dst_ip or src_ip

        if external_ip and not _is_private_ip(external_ip):
            # threat_actor for inbound attackers; ip node for outbound destinations
            node_type = "threat_actor" if is_inbound else "ip"
            ip_node_id = f"ip_{external_ip}"
            self.upsert_node(ip_node_id, node_type, external_ip,
                             endpoint_id=ep_id, risk_score=score, severity=severity,
                             metadata={"attack_type": attack,
                                       "mitre_technique": mitre_id,
                                       "source_layer": "network",
                                       "confidence": confidence})
            nodes.append({"node_id": ip_node_id})

            # Correct direction: inbound = threat_actor → endpoint; outbound = endpoint → ip
            if is_inbound:
                e = self.upsert_edge(ip_node_id, ep_node_id, attack,
                                     endpoint_id=ep_id,
                                     metadata={"attack_type": attack, "label": attack,
                                               "mitre_technique": mitre_id, "tactic": tactic,
                                               "severity": severity, "confidence": confidence,
                                               "correlation_score": score / 100})
            else:
                e = self.upsert_edge(ep_node_id, ip_node_id, attack,
                                     endpoint_id=ep_id,
                                     metadata={"attack_type": attack, "label": attack,
                                               "mitre_technique": mitre_id, "tactic": tactic,
                                               "severity": severity, "confidence": confidence,
                                               "correlation_score": score / 100})
            edges.append(e)

        return nodes, edges

    def process_fusion_alert(self, event: dict) -> tuple:
        nodes, edges = [], []
        ep_id     = event.get("endpoint_id", "server")
        severity  = event.get("severity", "LOW")
        score     = float(event.get("threat_score", 0.5)) * 100
        attack    = event.get("attack_type", "Fusion Alert")
        sources   = event.get("source", [])
        mitre_id, tactic = _mitre_for(attack)
        confidence = float(event.get("confidence", score / 100))

        ep_node_id = f"endpoint_{ep_id}"
        n = self.upsert_node(ep_node_id, "endpoint", ep_id,
                             endpoint_id=ep_id, risk_score=score, severity=severity,
                             metadata={"attack_type": attack, "mitre_technique": mitre_id})
        nodes.append(n)

        # Unique alert node per (endpoint_id, attack_type, 10-min bucket)
        bucket = datetime.now(timezone.utc).strftime("%Y%m%d%H%M")[:-1] + "0"
        alert_node_id = f"alert_{ep_id}_{hashlib.md5(attack.encode()).hexdigest()[:6]}_{bucket}"
        n = self.upsert_node(alert_node_id, "alert", attack,
                             endpoint_id=ep_id, risk_score=score, severity=severity,
                             metadata={"threat_score": score, "sources": sources,
                                       "shap": event.get("shap_explanation", []),
                                       "mitre_technique": mitre_id,
                                       "source_layer": "fusion"})
        nodes.append(n)
        e = self.upsert_edge(ep_node_id, alert_node_id, "triggered_alert",
                             endpoint_id=ep_id,
                             metadata={"severity": severity, "score": score,
                                       "attack_type": attack, "label": attack,
                                       "mitre_technique": mitre_id, "tactic": tactic,
                                       "confidence": confidence,
                                       "correlation_score": score / 100})
        edges.append(e)
        return nodes, edges

    def process_malware_alert(self, event: dict) -> tuple:
        """
        Build graph nodes for a malware alert.

        Creates a separate file node and a process node to represent the
        detection chain:  endpoint → file (File Download) → process (Execution)
        Both edges carry the Malware Activity MITRE technique T1204.
        """
        nodes, edges = [], []
        ep_id     = event.get("endpoint_id", "server")
        label     = event.get("label", "suspicious")
        score     = float(event.get("score", event.get("confidence", 0.5))) * 100
        proc_name = event.get("process_name", event.get("file_path", "unknown"))
        file_path = event.get("file_path", proc_name)
        severity  = "CRITICAL" if label == "malicious" else ("MEDIUM" if label == "suspicious" else "LOW")
        file_hash = event.get("sha256", event.get("md5", ""))
        mitre_id, tactic = _mitre_for("Malware Activity")
        confidence = score / 100

        ep_node_id = f"endpoint_{ep_id}"
        self.upsert_node(ep_node_id, "endpoint", ep_id, endpoint_id=ep_id,
                         risk_score=score, severity=severity,
                         metadata={"mitre_technique": mitre_id, "source_layer": "malware"})

        # File node — represents the artifact on disk
        file_id = f"file_{ep_id}_{hashlib.md5(file_path.encode()).hexdigest()[:8]}"
        n_file = self.upsert_node(file_id, "file", file_path,
                                  endpoint_id=ep_id, risk_score=score, severity=severity,
                                  metadata={"label": label, "hash": file_hash,
                                            "trusted": event.get("trusted", False),
                                            "mitre_technique": mitre_id,
                                            "source_layer": "malware",
                                            "confidence": confidence})
        nodes.append(n_file)

        # Process node — represents the running executable
        proc_id = f"process_{ep_id}_{hashlib.md5(proc_name.encode()).hexdigest()[:8]}"
        n_proc = self.upsert_node(proc_id, "process", proc_name,
                                  endpoint_id=ep_id, risk_score=score, severity=severity,
                                  metadata={"label": label, "hash": file_hash,
                                            "shap": event.get("shap_explanation", []),
                                            "trusted": event.get("trusted", False),
                                            "mitre_technique": mitre_id,
                                            "source_layer": "malware",
                                            "confidence": confidence})
        nodes.append(n_proc)

        # endpoint → file (File Download)
        e1 = self.upsert_edge(ep_node_id, file_id, "File Download",
                              endpoint_id=ep_id,
                              metadata={"attack_type": "Malware Activity",
                                        "label": "File Download",
                                        "mitre_technique": mitre_id, "tactic": tactic,
                                        "severity": severity, "confidence": confidence,
                                        "correlation_score": confidence})
        edges.append(e1)

        # file → process (Execution)
        e2 = self.upsert_edge(file_id, proc_id, "Execution",
                              endpoint_id=ep_id,
                              metadata={"attack_type": "Malware Activity",
                                        "label": "Execution",
                                        "mitre_technique": mitre_id, "tactic": tactic,
                                        "severity": severity, "confidence": confidence,
                                        "correlation_score": confidence})
        edges.append(e2)
        return nodes, edges

    def process_user_anomaly(self, event: dict) -> tuple:
        nodes, edges = [], []
        ep_id    = event.get("endpoint_id", "server")
        username = event.get("username", event.get("user", "unknown"))
        score    = float(event.get("score", event.get("anomaly_score", 0.5))) * 100
        severity = event.get("severity", "MEDIUM")
        mitre_id, tactic = _mitre_for("User Anomaly")
        confidence = score / 100

        user_node_id = f"user_{username}"
        n = self.upsert_node(user_node_id, "user", username,
                             endpoint_id=ep_id, risk_score=score, severity=severity,
                             metadata={"anomaly_reason": event.get("reason", ""),
                                       "last_seen": event.get("timestamp", ""),
                                       "mitre_technique": mitre_id,
                                       "source_layer": "user_behavior"})
        nodes.append(n)
        ep_node_id = f"endpoint_{ep_id}"
        self.upsert_node(ep_node_id, "endpoint", ep_id, endpoint_id=ep_id)
        e = self.upsert_edge(user_node_id, ep_node_id, "authenticated_as",
                             endpoint_id=ep_id,
                             metadata={"severity": severity, "score": score,
                                       "attack_type": "User Anomaly",
                                       "label": "Suspicious Login",
                                       "mitre_technique": mitre_id, "tactic": tactic,
                                       "confidence": confidence,
                                       "correlation_score": confidence})
        edges.append(e)
        return nodes, edges

    def process_sysmon_alert(self, event: dict) -> tuple:
        """Build graph nodes and edges for a Sysmon behavioral alert."""
        nodes, edges = [], []
        ep_id    = event.get("endpoint_id", "server")
        proc     = event.get("process_name", event.get("image", "unknown"))
        score    = float(event.get("anomaly_score", event.get("score", 0.5))) * 100
        severity = event.get("severity", "MEDIUM")
        mitre_id, tactic = _mitre_for("Sysmon Alert")
        confidence = score / 100

        ep_node_id = f"endpoint_{ep_id}"
        self.upsert_node(ep_node_id, "endpoint", ep_id, endpoint_id=ep_id,
                         risk_score=score, severity=severity)

        proc_id = f"process_{ep_id}_{hashlib.md5(proc.encode()).hexdigest()[:8]}"
        n = self.upsert_node(proc_id, "process", proc,
                             endpoint_id=ep_id, risk_score=score, severity=severity,
                             metadata={"mitre_technique": mitre_id,
                                       "source_layer": "sysmon",
                                       "event_id": event.get("event_id", ""),
                                       "confidence": confidence})
        nodes.append(n)
        e = self.upsert_edge(ep_node_id, proc_id, "Sysmon Alert",
                             endpoint_id=ep_id,
                             metadata={"attack_type": "Sysmon Alert",
                                       "label": "Process Chain",
                                       "mitre_technique": mitre_id, "tactic": tactic,
                                       "severity": severity, "confidence": confidence,
                                       "correlation_score": confidence})
        edges.append(e)
        return nodes, edges

    def process_endpoint_telemetry(self, telemetry: dict) -> tuple:
        """Called on each /endpoint/ingest payload to build baseline topology."""
        nodes, edges = [], []
        ep_id    = telemetry.get("endpoint", {}).get("endpoint_id", telemetry.get("endpoint_id", ""))
        hostname = telemetry.get("endpoint", {}).get("hostname", telemetry.get("hostname", ep_id))
        sys_data = telemetry.get("system", {})
        usr_data = telemetry.get("user", {})
        net_data = telemetry.get("network", {})

        # Endpoint node (low risk — baseline, not anomaly)
        ep_node_id = f"endpoint_{ep_id}"
        n = self.upsert_node(ep_node_id, "endpoint", hostname,
                             endpoint_id=ep_id, risk_score=0, severity="LOW",
                             metadata={
                                 "os": telemetry.get("endpoint", {}).get("os", ""),
                                 "ip": telemetry.get("endpoint", {}).get("ip_address", ""),
                                 "username": usr_data.get("current_user", ""),
                                 "cpu": sys_data.get("cpu_percent", 0),
                                 "mem": sys_data.get("memory_percent", 0),
                             })
        nodes.append(n)

        # User node
        username = usr_data.get("current_user", "")
        if username:
            user_node_id = f"user_{username}"
            n = self.upsert_node(user_node_id, "user", username,
                                 endpoint_id=ep_id, risk_score=0, severity="LOW",
                                 metadata={"endpoint": hostname})
            nodes.append(n)
            e = self.upsert_edge(user_node_id, ep_node_id, "authenticated_as",
                                 endpoint_id=ep_id)
            edges.append(e)

        # Suspicious connections → IP nodes
        for conn in (net_data.get("suspicious_connections") or []):
            dst = conn.get("remote_ip", conn.get("ip", ""))
            if dst and not _is_private_ip(dst):
                ip_node_id = f"ip_{dst}"
                self.upsert_node(ip_node_id, "ip", dst, endpoint_id=ep_id,
                                 risk_score=30, severity="MEDIUM",
                                 metadata={"port": conn.get("remote_port", ""),
                                           "reason": conn.get("reason", "suspicious port")})
                e = self.upsert_edge(ep_node_id, ip_node_id, "connected_to",
                                     endpoint_id=ep_id)
                edges.append(e)
        return nodes, edges

    def process_response_action(self, command: dict) -> tuple:
        """
        Called when a SOAR command completes.
        Links from the most recent alert node for this endpoint when available;
        falls back to linking from the endpoint node directly.
        """
        nodes, edges = [], []
        ep_id   = command.get("endpoint_id", "server")
        action  = command.get("action", "unknown")
        cmd_id  = str(command.get("_id", command.get("command_id", "")))
        status  = command.get("status", "completed")

        resp_node_id = f"response_{cmd_id or hashlib.md5(f'{ep_id}{action}'.encode()).hexdigest()[:8]}"
        n = self.upsert_node(resp_node_id, "response_action", action,
                             endpoint_id=ep_id, risk_score=0, severity="LOW",
                             metadata={"status": status,
                                       "target": command.get("target", ""),
                                       "result": command.get("result_message", "")})
        nodes.append(n)

        # Attempt to find the most recent alert node for this endpoint
        source_node_id = f"endpoint_{ep_id}"
        if self._db is not None:
            try:
                recent_alert = self._db["attack_graph_nodes"].find_one(
                    {"type": "alert", "endpoint_id": ep_id},
                    sort=[("last_updated", -1)],
                )
                if recent_alert:
                    source_node_id = recent_alert["node_id"]
            except Exception:
                pass  # Fall back to endpoint node

        e = self.upsert_edge(source_node_id, resp_node_id, "responded_by",
                             endpoint_id=ep_id,
                             metadata={"action": action, "status": status,
                                       "attack_type": action, "label": "Response Executed",
                                       "mitre_technique": "T1562",
                                       "confidence": 1.0,
                                       "correlation_score": 1.0})
        edges.append(e)
        return nodes, edges

    # ── Incident Correlation ──────────────────────────────────────────────────

    def ingest_to_incident(self, event_type: str, event_data: dict) -> "str | None":
        """
        Correlate an event into an existing open incident or create a new one.

        Correlation logic:
          - Find an open incident for this endpoint_id within the correlation window.
          - If found: append to its timeline, escalate severity if needed.
          - If not found: create a new incident document.

        Returns the incident_id string, or None when MongoDB is unavailable.
        """
        if self._db is None:
            return None

        ep_id = event_data.get(
            "endpoint_id",
            event_data.get("endpoint", {}).get("endpoint_id", "server"),
        )
        attack     = event_data.get("attack_type", event_type)
        severity   = event_data.get("severity", "MEDIUM")
        score      = float(event_data.get("threat_score", event_data.get("score", 0.5)))
        mitre_id, tactic = _mitre_for(attack)
        now        = datetime.now(timezone.utc)
        window_start = (now - timedelta(seconds=_INCIDENT_CORRELATION_WINDOW_S)).isoformat()

        # Find an open incident for this endpoint within the correlation window
        try:
            existing = self._db["incidents"].find_one(
                {"endpoint_id": ep_id, "status": "open",
                 "last_event_at": {"$gte": window_start}},
                sort=[("last_event_at", -1)],
            )
        except Exception as exc:
            logger.debug("[AttackGraphEngine] incident lookup failed: %s", exc)
            return None

        sev_order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

        if existing:
            incident_id = existing["incident_id"]
            cur_sev = existing.get("severity", "LOW")
            new_sev = (
                severity
                if sev_order.get(severity, 0) > sev_order.get(cur_sev, 0)
                else cur_sev
            )
            sources = set(existing.get("source_layers", []))
            sources.add(event_type)
            techniques = set(existing.get("mitre_techniques", []))
            techniques.add(mitre_id)

            try:
                self._db["incidents"].update_one(
                    {"incident_id": incident_id},
                    {
                        "$set": {
                            "severity":         new_sev,
                            "last_event_at":    now.isoformat(),
                            "source_layers":    list(sources),
                            "mitre_techniques": list(techniques),
                            "threat_score":     max(existing.get("threat_score", 0.0), score),
                        },
                        "$push": {
                            "timeline": {
                                "timestamp":      now.isoformat(),
                                "event_type":     event_type,
                                "attack_type":    attack,
                                "severity":       severity,
                                "mitre_technique": mitre_id,
                                "tactic":         tactic,
                                "source_layer":   event_type,
                                "description":    f"{attack} detected by {event_type} layer",
                            }
                        },
                    },
                )
            except Exception as exc:
                logger.warning("[AttackGraphEngine] incident update failed: %s", exc)
            return incident_id

        else:
            incident_id = f"INC-{now.strftime('%Y%m%d%H%M%S')}-{ep_id[:8]}"
            hostname    = event_data.get("hostname", ep_id)
            incident = {
                "incident_id":      incident_id,
                "endpoint_id":      ep_id,
                "hostname":         hostname,
                "status":           "open",
                "severity":         severity,
                "threat_score":     score,
                "attack_type":      attack,
                "title":            f"{attack} on {hostname}",
                "source_layers":    [event_type],
                "mitre_techniques": [mitre_id],
                "created_at":       now.isoformat(),
                "last_event_at":    now.isoformat(),
                "timeline": [{
                    "timestamp":      now.isoformat(),
                    "event_type":     event_type,
                    "attack_type":    attack,
                    "severity":       severity,
                    "mitre_technique": mitre_id,
                    "tactic":         tactic,
                    "source_layer":   event_type,
                    "description":    f"Incident created: {attack} detected by {event_type} layer",
                }],
                "affected_assets": [ep_id],
                "root_cause": f"Initial detection: {attack} from {event_type} layer",
                "src_ip": event_data.get("source_ip", event_data.get("src_ip", "")),
            }
            try:
                self._db["incidents"].insert_one(incident)
            except Exception as exc:
                logger.warning("[AttackGraphEngine] incident insert failed: %s", exc)
            return incident_id

    # ── Lifecycle helpers ─────────────────────────────────────────────────────

    def mark_endpoint_offline(self, endpoint_id: str) -> None:
        """
        Downgrade an endpoint node's severity to LOW and set its status to
        'offline' when the heartbeat monitor determines it has stopped reporting.
        The node is retained in the graph for historical context; the frontend
        uses `graph_update_remove` to hide it from the live topology view.
        """
        if self._db is None:
            return
        nid = f"ep-{endpoint_id}"
        now = datetime.now(timezone.utc)
        try:
            self._db["attack_graph_nodes"].update_one(
                {"node_id": nid},
                {"$set": {
                    "status": "offline",
                    "severity": "LOW",
                    "risk_score": 0,
                    "last_updated": now,
                }},
            )
        except Exception as exc:
            logger.debug(f"[AttackGraphEngine] mark_endpoint_offline({nid}) failed: {exc}")

    # ── Queries ───────────────────────────────────────────────────────────────

    def get_snapshot(self, max_age_hours: int = 48) -> dict:
        if self._db is None:
            return {"nodes": [], "edges": [], "step": 0}
        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)

        def _serialize(doc):
            doc = {k: v for k, v in doc.items() if k != "_id"}
            for key in ("timestamp", "last_updated"):
                if key in doc and hasattr(doc[key], "isoformat"):
                    doc[key] = doc[key].isoformat()
            return doc

        nodes = [_serialize(n) for n in
                 self._db["attack_graph_nodes"].find({"last_updated": {"$gte": cutoff}})]
        edges = [_serialize(e) for e in
                 self._db["attack_graph_edges"].find({"last_updated": {"$gte": cutoff}})]
        # step = highest chain_seq in the current snapshot so the frontend
        # scrubber knows the total number of replay steps available.
        step = max((e.get("chain_seq", 0) for e in edges), default=0)
        return {"nodes": nodes, "edges": edges, "step": step}

    def get_timeline(self, hours: int = 24) -> list:
        """Returns node + edge events sorted by timestamp for replay."""
        if self._db is None:
            return []
        cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)

        def _serialize(doc):
            doc = {k: v for k, v in doc.items() if k != "_id"}
            for key in ("timestamp", "last_updated"):
                if key in doc and hasattr(doc[key], "isoformat"):
                    doc[key] = doc[key].isoformat()
            return doc

        events = []
        for n in self._db["attack_graph_nodes"].find({"timestamp": {"$gte": cutoff}}).sort("timestamp", 1):
            events.append({"kind": "node", "timestamp": _serialize(n).get("timestamp"), "data": _serialize(n)})
        for e in self._db["attack_graph_edges"].find({"timestamp": {"$gte": cutoff}}).sort("timestamp", 1):
            events.append({"kind": "edge", "timestamp": _serialize(e).get("timestamp"), "data": _serialize(e)})
        events.sort(key=lambda x: x.get("timestamp") or "")
        return events

    def get_incidents(self, hours: int = 48, limit: int = 50) -> list:
        """Return incidents updated within the last *hours* hours, newest-first."""
        if self._db is None:
            return []
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=hours)).isoformat()
        try:
            docs = list(self._db["incidents"].find(
                {"last_event_at": {"$gte": cutoff}},
                {"_id": 0},
                sort=[("last_event_at", -1)],
            ).limit(limit))
            return docs
        except Exception as exc:
            logger.warning("[AttackGraphEngine] get_incidents failed: %s", exc)
            return []

    def get_incident(self, incident_id: str) -> "dict | None":
        """Return a single incident document with attached graph nodes and edges."""
        if self._db is None:
            return None
        try:
            doc = self._db["incidents"].find_one({"incident_id": incident_id}, {"_id": 0})
        except Exception as exc:
            logger.warning("[AttackGraphEngine] get_incident lookup failed: %s", exc)
            return None
        if not doc:
            return None

        # Attach graph nodes/edges for this endpoint within the incident window
        ep_id   = doc.get("endpoint_id", "")
        created = doc.get("created_at", "")
        last    = doc.get("last_event_at", "")
        if ep_id and self._db is not None:
            try:
                nodes = list(self._db["attack_graph_nodes"].find(
                    {"endpoint_id": ep_id,
                     "timestamp": {"$gte": created, "$lte": last}},
                    {"_id": 0},
                ))
                edges = list(self._db["attack_graph_edges"].find(
                    {"endpoint_id": ep_id,
                     "timestamp": {"$gte": created, "$lte": last}},
                    {"_id": 0},
                    sort=[("chain_seq", 1)],
                ))
                # Serialize datetime objects to ISO strings
                def _ser(d):
                    return {k: (v.isoformat() if hasattr(v, "isoformat") else v)
                            for k, v in d.items()}
                doc["graph"] = {"nodes": [_ser(n) for n in nodes],
                                "edges": [_ser(e) for e in edges]}
            except Exception:
                doc["graph"] = {"nodes": [], "edges": []}
        else:
            doc["graph"] = {"nodes": [], "edges": []}
        return doc


def _is_private_ip(ip: str) -> bool:
    """Returns True for RFC-1918 / loopback / link-local addresses."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4:
            return False
        if parts[0] == 10:
            return True
        if parts[0] == 172 and 16 <= parts[1] <= 31:
            return True
        if parts[0] == 192 and parts[1] == 168:
            return True
        if parts[0] == 127:
            return True
        if parts[0] == 169 and parts[1] == 254:
            return True
    except Exception:
        pass
    return False
