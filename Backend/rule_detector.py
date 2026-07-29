# rule_detector.py
# Rule-based detector that runs BEFORE the ML models.
# Catches attacks that have unmistakable network signatures:
#   - Port scans (many unique dst ports from one src)
#   - DoS / DDoS (massive packet rate)
#   - Brute force (many connections to same port)
#   - SYN floods (high SYN count, low ACK)
#   - Data exfiltration (large outbound transfer)
#
# Drop in D:\Cyber Sentinal\Network model\
# These rules are deterministic — no false positives on normal traffic.

import json
import os
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class FlowSummary:
    src_ip:    str
    dest_ip:   str
    dest_port: int
    src_port:  int
    proto:     str
    ts:        str
    pkts_fwd:  float
    pkts_bwd:  float
    bytes_fwd: float
    bytes_bwd: float
    duration:  float
    syn_flag:  bool
    ack_flag:  bool
    fin_flag:  bool
    rst_flag:  bool


@dataclass
class RuleHit:
    rule_name:   str
    attack_type: str
    severity:    str
    color:       str
    icon:        str
    description: str
    evidence:    str
    src_ip:      str
    dest_ip:     str
    dest_port:   int
    confidence:  float = 95.0
    # ── Rich stats — populated from aggregated flow data ──────────────────
    # These replace the hardcoded zeros that were causing empty table rows.
    total_bytes_sent: float = 0.0
    total_bytes_recv: float = 0.0
    total_pkts:       float = 0.0
    duration:         float = 0.0
    flow_count:       int   = 0
    proto:            str   = "TCP"
    ts:               str   = ""


# ── THRESHOLDS ────────────────────────────────────────────────────────────────
RULES = {
    # Port scan: one src hitting many distinct ports in one capture window
    "PORT_SCAN_HORIZONTAL": {
        "unique_dst_ports_threshold": 15,
    },
    # Host sweep: one src hitting many distinct destination IPs
    "HOST_SWEEP": {
        "unique_dst_ips_threshold": 10,
    },
    # SYN flood: many SYN packets, almost no ACK (incomplete handshakes)
    "SYN_FLOOD": {
        "min_syn_pkts":  500,
        "max_ack_ratio": 0.1,
    },
    # DoS: extreme packet rate from one source
    "DOS_FLOOD": {
        "min_pkts_per_second": 1000,
    },
    # Brute force: many connections to same port (SSH=22, RDP=3389, FTP=21 …)
    "BRUTE_FORCE": {
        "brute_force_ports": {22, 3389, 21, 5900, 1433, 3306, 23},
        "min_connections":   20,
    },
    # Data exfiltration: unusually large upload from internal host
    "DATA_EXFIL": {
        "min_bytes_sent_mb": 50,
        "min_upload_ratio":  5.0,
    },
}


class RuleDetector:
    """
    Analyses a full eve.json capture window and returns rule hits.
    Runs before ML models so high-confidence attacks are never suppressed
    by the personal baseline Gate 1.

    Each RuleHit now carries the full aggregated traffic stats for the
    offending source IP so the dashboard table shows real byte counts,
    duration, and the evidence string instead of blank/zero fields.

    Incremental reading: _file_offset tracks the byte position of the last
    read so that each call to analyse() only processes new lines appended
    since the previous call.  If the file shrinks (Suricata log rotation)
    the offset is reset to 0 and the new file is read from the start.
    """

    def __init__(self) -> None:
        # Byte offset into eve.json at the end of the last successful read.
        self._file_offset: int = 0

    def analyse(self, eve_path: str) -> tuple:
        """
        Returns:
            rule_hits   — list[RuleHit]  for detected attacks
            clean_flows — list[FlowSummary] for flows NOT flagged by rules
        """
        if not os.path.exists(eve_path):
            return [], []

        flows = self._parse_eve(eve_path)
        if not flows:
            return [], []

        # ── Per-source IP aggregation ─────────────────────────────────────
        src_stats = defaultdict(lambda: {
            "dst_ports":        set(),
            "dst_ips":          set(),
            "syn_count":        0,
            "ack_count":        0,
            "total_pkts":       0.0,
            "total_bytes_sent": 0.0,
            "total_bytes_recv": 0.0,
            "duration_sum":     0.0,
            "port_connections": defaultdict(int),
            "flow_count":       0,
            "first_ts":         "",   # timestamp of first flow from this src
            "proto":            "TCP",
            "sample_dst_ip":    "",   # first non-empty dest IP seen
        })

        for f in flows:
            s = src_stats[f.src_ip]
            s["dst_ports"].add(f.dest_port)
            s["dst_ips"].add(f.dest_ip)
            # Use packet-weighted counts so SYN/ACK ratio reflects traffic volume,
            # not just number of flows carrying these flags.
            s["syn_count"]        += (f.pkts_fwd if f.syn_flag else 0)
            s["ack_count"]        += (f.pkts_fwd if f.ack_flag else 0)
            s["total_pkts"]       += f.pkts_fwd + f.pkts_bwd
            s["total_bytes_sent"] += f.bytes_fwd
            s["total_bytes_recv"] += f.bytes_bwd
            s["duration_sum"]     += f.duration
            s["port_connections"][f.dest_port] += 1
            s["flow_count"]       += 1
            if not s["first_ts"]:
                s["first_ts"] = f.ts
            if not s["sample_dst_ip"] and f.dest_ip:
                s["sample_dst_ip"] = f.dest_ip
            s["proto"] = f.proto or "TCP"

        rule_hits   = []
        flagged_ips = set()

        for src_ip, s in src_stats.items():
            # Skip link-local / multicast
            if src_ip.startswith("fe80:") or src_ip.startswith("ff02:"):
                continue

            n_dst_ports = len(s["dst_ports"])
            n_dst_ips   = len(s["dst_ips"])
            duration    = max(s["duration_sum"], 0.001)
            pkts_per_s  = s["total_pkts"] / duration
            ack_ratio   = s["ack_count"] / max(s["syn_count"], 1)

            # Resolve best dest_ip for display
            best_dest_ip = (
                s["sample_dst_ip"]
                or (list(s["dst_ips"])[0] if s["dst_ips"] else "")
            )

            # Common kwargs shared by every RuleHit from this source IP.
            # These carry the REAL aggregated traffic stats so the dashboard
            # table is populated instead of showing zeros.
            common = dict(
                src_ip           = src_ip,
                dest_ip          = best_dest_ip,
                total_bytes_sent = s["total_bytes_sent"],
                total_bytes_recv = s["total_bytes_recv"],
                total_pkts       = s["total_pkts"],
                duration         = duration,
                flow_count       = s["flow_count"],
                proto            = s["proto"],
                ts               = s["first_ts"],
            )

            hits_this_src = []

            # ── Rule 1: Horizontal port scan ──────────────────────────────
            cfg = RULES["PORT_SCAN_HORIZONTAL"]
            if n_dst_ports >= cfg["unique_dst_ports_threshold"]:
                hits_this_src.append(RuleHit(
                    rule_name   = "PORT_SCAN_HORIZONTAL",
                    attack_type = "PortScan",
                    severity    = "HIGH",
                    color       = "#ea580c",
                    icon        = "🔍",
                    description = "Port Scan Detected",
                    evidence    = f"{n_dst_ports} unique ports scanned in one window",
                    dest_port   = 0,
                    confidence  = min(99.0, 70 + (n_dst_ports - cfg["unique_dst_ports_threshold"]) * 0.5),
                    **common,
                ))

            # ── Rule 2: Host sweep ────────────────────────────────────────
            cfg = RULES["HOST_SWEEP"]
            if n_dst_ips >= cfg["unique_dst_ips_threshold"] and n_dst_ports <= 3:
                # Filter out broadcast/multicast destinations to reduce false positives.
                real_ips = {
                    ip for ip in s["dst_ips"]
                    if ip and not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239.")
                }
                if len(real_ips) < cfg["unique_dst_ips_threshold"]:
                    pass
                else:
                    hits_this_src.append(RuleHit(
                        rule_name   = "HOST_SWEEP",
                        attack_type = "PortScan",
                        severity    = "HIGH",
                        color       = "#ea580c",
                        icon        = "🔍",
                        description = "Network Host Sweep",
                        evidence    = f"{len(real_ips)} unique hosts probed on {n_dst_ports} port(s)",
                        dest_port   = list(s["port_connections"].keys())[0] if s["port_connections"] else 0,
                        confidence  = 90.0,
                        **common,
                    ))

            # ── Rule 3: SYN flood ─────────────────────────────────────────
            cfg = RULES["SYN_FLOOD"]
            if s["syn_count"] >= cfg["min_syn_pkts"] and ack_ratio < cfg["max_ack_ratio"]:
                hits_this_src.append(RuleHit(
                    rule_name   = "SYN_FLOOD",
                    attack_type = "DoS",
                    severity    = "CRITICAL",
                    color       = "#dc2626",
                    icon        = "💥",
                    description = "SYN Flood Attack",
                    evidence    = f"{s['syn_count']} SYNs sent, {ack_ratio:.0%} ACK completion rate",
                    dest_port   = 0,
                    confidence  = 97.0,
                    **common,
                ))

            # ── Rule 4: DoS flood ─────────────────────────────────────────
            cfg = RULES["DOS_FLOOD"]
            if pkts_per_s >= cfg["min_pkts_per_second"]:
                hits_this_src.append(RuleHit(
                    rule_name   = "DOS_FLOOD",
                    attack_type = "DoS",
                    severity    = "CRITICAL",
                    color       = "#dc2626",
                    icon        = "💥",
                    description = "DoS Flood Attack",
                    evidence    = f"{pkts_per_s:,.0f} packets/sec from this host",
                    dest_port   = 0,
                    confidence  = 96.0,
                    **common,
                ))

            # ── Rule 5: Brute force ───────────────────────────────────────
            cfg = RULES["BRUTE_FORCE"]
            for port, conn_count in s["port_connections"].items():
                if port in cfg["brute_force_ports"] and conn_count >= cfg["min_connections"]:
                    svc = {
                        22: "SSH", 3389: "RDP", 21: "FTP",
                        5900: "VNC", 1433: "MSSQL", 3306: "MySQL", 23: "Telnet",
                    }.get(port, str(port))
                    hits_this_src.append(RuleHit(
                        rule_name   = "BRUTE_FORCE",
                        attack_type = "BruteForce",
                        severity    = "HIGH",
                        color       = "#d97706",
                        icon        = "🔨",
                        description = f"Brute Force — {svc}",
                        evidence    = f"{conn_count} repeated connections to {svc} (port {port})",
                        dest_port   = port,
                        confidence  = min(99.0, 75 + conn_count * 0.5),
                        **common,
                    ))

            # ── Rule 6: Data exfiltration ─────────────────────────────────
            cfg    = RULES["DATA_EXFIL"]
            mb_out = s["total_bytes_sent"] / (1024 * 1024)
            ratio  = s["total_bytes_sent"] / max(s["total_bytes_recv"], 1)
            if mb_out >= cfg["min_bytes_sent_mb"] and ratio >= cfg["min_upload_ratio"]:
                hits_this_src.append(RuleHit(
                    rule_name   = "DATA_EXFIL",
                    attack_type = "Infiltration",
                    severity    = "CRITICAL",
                    color       = "#4c0519",
                    icon        = "🥷",
                    description = "Data Exfiltration Detected",
                    evidence    = f"{mb_out:.1f}MB uploaded, {ratio:.1f}x more sent than received",
                    dest_port   = 0,
                    confidence  = 88.0,
                    **common,
                ))

            if hits_this_src:
                rule_hits.extend(hits_this_src)
                flagged_ips.add(src_ip)

        # Clean flows = flows whose src_ip was NOT flagged by any rule
        clean_flows = [f for f in flows if f.src_ip not in flagged_ips]

        if rule_hits:
            logger.info(
                f"🚨 Rule detector: {len(rule_hits)} hits from "
                f"{len(flagged_ips)} IPs | {len(clean_flows)} clean flows → ML"
            )

        return rule_hits, clean_flows

    # ─────────────────────────────────────────────────────────────────────
    # Time window for the secondary recency filter (seconds).
    _TIME_WINDOW_SECONDS: int = 120

    def _parse_eve(self, eve_path: str) -> list:
        """
        Read only lines appended since the last call (incremental read).

        Log-rotation guard: if the current file size is smaller than the
        stored offset, Suricata has rotated the log — reset to 0 and read
        the new file from the start.

        Secondary filter: discard any flow whose timestamp is older than
        _TIME_WINDOW_SECONDS (2 minutes) relative to the current UTC clock.
        This guards against stale records that may appear after a rotation.
        """
        flows = []
        try:
            with self._open_with_retry(eve_path) as f:
                # ── Log-rotation detection ────────────────────────────────
                f.seek(0, 2)                    # seek to end to get file size
                file_size = f.tell()
                if file_size < self._file_offset:
                    logger.info(
                        "eve.json is smaller than stored offset "
                        f"({file_size} < {self._file_offset}) — "
                        "log rotation detected, resetting offset to 0"
                    )
                    self._file_offset = 0

                # ── Seek to last-read position and read new lines only ────
                f.seek(self._file_offset)

                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        ev = json.loads(line)
                    except Exception:
                        continue

                    if ev.get("event_type") != "flow":
                        continue

                    src = ev.get("src_ip", "")
                    if src.startswith("fe80:") or src.startswith("ff02:"):
                        continue

                    flow = ev.get("flow", {})
                    tcp  = ev.get("tcp", {})

                    flows.append(FlowSummary(
                        src_ip    = src,
                        dest_ip   = ev.get("dest_ip", ""),
                        dest_port = int(ev.get("dest_port", 0)),
                        src_port  = int(ev.get("src_port", 0)),
                        proto     = ev.get("proto", "TCP").upper(),
                        ts        = ev.get("timestamp", ""),
                        pkts_fwd  = float(flow.get("pkts_toserver", 0)),
                        pkts_bwd  = float(flow.get("pkts_toclient", 0)),
                        bytes_fwd = float(flow.get("bytes_toserver", 0)),
                        bytes_bwd = float(flow.get("bytes_toclient", 0)),
                        # Use a sane lower bound for rate-based rule metrics.
                        # Very tiny durations explode packets/sec and cause false positives.
                        duration  = max(float(flow.get("age", 0)), 1.0),
                        syn_flag  = bool(tcp.get("syn", False)),
                        ack_flag  = bool(tcp.get("ack", False)),
                        fin_flag  = bool(tcp.get("fin", False)),
                        rst_flag  = bool(tcp.get("rst", False)),
                    ))

                # ── Persist the new read position ─────────────────────────
                self._file_offset = f.tell()

        except Exception as e:
            logger.error(f"Error parsing eve.json: {e}")

        # ── 2-minute recency filter ───────────────────────────────────────
        # Suricata timestamps are ISO-8601 with timezone offset, e.g.:
        #   2024-02-15T08:23:01.123456+0000
        # We parse and compare against UTC now.  Flows that cannot be parsed
        # are kept (fail-open) so a malformed timestamp never silently drops
        # a real detection.
        cutoff = datetime.now(tz=timezone.utc) - timedelta(seconds=self._TIME_WINDOW_SECONDS)
        recent: list = []
        for fl in flows:
            try:
                ts_str = fl.ts
                if ts_str:
                    # Python's fromisoformat doesn't handle "+0000" (no colon)
                    # in Python < 3.11; normalise to "+00:00" form.
                    if len(ts_str) > 5 and ts_str[-5] in ("+", "-") and ":" not in ts_str[-5:]:
                        ts_str = ts_str[:-2] + ":" + ts_str[-2:]
                    flow_dt = datetime.fromisoformat(ts_str)
                    if flow_dt.tzinfo is None:
                        flow_dt = flow_dt.replace(tzinfo=timezone.utc)
                    if flow_dt < cutoff:
                        continue        # stale — discard
            except Exception:
                pass                    # unparseable timestamp — keep the flow
            recent.append(fl)

        stale_count = len(flows) - len(recent)
        if stale_count:
            logger.debug(f"_parse_eve: discarded {stale_count} flows older than {self._TIME_WINDOW_SECONDS}s")

        return recent

    @staticmethod
    def _open_with_retry(path: str, retries: int = 5, delay: float = 0.2):
        """
        Windows file-lock retry helper.
        Suricata may hold eve.json briefly while rotating/writing.
        """
        for attempt in range(retries):
            try:
                return open(path, "r", encoding="utf-8", errors="ignore")
            except PermissionError:
                if attempt < retries - 1:
                    time.sleep(delay)
                else:
                    raise
