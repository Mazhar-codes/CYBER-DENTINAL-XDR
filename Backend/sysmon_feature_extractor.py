"""
sysmon_feature_extractor.py — Cyber Sentinel XDR
=================================================
Converts a rolling window of raw Sysmon events into a time-bucketed feature
matrix suitable for LSTM input.

Feature vector (12 features per 10-second bucket):
    0   process_create_count      EventID 1  — raw process launch rate
    1   network_connection_count  EventID 3  — outbound connection rate
    2   file_create_count         EventID 11 — file write rate
    3   image_load_count          EventID 7  — DLL/module load rate
    4   registry_event_count      EventID 12+13 — registry modification rate
    5   dns_query_count           EventID 22 — DNS lookup rate
    6   high_risk_event_count     EventID 8+25 — remote thread / process tamper
    7   unique_process_count      distinct PIDs seen in bucket
    8   unique_dst_ip_count       distinct DestinationIp values (EventID 3)
    9   unique_dst_port_count     distinct DestinationPort values (EventID 3)
   10   cmd_process_count         cmd.exe or powershell.exe launches (EventID 1)
   11   suspicious_port_count     connections to ports 4444,1337,31337,8080,9001,6666

Usage:
    from sysmon_feature_extractor import SysmonFeatureExtractor

    extractor = SysmonFeatureExtractor(bucket_seconds=10, sequence_length=20)
    extractor.push(event_dict)          # call for every incoming Sysmon event
    matrix = extractor.get_sequence()  # np.ndarray (20, 12) or None if not full yet
"""
from __future__ import annotations

import logging
import os
import time
from collections import defaultdict, deque
from typing import Optional

import numpy as np

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Feature constants
# ---------------------------------------------------------------------------

FEATURE_NAMES: list[str] = [
    "process_create_count",
    "network_connection_count",
    "file_create_count",
    "image_load_count",
    "registry_event_count",
    "dns_query_count",
    "high_risk_event_count",
    "unique_process_count",
    "unique_dst_ip_count",
    "unique_dst_port_count",
    "cmd_process_count",
    "suspicious_port_count",
]

N_FEATURES: int = len(FEATURE_NAMES)   # 12

# Ports associated with common C2/backdoor frameworks
_SUSPICIOUS_PORTS: frozenset[str] = frozenset({
    "4444",   # Metasploit default
    "1337",   # l33t / generic backdoor
    "31337",  # Back Orifice
    "8080",   # common HTTP alternate / C2
    "9001",   # Tor / Metasploit
    "6666",   # common RAT
    "4443",   # HTTPS reverse shell
    "443",    # suspicious when used by non-browser processes — not filtered here
              # (leave domain filtering to the downstream model)
})

# Executables counted as "cmd_process" for lateral movement / living-off-the-land
_CMD_NAMES: frozenset[str] = frozenset({
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe", "mshta.exe",
})

# EventIDs mapped to feature index (for fast dispatch)
_EID_TO_FIELD: dict[str, str] = {
    "1":  "process_create_count",
    "3":  "network_connection_count",
    "7":  "image_load_count",
    "8":  "high_risk_event_count",
    "11": "file_create_count",
    "12": "registry_event_count",
    "13": "registry_event_count",
    "22": "dns_query_count",
    "25": "high_risk_event_count",
}


# ---------------------------------------------------------------------------
# Bucket accumulator (mutable, reset every bucket_seconds)
# ---------------------------------------------------------------------------

class _Bucket:
    """Accumulates feature counts for one time bucket."""

    __slots__ = (
        "process_create_count",
        "network_connection_count",
        "file_create_count",
        "image_load_count",
        "registry_event_count",
        "dns_query_count",
        "high_risk_event_count",
        "cmd_process_count",
        "suspicious_port_count",
        "_pids",
        "_dst_ips",
        "_dst_ports",
        "start_time",
    )

    def __init__(self, start_time: float) -> None:
        self.process_create_count: int = 0
        self.network_connection_count: int = 0
        self.file_create_count: int = 0
        self.image_load_count: int = 0
        self.registry_event_count: int = 0
        self.dns_query_count: int = 0
        self.high_risk_event_count: int = 0
        self.cmd_process_count: int = 0
        self.suspicious_port_count: int = 0
        self._pids: set[str] = set()
        self._dst_ips: set[str] = set()
        self._dst_ports: set[str] = set()
        self.start_time: float = start_time

    def to_feature_vector(self) -> list[float]:
        return [
            float(self.process_create_count),
            float(self.network_connection_count),
            float(self.file_create_count),
            float(self.image_load_count),
            float(self.registry_event_count),
            float(self.dns_query_count),
            float(self.high_risk_event_count),
            float(len(self._pids)),
            float(len(self._dst_ips)),
            float(len(self._dst_ports)),
            float(self.cmd_process_count),
            float(self.suspicious_port_count),
        ]


# ---------------------------------------------------------------------------
# SysmonFeatureExtractor
# ---------------------------------------------------------------------------

class SysmonFeatureExtractor:
    """
    Accumulates Sysmon events into fixed-size time buckets and produces a
    (sequence_length, N_FEATURES) numpy array for LSTM inference.

    Parameters
    ----------
    bucket_seconds : int
        Width of each time bucket in seconds.  Default: 10.
    sequence_length : int
        Number of buckets per LSTM input window.  Default: 20.
        With bucket_seconds=10 this covers 200 seconds of history.
    """

    def __init__(
        self,
        bucket_seconds: int = 10,
        sequence_length: int = 20,
    ) -> None:
        self.bucket_seconds = bucket_seconds
        self.sequence_length = sequence_length

        # Rolling deque of completed bucket feature vectors
        self._completed: deque[list[float]] = deque(maxlen=sequence_length)

        # Active (current, incomplete) bucket
        self._current: _Bucket = _Bucket(start_time=time.time())

        logger.debug(
            f"SysmonFeatureExtractor: initialized — "
            f"bucket={bucket_seconds}s, sequence_length={sequence_length}, "
            f"n_features={N_FEATURES}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def push(self, event: dict) -> None:
        """
        Ingest one Sysmon event dict.
        Accepts both the new flat format from SysmonFileReader and the old
        nested format {"winlog": {"event_id": "1", "event_data": {...}}}.
        Updates the current bucket, and if the bucket interval has expired,
        finalises it and starts a new one.
        """
        # Check whether the current bucket has expired
        now = time.time()
        if now - self._current.start_time >= self.bucket_seconds:
            self._finalise_bucket(self._current)
            self._current = _Bucket(start_time=now)
            logger.debug(
                f"SysmonFeatureExtractor: bucket finalised — "
                f"completed={len(self._completed)}/{self.sequence_length}"
            )

        # Extract event fields — support new flat format AND old nested format
        if "event_id" in event:
            # New flat format from SysmonFileReader
            event_id = str(event.get("event_id", ""))
            pid      = str(event.get("pid", ""))
            image    = event.get("process", "")
            dst_ip   = event.get("dest_ip", "")
            dst_port = str(event.get("dest_port", ""))
        else:
            # Old nested format from SysmonWinEventReader / Winlogbeat NDJSON
            winlog   = event.get("winlog", event)
            event_id = str(winlog.get("event_id") or winlog.get("EventID") or "")
            data     = winlog.get("event_data", winlog.get("EventData", {}))
            pid      = str(data.get("ProcessId", data.get("SourceProcessId", "")))
            image    = data.get("Image", "")
            dst_ip   = data.get("DestinationIp", "")
            dst_port = str(data.get("DestinationPort", ""))

        if not event_id or event_id not in _EID_TO_FIELD:
            return

        b = self._current

        # Increment the primary counter for this event type
        field = _EID_TO_FIELD[event_id]
        setattr(b, field, getattr(b, field) + 1)

        # Extract PID for unique_process_count
        if pid:
            b._pids.add(pid)

        # Per-EventID enrichment
        if event_id == "1":
            # ProcessCreate — check for cmd/powershell
            basename = os.path.basename(image).lower() if image else ""
            if basename in _CMD_NAMES:
                b.cmd_process_count += 1

        elif event_id == "3":
            # NetworkConnect — track unique IPs, ports, suspicious ports
            if dst_ip:
                b._dst_ips.add(dst_ip)
            if dst_port:
                b._dst_ports.add(dst_port)
                if dst_port in _SUSPICIOUS_PORTS:
                    b.suspicious_port_count += 1

    def get_sequence(self) -> Optional[np.ndarray]:
        """
        Return the current rolling window as a numpy array of shape
        (sequence_length, N_FEATURES), or None if fewer than sequence_length
        complete buckets have been accumulated.

        The returned array is a fresh copy — safe to modify/normalise downstream.
        """
        if len(self._completed) < self.sequence_length:
            logger.debug(
                f"SysmonFeatureExtractor: not enough buckets yet "
                f"({len(self._completed)}/{self.sequence_length})"
            )
            return None

        matrix = np.array(list(self._completed), dtype=np.float32)
        # shape: (sequence_length, N_FEATURES)
        return matrix

    def reset(self) -> None:
        """Clear all accumulated data and start fresh."""
        self._completed.clear()
        self._current = _Bucket(start_time=time.time())
        logger.debug("SysmonFeatureExtractor: reset")

    @property
    def buckets_collected(self) -> int:
        """Number of completed buckets in the rolling window."""
        return len(self._completed)

    @property
    def is_ready(self) -> bool:
        """True when get_sequence() will return a full matrix."""
        return len(self._completed) >= self.sequence_length

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _finalise_bucket(self, bucket: _Bucket) -> None:
        """Move a completed bucket into the rolling deque."""
        vec = bucket.to_feature_vector()
        self._completed.append(vec)
        logger.debug(
            f"SysmonFeatureExtractor: bucket pushed — vec={[f'{v:.0f}' for v in vec]}"
        )


# ---------------------------------------------------------------------------
# Standalone test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        stream=sys.stdout,
    )

    # Feed some synthetic events to verify feature extraction
    extractor = SysmonFeatureExtractor(bucket_seconds=2, sequence_length=3)

    _test_events = [
        {"winlog": {"event_id": "1", "event_data": {"Image": "C:\\Windows\\cmd.exe", "ProcessId": "100"}}},
        {"winlog": {"event_id": "3", "event_data": {"DestinationIp": "1.2.3.4", "DestinationPort": "4444", "ProcessId": "100"}}},
        {"winlog": {"event_id": "11", "event_data": {"TargetFilename": "C:\\temp\\file.txt", "ProcessId": "200"}}},
        {"winlog": {"event_id": "22", "event_data": {"QueryName": "evil.com", "ProcessId": "100"}}},
        {"winlog": {"event_id": "8",  "event_data": {"SourceProcessId": "100"}}},
    ]

    print("Feeding 5 test events per bucket for 3 buckets...")
    for bucket_num in range(4):
        for ev in _test_events:
            extractor.push(ev)
        print(f"Bucket {bucket_num+1} fed — waiting {extractor.bucket_seconds}s...")
        time.sleep(extractor.bucket_seconds)

    seq = extractor.get_sequence()
    if seq is not None:
        print(f"\nSequence shape: {seq.shape}")
        print("Feature names:", FEATURE_NAMES)
        print("Last bucket:", seq[-1].tolist())
    else:
        print("Sequence not ready yet — collect more buckets.")
