# collect_baseline.py
# Run this for 30–60 minutes while doing NORMAL activities:
# browsing, YouTube, Teams calls, downloads — whatever is normal FOR YOU.
# It captures traffic, runs Suricata, extracts CIC-style flow features, saves to CSV.
# Run: python collect_baseline.py

import json
import logging
import os
import subprocess
from datetime import datetime

import numpy as np
import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")

# ── CONFIG ───────────────────────────────────────────────────────────────────
TSHARK_EXE = r"C:\Program Files\Wireshark\tshark.exe"
SURICATA_EXE = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_YAML = r"C:\Program Files\Suricata\suricata.yaml"
CAPTURE_DIR = r"C:\SuricataLogs\baseline"
OUTPUT_CSV = r"D:\Cyber Sentinal\Backend\personal_baseline.csv"
CAPTURE_INTERFACE = r"\Device\NPF_{B5A75558-6CB6-473B-B521-5B390F7ADE47}"
CAPTURE_SECONDS = 60  # capture window per cycle
TOTAL_CYCLES = 30  # 30 cycles x 60s = 30 minutes (increase for more data)

os.makedirs(CAPTURE_DIR, exist_ok=True)


# ── FEATURE EXTRACTION ───────────────────────────────────────────────────────
def extract_features(eve_path: str) -> list:
  """Extract CIC-like flow features from a Suricata eve.json file."""
  if not os.path.exists(eve_path):
    return []

  flows = []
  with open(eve_path, "r", encoding="utf-8", errors="ignore") as f:
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
      # Skip IPv6 link-local and multicast
      if src.startswith("fe80:") or src.startswith("ff02:"):
        continue

      flow = ev.get("flow", {})
      tcp = ev.get("tcp", {})
      dest_port = ev.get("dest_port", 0)

      pkts_fwd = float(flow.get("pkts_toserver", 0) or 0)
      pkts_bwd = float(flow.get("pkts_toclient", 0) or 0)
      bytes_fwd = float(flow.get("bytes_toserver", 0) or 0)
      bytes_bwd = float(flow.get("bytes_toclient", 0) or 0)
      duration = max(float(flow.get("age", 0) or 0), 0.000001)

      total_pkts = pkts_fwd + pkts_bwd
      total_bytes = bytes_fwd + bytes_bwd
      pkt_len_mean = total_bytes / max(total_pkts, 1.0)

      # Per-direction mean packet lengths (used in several approximations below)
      fwd_pkt_len_mean = bytes_fwd / max(pkts_fwd, 1.0)
      bwd_pkt_len_mean = bytes_bwd / max(pkts_bwd, 1.0)

      # ── Statistical approximations for features unavailable from eve.json ──
      #
      # Suricata only reports per-flow aggregate byte/packet counts and the
      # flow age (duration).  The CIC-IDS2017 features that require per-packet
      # observations (length variance, IAT jitter, etc.) cannot be computed
      # exactly.  The approximations below use coefficient-of-variation
      # heuristics that hold reasonably for real TCP flows:
      #
      #   std ≈ mean * 0.5  (CV=0.5 is typical for mixed HTTP/stream traffic)
      #   min ≈ mean * 0.1  (ACK-only / header packets push the minimum down)
      #
      # These are biased estimates, not exact values.  They keep the feature
      # columns in a plausible range so the trained scaler does not receive
      # hard zeros for every statistical moment, which would distort the
      # IsolationForest anomaly score and the RandomForest classifier.

      # Packet-length estimates (microseconds not involved here)
      fwd_pkt_len_std = fwd_pkt_len_mean * 0.5
      fwd_pkt_len_min = max(40.0, fwd_pkt_len_mean * 0.1)   # TCP header floor ~40 B

      bwd_pkt_len_std = bwd_pkt_len_mean * 0.5
      bwd_pkt_len_min = max(40.0, bwd_pkt_len_mean * 0.1)

      pkt_len_std = pkt_len_mean * 0.5
      pkt_len_var = pkt_len_std ** 2                         # variance = std^2
      min_pkt_len = min(fwd_pkt_len_min, bwd_pkt_len_min)

      # IAT estimates (converted to microseconds to match CIC convention)
      flow_iat_mean_us = duration / max(total_pkts, 1.0) * 1_000_000
      flow_iat_std  = flow_iat_mean_us * 0.5
      flow_iat_min  = flow_iat_mean_us * 0.1                 # burst floor

      fwd_iat_mean_us = duration / max(pkts_fwd, 1.0) * 1_000_000
      fwd_iat_std = fwd_iat_mean_us * 0.5

      bwd_iat_mean_us = duration / max(pkts_bwd, 1.0) * 1_000_000
      bwd_iat_std = bwd_iat_mean_us * 0.5

      # Active-period std: a single captured flow has one contiguous activity
      # window (std≈0 exactly), but the scaler expects variance > 0.
      # Use 10% of the mean as a small non-zero estimate.
      active_mean_us = duration * 1_000_000
      active_std = active_mean_us * 0.1

      flows.append(
        {
          "Destination Port": float(dest_port),
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
          "Fwd PSH Flags": 1.0 if tcp.get("psh") else 0.0,
          "Fwd URG Flags": 1.0 if tcp.get("urg") else 0.0,
          "Fwd Header Length": 20.0,
          "Bwd Header Length": 20.0,
          "Fwd Packets/s": pkts_fwd / duration,
          "Bwd Packets/s": pkts_bwd / duration,
          "Min Packet Length": min_pkt_len,
          "Max Packet Length": max(bytes_fwd, bytes_bwd),
          "Packet Length Mean": pkt_len_mean,
          "Packet Length Std": pkt_len_std,
          "Packet Length Variance": pkt_len_var,
          "FIN Flag Count": 1.0 if tcp.get("fin") else 0.0,
          "SYN Flag Count": 1.0 if tcp.get("syn") else 0.0,
          "RST Flag Count": 1.0 if tcp.get("rst") else 0.0,
          "PSH Flag Count": 1.0 if tcp.get("psh") else 0.0,
          "ACK Flag Count": 1.0 if tcp.get("ack") else 0.0,
          "URG Flag Count": 1.0 if tcp.get("urg") else 0.0,
          "Down/Up Ratio": bytes_bwd / max(bytes_fwd, 1.0),
          "Average Packet Size": pkt_len_mean,
          "Avg Fwd Segment Size": fwd_pkt_len_mean,
          "Avg Bwd Segment Size": bwd_pkt_len_mean,
          "Subflow Fwd Packets": pkts_fwd,
          "Subflow Fwd Bytes": bytes_fwd,
          "Subflow Bwd Packets": pkts_bwd,
          "Subflow Bwd Bytes": bytes_bwd,
          "Init_Win_bytes_forward": float(tcp.get("tcp_window_size", 0) or 0),
          "Init_Win_bytes_backward": float(tcp.get("tcp_window_size", 0) or 0),
          "act_data_pkt_fwd": pkts_fwd,
          "min_seg_size_forward": 20.0,
          "Active Mean": active_mean_us,
          "Active Std": active_std,
          "Active Max": active_mean_us,
          "Active Min": active_mean_us,
          "Idle Mean": 0.0,
          "Idle Std": 0.0,
          "Idle Max": 0.0,
          "Idle Min": 0.0,
        }
      )
  return flows


# ── MAIN COLLECTION LOOP ──────────────────────────────────────────────────────
def main() -> None:
  all_flows: list[dict] = []
  print("=" * 60)
  print("BASELINE COLLECTION STARTED")
  print(
    f"Collecting {TOTAL_CYCLES} cycles × {CAPTURE_SECONDS}s = "
    f"{TOTAL_CYCLES * CAPTURE_SECONDS // 60} minutes of YOUR normal traffic"
  )
  print("\n👉 Do your normal activities: browse, stream YouTube, use Teams etc.")
  print("=" * 60)

  for cycle in range(1, TOTAL_CYCLES + 1):
    pcap_path = os.path.join(CAPTURE_DIR, f"baseline_{cycle}.pcap")
    suri_dir = os.path.join(CAPTURE_DIR, f"suri_{cycle}")
    os.makedirs(suri_dir, exist_ok=True)

    print(f"\n[{cycle}/{TOTAL_CYCLES}] Capturing {CAPTURE_SECONDS}s of traffic...")

    # tshark capture
    cmd = f'"{TSHARK_EXE}" -i "{CAPTURE_INTERFACE}" -a duration:{CAPTURE_SECONDS} -w "{pcap_path}"'
    subprocess.run(cmd, shell=True, capture_output=True)

    # Suricata analysis
    cmd = f'"{SURICATA_EXE}" -c "{SURICATA_YAML}" -r "{pcap_path}" -l "{suri_dir}" -k none'
    subprocess.run(cmd, shell=True, capture_output=True)

    # Extract features
    eve_path = os.path.join(suri_dir, "eve.json")
    flows = extract_features(eve_path)
    all_flows.extend(flows)
    print(f"  ✅ {len(flows)} flows extracted | Total so far: {len(all_flows)}")

    try:
      os.remove(pcap_path)
    except Exception:
      pass

  # Save to CSV
  if all_flows:
    df = pd.DataFrame(all_flows)
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    df.fillna(0, inplace=True)
    df.to_csv(OUTPUT_CSV, index=False)
    print(f"\n✅ Saved {len(df)} personal baseline flows to:\n   {OUTPUT_CSV}")
  else:
    print("\n❌ No flows collected — check tshark and Suricata paths")


if __name__ == "__main__":
  main()

