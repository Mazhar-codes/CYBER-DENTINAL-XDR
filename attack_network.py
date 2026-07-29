"""
Domain 1 — Network Attack
Multi-phase network attack against the real registered endpoint:
  Phase 1: Horizontal port scan (18 ports) → /predict/network
  Phase 2: C2 beaconing flow (port 4444)   → /predict/network
  Phase 3: Guaranteed CRITICAL alert        → /demo/inject (real host)
"""
import time
import requests
import config as _cfg

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"; B = "\033[1m"; X = "\033[0m"

_SCAN_PORTS = [22, 23, 25, 80, 110, 135, 139, 143, 443, 445,
               1433, 3306, 3389, 5900, 8080, 8443, 9200, 27017]

_BASE_FLOW = {
    "Destination Port": 445,
    "Flow Duration": 2000,
    "Total Fwd Packets": 1,
    "Total Backward Packets": 0,
    "Total Length of Fwd Packets": 44,
    "Total Length of Bwd Packets": 0,
    "Fwd Packet Length Max": 44, "Fwd Packet Length Min": 44,
    "Fwd Packet Length Mean": 44.0, "Fwd Packet Length Std": 0.0,
    "Bwd Packet Length Max": 0, "Bwd Packet Length Min": 0,
    "Bwd Packet Length Mean": 0.0, "Bwd Packet Length Std": 0.0,
    "Flow Bytes/s": 22000.0, "Flow Packets/s": 500.0,
    "Flow IAT Mean": 2000.0, "Flow IAT Std": 0.0,
    "Flow IAT Max": 2000.0, "Flow IAT Min": 2000.0,
    "Fwd IAT Total": 0.0, "Fwd IAT Mean": 0.0, "Fwd IAT Std": 0.0,
    "Fwd IAT Max": 0.0, "Fwd IAT Min": 0.0,
    "Bwd IAT Total": 0.0, "Bwd IAT Mean": 0.0, "Bwd IAT Std": 0.0,
    "Bwd IAT Max": 0.0, "Bwd IAT Min": 0.0,
    "Fwd PSH Flags": 0, "Bwd PSH Flags": 0,
    "Fwd URG Flags": 0, "Bwd URG Flags": 0,
    "Fwd Header Length": 0, "Bwd Header Length": 0,
    "Fwd Packets/s": 500.0, "Bwd Packets/s": 0.0,
    "Min Packet Length": 44, "Max Packet Length": 44,
    "Packet Length Mean": 44.0, "Packet Length Std": 0.0,
    "Packet Length Variance": 0.0,
    "FIN Flag Count": 0, "SYN Flag Count": 1, "RST Flag Count": 1,
    "PSH Flag Count": 0, "ACK Flag Count": 0,
    "URG Flag Count": 0, "CWE Flag Count": 0, "ECE Flag Count": 0,
    "Down/Up Ratio": 0.0, "Average Packet Size": 44.0,
    "Avg Fwd Segment Size": 44.0, "Avg Bwd Segment Size": 0.0,
    "Fwd Header Length.1": 0,
    "Fwd Avg Bytes/Bulk": 0.0, "Fwd Avg Packets/Bulk": 0.0, "Fwd Avg Bulk Rate": 0.0,
    "Bwd Avg Bytes/Bulk": 0.0, "Bwd Avg Packets/Bulk": 0.0, "Bwd Avg Bulk Rate": 0.0,
    "Subflow Fwd Packets": 1, "Subflow Fwd Bytes": 44,
    "Subflow Bwd Packets": 0, "Subflow Bwd Bytes": 0,
}

_C2_FLOW = {**_BASE_FLOW,
    "Destination Port": 4444,
    "Flow Duration": 300_000_000,
    "Total Fwd Packets": 180, "Total Backward Packets": 175,
    "Total Length of Fwd Packets": 25200, "Total Length of Bwd Packets": 24500,
    "Flow Bytes/s": 330.0, "Flow Packets/s": 1.17,
    "Flow IAT Mean": 10_000_000.0, "Flow IAT Std": 500_000.0,
    "SYN Flag Count": 1, "RST Flag Count": 0, "ACK Flag Count": 355,
}


def _post(endpoint: str, body: dict) -> dict:
    try:
        r = requests.post(f"{_cfg.BACKEND_URL}{endpoint}",
                          json=body, headers=_cfg.HEADERS, timeout=10)
        return r.json() if r.ok else {"error": r.status_code, "detail": r.text[:120]}
    except Exception as e:
        return {"error": str(e)}


def run() -> None:
    ep = _cfg.get_real_endpoint()
    host     = ep["hostname"]
    src_ip   = ep["ip_address"]

    print(f"\n{R}{B}{'─'*58}")
    print(f"  DOMAIN 1 — NETWORK ATTACK")
    print(f"  Target endpoint : {host}  ({src_ip})")
    print(f"  Phase 1: Horizontal port scan ({len(_SCAN_PORTS)} ports)")
    print(f"  Phase 2: C2 beaconing on port 4444")
    print(f"  Phase 3: CRITICAL fusion alert on real host")
    print(f"{'─'*58}{X}\n")

    # Phase 1 — Port scan
    print(f"{Y}[1/3] Injecting port scan flows...{X}")
    scan_flows = [{**_BASE_FLOW, "Destination Port": p} for p in _SCAN_PORTS]
    r1 = _post("/predict/network", {"flows": scan_flows})
    print(f"  → ML result: attack_type={r1.get('attack_type', r1.get('prediction', '?'))}  "
          f"score={r1.get('anomaly_score', r1.get('score', '?'))}")

    time.sleep(1)

    # Phase 2 — C2 beacon
    print(f"{Y}[2/3] Injecting C2 beaconing flow (port 4444)...{X}")
    r2 = _post("/predict/network", {"flows": [_C2_FLOW]})
    print(f"  → ML result: {r2.get('attack_type', r2.get('prediction', '?'))}  "
          f"score={r2.get('anomaly_score', '?')}")

    time.sleep(1)

    # Phase 3 — Guaranteed CRITICAL on the real host
    print(f"{Y}[3/3] Firing CRITICAL alert on {host}...{X}")
    r3 = _post("/demo/inject", {
        "attack_type":   "PortScan + C2 Beaconing",
        "network_score": 0.97,
        "user_score":    0.30,
        "system_score":  0.20,
        "malware_score": 0.25,
        "host":          host,
        "hostname":      host,
        "src_ip":        src_ip,
        "endpoint_id":   ep["endpoint_id"],
    })
    sev = r3.get("severity", "?")
    col = R if sev == "CRITICAL" else Y
    print(f"  {col}→ {sev}  score={r3.get('score','?')}  attack={r3.get('attack_type','?')}{X}")
    print(f"\n{G}✓ Domain 1 complete — check Alert Stream on dashboard{X}\n")
