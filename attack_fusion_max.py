"""
Max-Impact Fusion Injection
Fires 3 combined-scenario CRITICAL alerts against the real registered endpoint.
Used by run_demo.py option 5 (ALL DOMAINS simultaneous).
"""
import time
import requests
import config as _cfg

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; M = "\033[95m"; B = "\033[1m"; X = "\033[0m"

_SCENARIOS = [
    {
        "attack_type":   "Advanced Persistent Threat (APT)",
        "network_score": 0.97,
        "user_score":    0.95,
        "system_score":  0.93,
        "malware_score": 0.96,
    },
    {
        "attack_type":   "Ransomware + Lateral Movement",
        "network_score": 0.92,
        "user_score":    0.88,
        "system_score":  0.98,
        "malware_score": 0.97,
    },
    {
        "attack_type":   "C2 Beaconing + Insider Exfiltration",
        "network_score": 0.95,
        "user_score":    0.96,
        "system_score":  0.70,
        "malware_score": 0.85,
    },
]


def _post(endpoint: str, body: dict) -> dict:
    try:
        r = requests.post(f"{_cfg.BACKEND_URL}{endpoint}",
                          json=body, headers=_cfg.HEADERS, timeout=15)
        return r.json() if r.ok else {"error": r.status_code, "detail": r.text[:120]}
    except Exception as e:
        return {"error": str(e)}


def run() -> None:
    ep = _cfg.get_real_endpoint()
    host   = ep["hostname"]
    src_ip = ep["ip_address"]

    print(f"\n{M}{B}{'═'*58}")
    print(f"  MAX-IMPACT FUSION — {len(_SCENARIOS)} CRITICAL SCENARIOS")
    print(f"  Target endpoint : {host}  ({src_ip})")
    print(f"  All 4 models ≥0.85 → CRITICAL + SOAR auto-execute")
    print(f"{'═'*58}{X}\n")

    for i, scenario in enumerate(_SCENARIOS, 1):
        body = {
            **scenario,
            "host":        host,
            "hostname":    host,
            "src_ip":      src_ip,
            "endpoint_id": ep["endpoint_id"],
        }
        print(f"{M}[{i}/{len(_SCENARIOS)}] {B}{scenario['attack_type']}{X}")
        r = _post("/demo/inject", body)
        sev   = r.get("severity", "?")
        score = r.get("score", "?")
        col = R if sev == "CRITICAL" else Y
        print(f"  {col}→ {sev}  score={score}  "
              f"SOAR={'triggered' if sev == 'CRITICAL' else 'standby'}{X}")
        if i < len(_SCENARIOS):
            time.sleep(3)

    print(f"\n{R}{B}{'═'*58}")
    print(f"  ALL {len(_SCENARIOS)} SCENARIOS INJECTED ON {host}")
    print(f"  • Alert Stream  → {len(_SCENARIOS)} CRITICAL rows")
    print(f"  • Response Modal → Respond button on each row")
    print(f"  • Attack Graph  → Multi-node cluster on {host}")
    print(f"  • Endpoint Grid → {host} card shows CRITICAL glow")
    print(f"{'═'*58}{X}\n")
