"""
Domain 3 — System Monitor Attack
Ransomware resource pressure against the real registered endpoint:
  Phase 1: 3 × /endpoint/ingest bursts with real endpoint_id + extreme CPU/mem
  Phase 2: Guaranteed CRITICAL alert on the real host
"""
import time
import requests
import config as _cfg

R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; B = "\033[1m"; X = "\033[0m"


def _post(endpoint: str, body: dict) -> dict:
    try:
        r = requests.post(f"{_cfg.BACKEND_URL}{endpoint}",
                          json=body, headers=_cfg.HEADERS, timeout=15)
        return r.json() if r.ok else {"error": r.status_code, "detail": r.text[:120]}
    except Exception as e:
        return {"error": str(e)}


def run() -> None:
    ep = _cfg.get_real_endpoint()
    endpoint_id = ep["endpoint_id"]
    host        = ep["hostname"]
    src_ip      = ep["ip_address"]

    print(f"\n{R}{B}{'─'*58}")
    print(f"  DOMAIN 3 — SYSTEM MONITOR ATTACK")
    print(f"  Target endpoint : {host}  ({src_ip})")
    print(f"  Endpoint ID     : {endpoint_id}")
    print(f"  Ransomware profile: CPU 100%%, memory 94%%, suspicious processes")
    print(f"{'─'*58}{X}\n")

    # Phase 1 — 3 bursts of extreme system telemetry on the real endpoint
    print(f"{Y}[1/2] Sending ransomware-profile telemetry bursts to {host}...{X}")
    for i in range(3):
        payload = {
            "endpoint": {
                "endpoint_id": endpoint_id,
                "hostname":    host,
                "ip_address":  src_ip,
                "os":          "Windows 11",
                "username":    "DELL",
                "agent_version": "1.0.0",
            },
            "system": {
                "cpu_percent":    99.8,
                "memory_percent": 94.2,
                "disk_percent":   88.5,
                "process_count":  312,
                "top_processes": [
                    {"name": "vssadmin.exe", "cpu": 38.4, "memory": 1_800_000_000},
                    {"name": "wmic.exe",     "cpu": 12.1, "memory":   450_000_000},
                    {"name": "cmd.exe",      "cpu":  8.7, "memory":   200_000_000},
                    {"name": "powershell.exe","cpu":  5.3, "memory":    80_000_000},
                ],
            },
            "malware": {
                "suspicious_processes": [
                    {
                        "name":          "vssadmin.exe",
                        "pid":           4488,
                        "path":          "C:\\Windows\\System32\\vssadmin.exe",
                        "cmdline":       "vssadmin delete shadows /all /quiet",
                        "is_suspicious": True,
                    }
                ],
            },
            "network":  {},
            "user":     {"current_user": "DELL", "sessions": []},
        }
        r = _post("/endpoint/ingest", payload)
        status = r.get("status", r.get("error", "?"))
        print(f"  Burst {i+1}/3 → {status}")
        if i < 2:
            time.sleep(2)   # rate-limit is 1 req/2s per endpoint_id

    time.sleep(1)

    # Phase 2 — Guaranteed CRITICAL on the real host
    print(f"\n{Y}[2/2] Firing CRITICAL ransomware alert on {host}...{X}")
    r2 = _post("/demo/inject", {
        "attack_type":   "Ransomware Behavior",
        "network_score": 0.35,
        "user_score":    0.40,
        "system_score":  0.98,
        "malware_score": 0.92,
        "host":          host,
        "hostname":      host,
        "src_ip":        src_ip,
        "endpoint_id":   endpoint_id,
    })
    sev = r2.get("severity", "?")
    col = R if sev == "CRITICAL" else Y
    print(f"  {col}→ {sev}  score={r2.get('score','?')}  attack={r2.get('attack_type','?')}{X}")
    print(f"\n{G}✓ Domain 3 complete — check System Monitor + Fusion alerts on dashboard{X}\n")
