"""
Domain 2 — User Behavior Attack
Insider threat pattern against the real registered endpoint:
  Phase 1: Inject Winlogbeat events (bulk file access + failed logons)
  Phase 2: Trigger model inference
  Phase 3: Guaranteed HIGH alert on the real host
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
    host   = ep["hostname"]
    src_ip = ep["ip_address"]

    import os
    username = os.getenv("USERNAME", "DELL")

    print(f"\n{R}{B}{'─'*58}")
    print(f"  DOMAIN 2 — USER BEHAVIOR ATTACK")
    print(f"  Target endpoint : {host}  ({src_ip})")
    print(f"  User            : {username}")
    print(f"  Insider threat: after-hours bulk file exfil + failed logons")
    print(f"{'─'*58}{X}\n")

    # Phase 1 — Inject suspicious Winlogbeat events for the real user
    print(f"{Y}[1/3] Injecting insider-threat activity for {username}...{X}")
    r1 = _post("/simulate-user-attack", {
        "file_creates":  800,
        "file_reads":   1200,
        "failed_logons":  45,
        "username":     username,
    })
    if "error" in r1:
        print(f"  {Y}! simulate-user-attack: {r1}{X}")
    else:
        print(f"  → Events written: {r1.get('events_written','?')}  "
              f"file={str(r1.get('log_file','?'))[:55]}")

    time.sleep(2)

    # Phase 2 — Trigger immediate inference
    print(f"{Y}[2/3] Running user behavior model inference...{X}")
    r2 = _post("/predict/user", {"lookback_minutes": 5, "threshold_override": 0.30})
    if "error" in r2:
        print(f"  {Y}! predict/user: {r2}{X}")
    else:
        anomalies = sum(1 for u in r2.get("users", []) if u.get("is_anomalous"))
        print(f"  → Users evaluated: {r2.get('users_evaluated','?')}  anomalies={anomalies}")

    time.sleep(1)

    # Phase 3 — Guaranteed HIGH on the real host
    print(f"{Y}[3/3] Firing HIGH insider-threat alert on {host}...{X}")
    r3 = _post("/demo/inject", {
        "attack_type":   "Insider Threat — Bulk Exfiltration",
        "network_score": 0.20,
        "user_score":    0.95,
        "system_score":  0.25,
        "malware_score": 0.15,
        "host":          host,
        "hostname":      host,
        "src_ip":        src_ip,
        "endpoint_id":   ep["endpoint_id"],
    })
    sev = r3.get("severity", "?")
    col = R if sev in ("CRITICAL", "HIGH") else Y
    print(f"  {col}→ {sev}  score={r3.get('score','?')}  attack={r3.get('attack_type','?')}{X}")
    print(f"\n{G}✓ Domain 2 complete — check User Behavior panel on dashboard{X}\n")
