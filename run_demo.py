#!/usr/bin/env python3
"""
Cyber Sentinel XDR — Attack Demonstration Runner
=================================================
Interactive menu with live Socket.IO alert feed.
Launches each domain attack and shows real-time XDR detections in terminal.

Usage:
  python run_demo.py
  python run_demo.py --backend http://192.168.1.10:8000 --api-key YOUR_KEY

Requirements (install if missing):
  pip install requests "python-socketio[client]" websocket-client
"""

import os, sys, time, threading, argparse, importlib, traceback
sys.path.insert(0, os.path.dirname(__file__))
import config as _cfg

# ── ANSI colour helpers ────────────────────────────────────────────────────────
R = "\033[91m"; G = "\033[92m"; Y = "\033[93m"; C = "\033[96m"
M = "\033[95m"; B = "\033[1m"; DIM = "\033[2m"; X = "\033[0m"

BANNER = f"""{B}{R}
╔══════════════════════════════════════════════════════════════════╗
║          CYBER SENTINEL XDR  ·  ATTACK DEMONSTRATION SUITE      ║
║   Tests all 4 detection domains against your live XDR server    ║
╚══════════════════════════════════════════════════════════════════╝{X}"""

MENU = f"""
{B}Select attack:{X}
  {R}[1]{X} Domain 1 — {B}Network{X}        Port Scan · C2 Connections · API Injection
  {R}[2]{X} Domain 2 — {B}User Behavior{X}  After-hours · Concurrent Sessions · Fusion Injection
  {R}[3]{X} Domain 3 — {B}System Monitor{X} CPU 100% + Memory Pressure → CRITICAL
  {R}[4]{X} Domain 4 — {B}Malware{X}        Packed PE · Crypto imports · EMBER vector injection
  {R}[5]{X} {B}ALL DOMAINS{X}              Simultaneous + Max-impact fusion → CRITICAL
  {Y}[p]{X} Pre-flight check
  {C}[c]{X} Clear dashboard    Removes old demo data so the board starts clean
  {Y}[0]{X} Exit
"""

_alert_log:   list  = []
_sio_client          = None
_sio_connected: bool = False


# ── Socket.IO live monitor ─────────────────────────────────────────────────────

def _start_monitor() -> None:
    """Background thread: connect to XDR server and print incoming alerts."""
    global _sio_client, _sio_connected
    try:
        import socketio as sio_lib
    except ImportError:
        print(f"\n{Y}[MONITOR] python-socketio not installed — live feed disabled{X}")
        print(f"{Y}  Install: pip install \"python-socketio[client]\" websocket-client{X}\n")
        return

    sio = sio_lib.Client(logger=False, engineio_logger=False)
    _sio_client = sio

    @sio.event
    def connect():
        global _sio_connected
        _sio_connected = True
        print(f"\n{G}[MONITOR] ✓ Connected to {_cfg.BACKEND_URL} — live alert feed active{X}\n")

    @sio.event
    def disconnect():
        global _sio_connected
        _sio_connected = False

    def _show(domain: str, data: dict) -> None:
        sev = str(
            data.get("severity") or data.get("label") or data.get("attack_type") or "?"
        ).upper()
        col = R if sev in ("CRITICAL", "HIGH", "MALICIOUS") else (Y if sev == "SUSPICIOUS" else G)
        _alert_log.append((domain, sev))
        # Print the alert clearly — visible while user is reading the menu
        print(f"\n{col}{'━'*62}")
        print(f"  ⚡  XDR DETECTED — {domain}")
        _fields = ["threat_type","attack_type","label","anomaly_score",
                   "threat_score","source","reason","hostname"]
        parts = "  ".join(f"{k}={data[k]!r}" for k in _fields if k in data)[:80]
        print(f"  {parts or str(data)[:80]}")
        print(f"  severity={sev}")
        print(f"{'━'*62}{X}")

    for evt in [
        "network_anomaly", "user_anomaly", "system_anomaly",
        "malware_alert", "malware_scan", "sysmon_alert",
        "fusion_alert", "endpoint_alert", "endpoint_update",
        "command_queued", "command_result", "response_required",
        "response_plan_ready", "response_executed",
    ]:
        sio.on(evt, lambda data, e=evt: _show(e, data if isinstance(data, dict) else {"raw": str(data)}))

    try:
        sio.connect(_cfg.BACKEND_URL, transports=["websocket", "polling"])
        sio.wait()
    except Exception as exc:
        print(f"{Y}[MONITOR] Socket.IO error: {exc}{X}")


# ── Pre-flight check ──────────────────────────────────────────────────────────

def preflight() -> None:
    print(f"\n{B}{'─'*50}\n  Pre-flight Checks\n{'─'*50}{X}")

    # Backend reachability
    try:
        import requests
        r = requests.get(f"{_cfg.BACKEND_URL}/health", headers=_cfg.HEADERS, timeout=5)
        if r.status_code == 200:
            h = r.json()
            print(f"{G}  ✓ Backend REACHABLE at {_cfg.BACKEND_URL}{X}")
            print(f"{C}    mongo={h.get('mongo','?')}  "
                  f"network_model={h.get('network_model','?')}  "
                  f"malware_model={h.get('malware_model','?')}{X}")
        else:
            print(f"{Y}  ! Backend HTTP {r.status_code}{X}")
    except ImportError:
        print(f"{Y}  ! requests not installed — pip install requests{X}")
    except Exception as exc:
        print(f"{R}  ✗ Backend UNREACHABLE: {exc}{X}")
        print(f"{Y}    Start: cd Backend && uvicorn backend:sio_app --host 0.0.0.0 --port 8000{X}")

    # Endpoint agent running?
    try:
        import subprocess
        out = subprocess.run(
            ["powershell", "-Command",
             "Get-Process python -ErrorAction SilentlyContinue | "
             "Where-Object {$_.MainWindowTitle -like '*agent*' -or "
             "$_.Path -like '*agent*'} | Measure-Object | Select-Object -ExpandProperty Count"],
            capture_output=True, text=True, timeout=5
        ).stdout.strip()
        count = int(out) if out.isdigit() else 0
        if count > 0:
            print(f"{G}  ✓ Endpoint agent appears to be running ({count} python proc(s)){X}")
        else:
            print(f"{Y}  ! Endpoint agent not detected — system/malware real-behavior tests{X}")
            print(f"{Y}    may not report via telemetry path.{X}")
            print(f"{Y}    Start: cd endpoint_agent && python agent.py{X}")
    except Exception:
        pass

    # Suricata eve.json
    eve = r"C:\SuricataLogs\eve.json"
    if os.path.exists(eve):
        kb = os.path.getsize(eve) // 1024
        print(f"{G}  ✓ Suricata eve.json present ({kb} KB) — network rule detection active{X}")
    else:
        print(f"{Y}  ! Suricata eve.json not found at {eve}{X}")
        print(f"{Y}    API injection fallback will be used for network domain{X}")

    # psutil installed?
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.3)
        mem = psutil.virtual_memory().percent
        print(f"{G}  ✓ psutil available — current cpu={cpu:.1f}% mem={mem:.1f}%{X}")
    except ImportError:
        print(f"{Y}  ! psutil not installed — system stress test may be limited{X}")

    print(f"\n{C}  Backend URL : {_cfg.BACKEND_URL}")
    print(f"  API Key     : {_cfg.API_KEY[:12]}...")
    print(f"  Socket.IO   : {'connected' if _sio_connected else 'connecting...'}")
    print(f"  Alerts seen : {len(_alert_log)}{X}\n")


# ── Dashboard cleanup ─────────────────────────────────────────────────────────

def _cleanup_dashboard() -> None:
    """Call POST /demo/cleanup to remove old demo data from MongoDB."""
    print(f"\n{C}{B}{'─'*58}")
    print(f"  CLEARING DASHBOARD DATA")
    print(f"  Removes phantom endpoints, stale alerts, old attack graph nodes")
    print(f"{'─'*58}{X}\n")
    try:
        import requests
        r = requests.post(
            f"{_cfg.BACKEND_URL}/demo/cleanup",
            headers=_cfg.HEADERS,
            timeout=15,
        )
        if r.ok:
            data = r.json()
            removed = data.get("removed", {})
            print(f"{G}  ✓ Cleanup complete{X}")
            for col, count in removed.items():
                if count:
                    print(f"  {Y}  • {col}: {count} document(s) removed{X}")
            if not any(removed.values()):
                print(f"{C}  Nothing to remove — dashboard was already clean{X}")
            print(f"\n{C}  Dashboard re-fetching endpoint list automatically...{X}")
        else:
            print(f"{R}  ✗ Cleanup failed: HTTP {r.status_code}{X}")
            print(f"  {r.text[:120]}")
    except Exception as exc:
        print(f"{R}  ✗ Error: {exc}{X}")
    print()


# ── Domain runner ─────────────────────────────────────────────────────────────

_MODULE_MAP = {
    1: "attack_network",
    2: "attack_user",
    3: "attack_system",
    4: "attack_malware",
}


def _run_module(n: int) -> None:
    mod_name = _MODULE_MAP.get(n)
    if not mod_name:
        return
    try:
        mod = importlib.import_module(mod_name)
        importlib.reload(mod)   # allow repeated runs without restart
        mod.run()
    except Exception:
        print(f"{R}Error running {mod_name}:{X}")
        traceback.print_exc()


def run_all() -> None:
    """Launch all 4 domains simultaneously, then fire max-impact fusion."""
    print(f"\n{B}{R}{'='*62}")
    print(f"  COMBINED ATTACK — ALL 4 DOMAINS SIMULTANEOUSLY")
    print(f"  Fusion target: ≥ 0.85 → CRITICAL → SOAR auto-execute")
    print(f"{'='*62}{X}\n")

    threads = []
    for n in _MODULE_MAP:
        t = threading.Thread(target=_run_module, args=(n,), name=f"domain-{n}", daemon=True)
        threads.append(t)

    print(f"{Y}Launching all 4 domain attacks...{X}")
    for t in threads:
        t.start()
        time.sleep(1.5)   # stagger so terminal output is readable

    # After 12s (enough for real attacks to start), fire max-impact fusion injection
    time.sleep(12)
    print(f"\n{B}{M}[FUSION] Firing max-impact combined fusion injection...{X}")
    try:
        import attack_fusion_max
        importlib.reload(attack_fusion_max)
        attack_fusion_max.run()
    except Exception:
        traceback.print_exc()

    for t in threads:
        t.join(timeout=120)

    print(f"\n{G}{B}Combined attack complete!{X}")
    print(f"{C}Total XDR alerts received during demo: {len(_alert_log)}{X}")
    for evt, sev in _alert_log[-15:]:
        col = R if sev in ("CRITICAL","HIGH","MALICIOUS") else Y
        print(f"  {col}● {evt}: {sev}{X}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(description="Cyber Sentinel XDR Demo Runner")
    parser.add_argument("--backend", default="", help="Override backend URL")
    parser.add_argument("--api-key", default="", help="Override API key")
    args = parser.parse_args()

    if args.backend:
        _cfg.BACKEND_URL = args.backend
    if args.api_key:
        _cfg.API_KEY = args.api_key
        _cfg.HEADERS = {"X-API-Key": _cfg.API_KEY, "Content-Type": "application/json"}

    print(BANNER)
    print(f"{C}Backend : {_cfg.BACKEND_URL}")
    print(f"API Key : {_cfg.API_KEY[:12]}...{X}\n")

    # Enable ANSI on Windows
    try:
        import ctypes
        ctypes.windll.kernel32.SetConsoleMode(
            ctypes.windll.kernel32.GetStdHandle(-11), 7
        )
    except Exception:
        pass

    # Start live alert monitor in background
    monitor = threading.Thread(target=_start_monitor, daemon=True, name="sio-monitor")
    monitor.start()
    time.sleep(2)   # Give Socket.IO time to connect

    while True:
        print(MENU)
        if _sio_connected:
            print(f"{G}  [Socket.IO: CONNECTED — live alerts will appear here]{X}\n")
        else:
            print(f"{Y}  [Socket.IO: connecting to {_cfg.BACKEND_URL}...]{X}\n")

        try:
            choice = input(f"{B}Enter choice > {X}").strip().lower()
        except (KeyboardInterrupt, EOFError):
            break

        if   choice == "0": break
        elif choice == "1": _run_module(1)
        elif choice == "2": _run_module(2)
        elif choice == "3": _run_module(3)
        elif choice == "4": _run_module(4)
        elif choice == "5": run_all()
        elif choice == "p": preflight()
        elif choice == "c": _cleanup_dashboard()
        else:
            print(f"{Y}Invalid — enter 0–5, p, or c{X}")

    # Clean up Socket.IO
    if _sio_client:
        try: _sio_client.disconnect()
        except Exception: pass

    print(f"\n{G}Session ended. Total XDR alerts detected: {len(_alert_log)}{X}")


if __name__ == "__main__":
    main()
