"""
Cyber Sentinel XDR -- Endpoint Agent GUI  (NEW C: copy)
Same auto-detect of Wi-Fi/Ethernet adapters + live status dashboard (Sysmon /
Suricata / Winlogbeat) + scrolling agent log as the E: original, but pointed at
the new C: copy's endpoint_agent package and its own .env (new API key).

Fix vs original: the agent is launched with the .env values injected into its
process environment (the agent reads config from os.environ only), so the new
XDR_API_KEY / XDR_BACKEND_URL reliably reach it.

Must run elevated (Sysmon install + Suricata capture need Administrator).
Built with `pyinstaller --uac-admin` so double-clicking the .exe prompts UAC.
"""
import json
import os
import queue
import re
import shutil
import subprocess
import sys
import threading
import time
import tkinter as tk
from datetime import datetime
from tkinter import messagebox, ttk

ROOT           = r"C:\Users\beeb9\Downloads\Compressed\New folder"
AGENT_DIR      = ROOT + r"\endpoint_agent"
ENV_FILE       = AGENT_DIR + r"\.env"
# Sysmon64.exe is Microsoft tooling shared machine-wide (not part of the repo);
# point at the existing install. Copy it into the new project if you want zero
# external references.
SYSMON_EXE     = r"E:\Cyber Sentinal Endpoint\Sysmon\Sysmon64.exe"
SYSMON_CONFIG  = AGENT_DIR + r"\config\sysmon_config.xml"
SURICATA_EXE   = r"C:\Program Files\Suricata\suricata.exe"
SURICATA_YAML  = r"C:\Program Files\Suricata\suricata.yaml"
SURICATA_LOGS  = r"C:\SuricataLogs\suricata_1"
DATA_DIR       = r"C:\ProgramData\CyberSentinel"

CREATE_NO_WINDOW = 0x08000000
# Prefer this copy's backend venv python, else fall back to system python.
_VENV_PY = ROOT + r"\Backend\venv\Scripts\python.exe"
PYTHON_EXE = _VENV_PY if os.path.isfile(_VENV_PY) else (
    shutil.which("python") or r"C:\Users\beeb9\AppData\Local\Programs\Python\Python311\python.exe"
)


# ---------------------------------------------------------------------------
# .env helpers
# ---------------------------------------------------------------------------

def read_env(path: str) -> dict:
    values = {}
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                m = re.match(r"^\s*([^#\s][^=]*?)\s*=\s*(.*)$", line)
                if m:
                    values[m.group(1).strip()] = m.group(2).strip().strip('"').strip("'")
    return values


def write_env(path: str, updates: dict) -> None:
    lines = []
    if os.path.isfile(path):
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    seen = set()
    out = []
    for line in lines:
        m = re.match(r"^\s*([^#\s][^=]*?)\s*=", line)
        if m and m.group(1).strip() in updates:
            key = m.group(1).strip()
            out.append(f"{key}={updates[key]}\n")
            seen.add(key)
        else:
            out.append(line)
    for key, val in updates.items():
        if key not in seen:
            out.append(f"{key}={val}\n")
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(out)


# ---------------------------------------------------------------------------
# Adapter detection
# ---------------------------------------------------------------------------

def list_adapters() -> list:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             "Get-NetAdapter | Select-Object Name,InterfaceDescription,InterfaceGuid,Status | ConvertTo-Json"],
            capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW,
        )
        data = json.loads(r.stdout)
        if isinstance(data, dict):
            data = [data]
        return data or []
    except Exception:
        return []


# ---------------------------------------------------------------------------
# Service / process status checks
# ---------------------------------------------------------------------------

def sc_running(service: str) -> bool:
    try:
        r = subprocess.run(
            ["sc.exe", "query", service], capture_output=True, text=True,
            timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        return "RUNNING" in r.stdout.upper()
    except Exception:
        return False


def process_running(exe_name: str) -> bool:
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH"],
            capture_output=True, text=True, timeout=10, creationflags=CREATE_NO_WINDOW,
        )
        return exe_name.lower() in r.stdout.lower()
    except Exception:
        return False


def suricata_running() -> bool:
    return process_running("suricata.exe")


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Sentinel XDR -- Endpoint Agent (New Copy)")
        self.geometry("760x640")
        self.configure(bg="#111827")

        self.agent_proc = None
        self.suricata_proc = None
        self.log_queue = queue.Queue()
        self.adapters = []

        env = read_env(ENV_FILE)
        self.backend_url_var = tk.StringVar(value=env.get("XDR_BACKEND_URL", "http://127.0.0.1:8000"))

        self._build_ui()
        self._refresh_adapters()
        self._poll_status()
        self._drain_log_queue()

    def _build_ui(self) -> None:
        FG, BG, ACCENT = "#e5e7eb", "#111827", "#1f2937"

        tk.Label(self, text="CYBER SENTINEL XDR", fg="#22d3ee", bg=BG,
                 font=("Segoe UI", 16, "bold")).pack(pady=(14, 0))
        tk.Label(self, text="Endpoint Agent - New Copy", fg=FG, bg=BG,
                 font=("Segoe UI", 10)).pack(pady=(0, 10))

        cfg = tk.Frame(self, bg=ACCENT)
        cfg.pack(fill="x", padx=16, pady=(0, 8))

        tk.Label(cfg, text="Backend URL:", fg=FG, bg=ACCENT, font=("Segoe UI", 9)).grid(row=0, column=0, sticky="w", padx=8, pady=8)
        tk.Entry(cfg, textvariable=self.backend_url_var, width=40).grid(row=0, column=1, sticky="w", padx=8, pady=8)

        tk.Label(cfg, text="Network adapter:", fg=FG, bg=ACCENT, font=("Segoe UI", 9)).grid(row=1, column=0, sticky="w", padx=8, pady=8)
        self.adapter_combo = ttk.Combobox(cfg, width=55, state="readonly")
        self.adapter_combo.grid(row=1, column=1, sticky="w", padx=8, pady=8)

        tk.Button(cfg, text="Refresh Adapters", command=self._refresh_adapters,
                  bg="#374151", fg="white", relief="flat").grid(row=1, column=2, padx=8)

        status = tk.Frame(self, bg=ACCENT)
        status.pack(fill="x", padx=16, pady=8)
        self.sysmon_dot = tk.Label(status, text="● Sysmon", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.sysmon_dot.pack(side="left", padx=14, pady=8)
        self.suricata_dot = tk.Label(status, text="● Suricata", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.suricata_dot.pack(side="left", padx=14, pady=8)
        self.winlogbeat_dot = tk.Label(status, text="● Winlogbeat", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.winlogbeat_dot.pack(side="left", padx=14, pady=8)
        self.agent_dot = tk.Label(status, text="● Agent", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.agent_dot.pack(side="left", padx=14, pady=8)

        btns = tk.Frame(self, bg=BG)
        btns.pack(fill="x", padx=16, pady=4)
        tk.Button(btns, text="Save Settings", command=self.save_settings,
                  bg="#374151", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), pady=8
                  ).grid(row=0, column=0, sticky="ew", padx=4)
        tk.Button(btns, text="Start Agent", command=self.start_agent,
                  bg="#16a34a", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), pady=8
                  ).grid(row=0, column=1, sticky="ew", padx=4)
        tk.Button(btns, text="Stop Agent", command=self.stop_agent,
                  bg="#dc2626", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), pady=8
                  ).grid(row=0, column=2, sticky="ew", padx=4)
        # Dedicated Suricata toggle -- Suricata is a background process (not a
        # service), so stopping the agent does not stop it. Label flips with status.
        self.suricata_btn = tk.Button(btns, text="Stop Suricata", command=self.toggle_suricata,
                  bg="#b45309", fg="white", relief="flat", font=("Segoe UI", 10, "bold"), pady=8)
        self.suricata_btn.grid(row=1, column=0, columnspan=3, sticky="ew", padx=4, pady=(6, 0))
        btns.grid_columnconfigure(0, weight=1)
        btns.grid_columnconfigure(1, weight=1)
        btns.grid_columnconfigure(2, weight=1)

        tk.Label(self, text="Live telemetry log (endpoint -> XDR server)", fg=FG, bg=BG,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(12, 2))
        self.log = tk.Text(self, height=20, bg="#0b1220", fg="#9ca3af",
                           insertbackground="white", font=("Consolas", 9), relief="flat")
        self.log.pack(fill="both", expand=True, padx=16, pady=(0, 16))

    def _write(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _refresh_adapters(self) -> None:
        self.adapters = list_adapters()
        labels = [
            f"{a.get('Name')}  [{a.get('Status')}]  {a.get('InterfaceDescription')}"
            for a in self.adapters
        ]
        self.adapter_combo["values"] = labels
        if labels:
            up_idx = next((i for i, a in enumerate(self.adapters) if a.get("Status") == "Up"), 0)
            self.adapter_combo.current(up_idx)
        self._write(f"Found {len(labels)} network adapter(s).")

    def _poll_status(self) -> None:
        def worker():
            sysmon = sc_running("Sysmon64")
            suricata = suricata_running()
            winlogbeat = sc_running("winlogbeat")
            agent_alive = self.agent_proc is not None and self.agent_proc.poll() is None
            self.after(0, lambda: self._update_dots(sysmon, suricata, winlogbeat, agent_alive))
        threading.Thread(target=worker, daemon=True).start()
        self.after(4000, self._poll_status)

    def _update_dots(self, sysmon, suricata, winlogbeat, agent) -> None:
        self.sysmon_dot.config(fg="#22c55e" if sysmon else "#ef4444")
        self.suricata_dot.config(fg="#22c55e" if suricata else "#ef4444")
        self.winlogbeat_dot.config(fg="#22c55e" if winlogbeat else "#ef4444")
        self.agent_dot.config(fg="#22c55e" if agent else "#ef4444")
        if hasattr(self, "suricata_btn"):
            if suricata:
                self.suricata_btn.config(text="Stop Suricata", bg="#dc2626")
            else:
                self.suricata_btn.config(text="Start Suricata", bg="#16a34a")

    def _drain_log_queue(self) -> None:
        try:
            while True:
                line = self.log_queue.get_nowait()
                self.log.insert("end", line)
                self.log.see("end")
        except queue.Empty:
            pass
        self.after(200, self._drain_log_queue)

    def _selected_adapter_guid(self):
        idx = self.adapter_combo.current()
        if idx < 0 or idx >= len(self.adapters):
            return None
        return self.adapters[idx].get("InterfaceGuid")

    def save_settings(self) -> None:
        guid = self._selected_adapter_guid()
        updates = {"XDR_BACKEND_URL": self.backend_url_var.get().strip()}
        if guid:
            updates["SURICATA_IFACE"] = f"\\Device\\NPF_{guid}"
        write_env(ENV_FILE, updates)
        self._write(f"Saved settings to {ENV_FILE}")

    # ------------------------------------------------------------------
    def _start_suricata(self) -> None:
        if suricata_running():
            self._write("Suricata: already running")
            return
        guid = self._selected_adapter_guid()
        if guid and os.path.isfile(SURICATA_EXE):
            os.makedirs(SURICATA_LOGS, exist_ok=True)
            os.makedirs(DATA_DIR, exist_ok=True)
            try:
                self.suricata_proc = subprocess.Popen(
                    [SURICATA_EXE, "-c", SURICATA_YAML, "-i", f"\\Device\\NPF_{guid}", "-l", SURICATA_LOGS],
                    creationflags=CREATE_NO_WINDOW,
                    stdout=open(os.path.join(DATA_DIR, "suricata_out.log"), "a"),
                    stderr=subprocess.STDOUT,
                )
                self._write("Suricata: starting...")
            except Exception as exc:
                self._write(f"Suricata failed to start: {exc}")
        else:
            self._write("Suricata: skipped (no adapter selected or suricata.exe not found)")

    def stop_suricata(self) -> None:
        # Suricata is a plain process (not a service); kill by image name so we
        # also catch instances started in a previous session or by start.ps1.
        try:
            r = subprocess.run(
                ["taskkill", "/F", "/IM", "suricata.exe"],
                capture_output=True, text=True, timeout=15, creationflags=CREATE_NO_WINDOW,
            )
            out = (r.stdout + r.stderr).strip()
            if r.returncode == 0:
                self._write("Suricata: stopped.")
            elif "not found" in out.lower() or "no running" in out.lower() or "not running" in out.lower():
                self._write("Suricata: was not running.")
            else:
                self._write(f"Suricata: stop result -- {out or 'unknown'}")
        except Exception as exc:
            self._write(f"Suricata: stop failed -- {exc}")
        self.suricata_proc = None

    def toggle_suricata(self) -> None:
        if suricata_running():
            self.stop_suricata()
        else:
            self._start_suricata()

    # ------------------------------------------------------------------
    def start_agent(self) -> None:
        self.save_settings()

        # 1. Sysmon
        if not sc_running("Sysmon64"):
            self._write("Sysmon64 not running -- installing/starting...")
            try:
                subprocess.run(
                    [SYSMON_EXE, "-accepteula", "-i", SYSMON_CONFIG],
                    capture_output=True, timeout=30, creationflags=CREATE_NO_WINDOW,
                )
            except Exception as exc:
                self._write(f"Sysmon install/start failed: {exc}")
        self._write("Sysmon: OK" if sc_running("Sysmon64") else "Sysmon: still not running (check admin rights)")

        # 2. Suricata
        self._start_suricata()

        # 3. Endpoint agent -- inject this copy's .env into the process env so
        #    the new XDR_API_KEY / XDR_BACKEND_URL reach the agent (it reads
        #    config from os.environ only).
        if self.agent_proc is not None and self.agent_proc.poll() is None:
            self._write("Agent already running.")
            return
        try:
            agent_env = {**os.environ, **read_env(ENV_FILE)}
            self.agent_proc = subprocess.Popen(
                [PYTHON_EXE, "-m", "endpoint_agent.agent"],
                cwd=ROOT,
                env=agent_env,
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, bufsize=1,
                creationflags=CREATE_NO_WINDOW,
            )
            threading.Thread(target=self._stream_agent_output, daemon=True).start()
            self._write("Endpoint agent starting (new API key injected)...")
        except Exception as exc:
            self._write(f"Failed to start endpoint agent: {exc}")

    def _stream_agent_output(self) -> None:
        proc = self.agent_proc
        if proc is None or proc.stdout is None:
            return
        for line in iter(proc.stdout.readline, ""):
            if not line:
                break
            self.log_queue.put(line if line.endswith("\n") else line + "\n")
        self.log_queue.put("[agent process exited]\n")

    def stop_agent(self) -> None:
        if self.agent_proc is not None and self.agent_proc.poll() is None:
            self.agent_proc.terminate()
            self._write("Stopped endpoint agent.")
        else:
            self._write("Agent is not running.")


if __name__ == "__main__":
    if not os.path.isdir(ROOT):
        messagebox.showerror("Cyber Sentinel XDR", f"Expected project root not found:\n{ROOT}")
        sys.exit(1)
    App().mainloop()
