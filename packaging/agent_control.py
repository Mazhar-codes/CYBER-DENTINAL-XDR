"""
Cyber Sentinel XDR - Endpoint Agent Control Panel

Tkinter front-end for CyberSentinelAgent.exe. Lets an operator view/edit the
backend URL, API key, and telemetry/command intervals, save them, and
Start/Stop the agent process - mirroring server_control.py's UX so both ends
of the product feel the same. Previously the installer's shortcut launched
CyberSentinelAgent.exe directly (a console app with no way to change settings
without re-running the installer or hand-editing an NSSM service's
environment), which is what this panel replaces.

Build:
    pyinstaller --clean --noconfirm packaging/AgentControl.spec
(or packaging/build_agent_control.ps1, which sets up the environment first.)
"""
import json
import os
import subprocess
import sys
import threading
import time
import tkinter as tk
import urllib.request
from pathlib import Path
from tkinter import messagebox

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008

BASE_DIR = os.path.dirname(
    os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__)
)
AGENT_EXE = os.path.join(BASE_DIR, "CyberSentinelAgent.exe")
AGENT_OUT_LOG = os.path.join(BASE_DIR, "agent_out.log")
AGENT_ERR_LOG = os.path.join(BASE_DIR, "agent_err.log")

# The installer's boot-time scheduled task runs this .cmd with whatever
# URL/key were entered in the install wizard baked in. Rewriting it here on
# every Save keeps a later reboot from silently reverting to those original
# install-time settings once the operator has edited them in this panel.
RUN_AGENT_CMD_PATH = os.path.join(BASE_DIR, "run_agent.cmd")

# Settings persist here purely for this panel's own use (repopulating fields
# on next launch, and building the CLI args passed to CyberSentinelAgent.exe
# on Start) - agent.py itself is untouched and keeps reading CLI args/env vars
# exactly as before, so this adds zero risk to the agent's own logic.
CONFIG_DIR = Path(os.environ.get("PROGRAMDATA", r"C:\ProgramData")) / "CyberSentinel"
CONFIG_PATH = CONFIG_DIR / "agent_gui_config.json"

DEFAULTS = {
    "backend_url": "http://localhost:8000",
    "api_key": "changeme-dev-key",
    "collect_interval": "5",
    "command_interval": "3",
}

AGENT_START_GRACE_SECS = 15

COLORS = {
    "bg": "#0a0f1e", "panel": "#111a2e", "fg": "#c9d6e8",
    "accent": "#22d3ee", "ok": "#22c55e", "bad": "#ef4444",
    "muted": "#64748b", "entry": "#0d1526", "hint": "#7c8aa5",
}


def read_config() -> dict:
    if CONFIG_PATH.exists():
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            merged = dict(DEFAULTS)
            merged.update({k: str(v) for k, v in data.items() if k in DEFAULTS})
            return merged
        except Exception:
            pass
    return dict(DEFAULTS)


def write_config(values: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with CONFIG_PATH.open("w", encoding="utf-8") as f:
        json.dump(values, f, indent=2)


def write_run_agent_cmd(values: dict) -> None:
    """Best-effort - if Program Files isn't writable for some reason, Start
    Agent from this panel still works fine using the values directly."""
    cmd = (
        "@echo off\r\n"
        f'"{AGENT_EXE}" --backend-url "{values["backend_url"]}" '
        f'--api-key "{values["api_key"]}" '
        f'--collect-interval {values["collect_interval"]} '
        f'--command-interval {values["command_interval"]}\r\n'
    )
    try:
        with open(RUN_AGENT_CMD_PATH, "w", encoding="utf-8") as f:
            f.write(cmd)
    except Exception:
        pass


class AgentControlPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Sentinel XDR - Endpoint Agent Control Panel")
        self.configure(bg=COLORS["bg"])
        self.geometry("680x560")
        self.minsize(640, 520)
        self.resizable(True, True)

        cfg = read_config()
        self.backend_url = tk.StringVar(value=cfg["backend_url"])
        self.api_key = tk.StringVar(value=cfg["api_key"])
        self.collect_interval = tk.StringVar(value=cfg["collect_interval"])
        self.command_interval = tk.StringVar(value=cfg["command_interval"])
        self._agent_start_ts = 0.0

        self._build_ui()
        self._poll_status()

    # ------------------------------------------------------------------
    def _build_ui(self):
        tk.Label(self, text="CYBER SENTINEL XDR", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 18, "bold")).pack(pady=(24, 0))
        tk.Label(self, text="Endpoint Agent Control Panel", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 10)).pack(pady=(0, 18))

        form = tk.Frame(self, bg=COLORS["bg"])
        form.pack(fill="x", padx=32, pady=(0, 4))
        rows = [
            ("Backend URL", self.backend_url, ""),
            ("API Key", self.api_key, ""),
            ("Collect Interval (s)", self.collect_interval, ""),
            ("Command Interval (s)", self.command_interval, ""),
        ]
        for i, (label, var, _act) in enumerate(rows):
            tk.Label(form, text=label, bg=COLORS["bg"], fg=COLORS["fg"],
                     font=("Consolas", 10), anchor="w").grid(row=i, column=0, sticky="w", pady=8)
            tk.Entry(form, textvariable=var, bg=COLORS["entry"], fg=COLORS["fg"],
                     insertbackground=COLORS["accent"], relief="flat",
                     font=("Consolas", 9)).grid(row=i, column=1, sticky="ew", padx=8, pady=8, ipady=4)
        form.grid_columnconfigure(1, weight=1)

        tk.Label(self, text="API Key must match the API Key shown on the Server's Control Panel "
                             "(Endpoint URL there is what Backend URL should point to).",
                 bg=COLORS["bg"], fg=COLORS["hint"], font=("Consolas", 8),
                 wraplength=600, justify="left").pack(fill="x", padx=34, pady=(4, 0))

        self.status = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["muted"],
                                font=("Consolas", 9), wraplength=600, justify="center")
        self.status.pack(pady=(20, 4))

        row1 = tk.Frame(self, bg=COLORS["bg"]); row1.pack(pady=6)
        self._btn(row1, "Save Config", self._save, COLORS["accent"])
        self._btn(row1, "Start Agent", self._start, COLORS["ok"])
        self._btn(row1, "Stop Agent", self._stop, COLORS["bad"])

        tk.Label(self, text=f"Config file: {CONFIG_PATH}", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 8)).pack(side="bottom", pady=8)
        tk.Label(self, text=f"Agent logs: {AGENT_OUT_LOG}", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 8)).pack(side="bottom")

    def _btn(self, parent, text, cmd, color):
        tk.Button(parent, text=text, command=cmd, bg=COLORS["panel"], fg=color,
                  activebackground=color, activeforeground=COLORS["bg"], relief="flat",
                  font=("Consolas", 10, "bold"), width=14, height=2, cursor="hand2",
                  bd=0).pack(side="left", padx=8)

    # ------------------------------------------------------------------
    def _current_values(self) -> dict:
        return {
            "backend_url": self.backend_url.get().strip() or DEFAULTS["backend_url"],
            "api_key": self.api_key.get().strip() or DEFAULTS["api_key"],
            "collect_interval": self.collect_interval.get().strip() or DEFAULTS["collect_interval"],
            "command_interval": self.command_interval.get().strip() or DEFAULTS["command_interval"],
        }

    def _save(self):
        try:
            cfg = self._current_values()
            write_config(cfg)
            write_run_agent_cmd(cfg)
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _is_running(self) -> bool:
        try:
            out = subprocess.run(
                ["tasklist", "/FI", "IMAGENAME eq CyberSentinelAgent.exe"],
                creationflags=CREATE_NO_WINDOW, capture_output=True, text=True,
            )
            return "CyberSentinelAgent.exe" in (out.stdout or "")
        except Exception:
            return False

    def _start(self):
        if not os.path.exists(AGENT_EXE):
            messagebox.showerror("Not found", f"CyberSentinelAgent.exe not found at:\n{AGENT_EXE}")
            return
        self._save()

        # If the agent is already running, restart it so edited settings
        # actually take effect instead of silently doing nothing (same fix
        # applied to the Server Control Panel's Start Server button).
        if self._is_running():
            self.status.config(
                text="Agent already running - restarting with current settings...",
                fg=COLORS["accent"],
            )
            self.update_idletasks()
            try:
                subprocess.run(["taskkill", "/IM", "CyberSentinelAgent.exe", "/F"],
                               creationflags=CREATE_NO_WINDOW, capture_output=True)
            except Exception:
                pass
            time.sleep(2)

        cfg = self._current_values()
        args = [
            AGENT_EXE,
            "--backend-url", cfg["backend_url"],
            "--api-key", cfg["api_key"],
            "--collect-interval", cfg["collect_interval"],
            "--command-interval", cfg["command_interval"],
        ]
        try:
            # Redirect to disk: CyberSentinelAgent.exe runs DETACHED with no
            # console, so without this any startup failure vanishes silently.
            with open(AGENT_OUT_LOG, "w", encoding="utf-8", errors="replace") as out_f, \
                    open(AGENT_ERR_LOG, "w", encoding="utf-8", errors="replace") as err_f:
                subprocess.Popen(
                    args, cwd=BASE_DIR,
                    creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS, close_fds=True,
                    stdout=out_f, stderr=err_f,
                )
            self._agent_start_ts = time.time()
            self.status.config(text="Agent starting...", fg=COLORS["accent"])
        except Exception as e:
            messagebox.showerror("Start failed", str(e))

    def _stop(self):
        try:
            subprocess.run(["taskkill", "/IM", "CyberSentinelAgent.exe", "/F"],
                           creationflags=CREATE_NO_WINDOW, capture_output=True)
            self.status.config(text="Agent stopped.", fg=COLORS["muted"])
        except Exception as e:
            messagebox.showerror("Stop failed", str(e))

    # ------------------------------------------------------------------
    def _poll_status(self):
        def work():
            running = self._is_running()
            health = None
            if running:
                try:
                    with urllib.request.urlopen("http://127.0.0.1:8765/health", timeout=3) as r:
                        health = json.loads(r.read().decode())
                except Exception:
                    health = None
            self._render_status(running, health)

        threading.Thread(target=work, daemon=True).start()
        self.after(4000, self._poll_status)

    def _render_status(self, running, health):
        cur = self.status.cget("text")
        if cur.startswith("Agent starting") or cur.startswith("Agent already running - restarting"):
            elapsed = time.time() - self._agent_start_ts
            if not running:
                if elapsed > AGENT_START_GRACE_SECS:
                    self.status.config(
                        text=f"Agent: CRASHED on startup - see agent_err.log in {BASE_DIR}",
                        fg=COLORS["bad"])
                return
            if health is None and elapsed < AGENT_START_GRACE_SECS:
                return

        if not running:
            self.status.config(text="Agent: STOPPED", fg=COLORS["muted"])
            return
        if health is None:
            self.status.config(
                text=f"Agent: RUNNING but not responding on its health port yet - "
                     f"see agent_err.log in {BASE_DIR}",
                fg=COLORS["bad"])
            return
        last_send = health.get("last_telemetry_sent") or "never"
        self.status.config(
            text=f"Agent: RUNNING  |  endpoint_id={health.get('endpoint_id', '?')}  |  "
                 f"last telemetry sent: {last_send}",
            fg=COLORS["ok"])


if __name__ == "__main__":
    app = AgentControlPanel()
    app.mainloop()
