"""
Cyber Sentinel XDR -- Control Panel  (NEW C: copy)
Launcher GUI for the independent C:-drive copy. Buttons open PowerShell windows
that run this copy's backend/frontend and launch its endpoint-agent GUI. Points
at this copy's OWN venv + .env (new database + new secrets). Does not touch any
detection/response logic.

Difference vs the E: original: the backend is started by calling the venv's
python.exe DIRECTLY (not `venv\Scripts\Activate.ps1`), because a *copied* venv's
activate script still contains the original E: path and would mis-activate.
"""
import ctypes
import os
import socket
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from datetime import datetime
from tkinter import scrolledtext

REPO          = r"C:\Users\beeb9\Downloads\Compressed\New folder"
BACKEND_DIR   = REPO + r"\Backend"
FRONTEND_DIR  = REPO + r"\Cyber Sentinal XDR Frontend"
VENV_PY       = BACKEND_DIR + r"\venv\Scripts\python.exe"

# The endpoint-agent GUI is a sibling .exe built from endpoint_gui.py.
# When frozen by PyInstaller, sys.executable is this exe's own path.
_HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
ENDPOINT_GUI_EXE = os.path.join(_HERE, "CyberSentinelXDR-EndpointAgent.exe")

CREATE_NEW_CONSOLE = 0x00000010


def open_powershell(command: str) -> None:
    """Open a new, visible PowerShell window running *command*."""
    subprocess.Popen(
        ["powershell", "-NoExit", "-Command", command],
        creationflags=CREATE_NEW_CONSOLE,
    )


def run_elevated(command: str) -> None:
    """Launch a new elevated PowerShell window (triggers a UAC prompt)."""
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "powershell.exe",
        f'-NoExit -Command "{command}"',
        None, 1,
    )


def port_is_open(port: int, host: str = "127.0.0.1") -> bool:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(0.5)
            return s.connect_ex((host, port)) == 0
    except Exception:
        return False


def pids_on_port(port: int) -> list:
    try:
        out = subprocess.run(
            ["netstat", "-ano"], capture_output=True, text=True, timeout=10
        ).stdout
    except Exception:
        return []
    pids = set()
    for line in out.splitlines():
        if f":{port} " in line and "LISTENING" in line:
            parts = line.split()
            if parts:
                pids.add(parts[-1])
    return list(pids)


def parent_pid(pid: str):
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-Command",
             f"(Get-CimInstance Win32_Process -Filter \"ProcessId={pid}\").ParentProcessId"],
            capture_output=True, text=True, timeout=10,
        )
        out = r.stdout.strip()
        return out if out.isdigit() else None
    except Exception:
        return None


def kill_tree(pid: str):
    r = subprocess.run(
        ["taskkill", "/F", "/T", "/PID", pid],
        capture_output=True, text=True, timeout=10,
    )
    return r.returncode == 0, (r.stdout + r.stderr).strip()


def kill_pids_elevated(pids: list) -> None:
    if not pids:
        return
    chained = " & ".join(f"taskkill /F /T /PID {p}" for p in pids)
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", "cmd.exe", f'/c "{chained}"', None, 0,
    )


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Sentinel XDR -- Control Panel (New Copy)")
        self.geometry("620x580")
        self.resizable(False, False)
        self.configure(bg="#111827")

        self._build_ui()
        self._poll_status()

    def _build_ui(self) -> None:
        FG, BG, ACCENT = "#e5e7eb", "#111827", "#1f2937"

        tk.Label(self, text="CYBER SENTINEL XDR", fg="#22d3ee", bg=BG,
                 font=("Segoe UI", 18, "bold")).pack(pady=(16, 0))
        tk.Label(self, text="Control Panel - New Independent Copy", fg=FG, bg=BG,
                 font=("Segoe UI", 10)).pack(pady=(0, 12))

        status_frame = tk.Frame(self, bg=ACCENT)
        status_frame.pack(fill="x", padx=16, pady=(0, 12))
        self.backend_dot = tk.Label(status_frame, text="● Backend (8000)", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.backend_dot.pack(side="left", padx=12, pady=8)
        self.frontend_dot = tk.Label(status_frame, text="● Frontend (3000)", fg="#ef4444", bg=ACCENT, font=("Segoe UI", 10, "bold"))
        self.frontend_dot.pack(side="left", padx=12, pady=8)

        btn_frame = tk.Frame(self, bg=BG)
        btn_frame.pack(fill="x", padx=16)

        def make_btn(parent, text, cmd, color="#2563eb"):
            return tk.Button(
                parent, text=text, command=cmd, bg=color, fg="white",
                activebackground="#1d4ed8", activeforeground="white",
                font=("Segoe UI", 10, "bold"), relief="flat", pady=8,
                cursor="hand2",
            )

        make_btn(btn_frame, "Start Backend", self.start_backend).grid(row=0, column=0, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Start Frontend", self.start_frontend).grid(row=0, column=1, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Start Endpoint Agent", self.start_endpoint).grid(row=1, column=0, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Start Everything", self.start_all, color="#16a34a").grid(row=1, column=1, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Stop Backend", self.stop_backend, color="#dc2626").grid(row=2, column=0, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Stop Frontend", self.stop_frontend, color="#dc2626").grid(row=2, column=1, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Open Dashboard", self.open_dashboard, color="#7c3aed").grid(row=3, column=0, sticky="ew", padx=4, pady=4)
        make_btn(btn_frame, "Stop Everything", self.stop_all, color="#991b1b").grid(row=3, column=1, sticky="ew", padx=4, pady=4)

        btn_frame.grid_columnconfigure(0, weight=1)
        btn_frame.grid_columnconfigure(1, weight=1)

        tk.Label(self, text="Activity Log", fg=FG, bg=BG, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=16, pady=(16, 2))
        self.log = scrolledtext.ScrolledText(
            self, height=14, bg="#0b1220", fg="#9ca3af", insertbackground="white",
            font=("Consolas", 9), relief="flat",
        )
        self.log.pack(fill="both", expand=True, padx=16, pady=(0, 16))
        self._write("Launcher ready (new C: copy).")

    def _write(self, msg: str) -> None:
        ts = datetime.now().strftime("%H:%M:%S")
        self.log.insert("end", f"[{ts}] {msg}\n")
        self.log.see("end")

    def _poll_status(self) -> None:
        def worker():
            b = port_is_open(8000)
            f = port_is_open(3000)
            self.after(0, lambda: self._update_dots(b, f))
        threading.Thread(target=worker, daemon=True).start()
        self.after(3000, self._poll_status)

    def _update_dots(self, backend_up: bool, frontend_up: bool) -> None:
        self.backend_dot.config(fg="#22c55e" if backend_up else "#ef4444")
        self.frontend_dot.config(fg="#22c55e" if frontend_up else "#ef4444")

    # ------------------------------------------------------------------
    def start_backend(self) -> None:
        # Call the venv python DIRECTLY (copied-venv activate script is unreliable).
        cmd = f"cd '{BACKEND_DIR}'; & '{VENV_PY}' -m uvicorn backend:sio_app --host 0.0.0.0 --port 8000"
        open_powershell(cmd)
        self._write("Opened Backend window (port 8000, new DB).")

    def start_frontend(self) -> None:
        cmd = f"cd '{FRONTEND_DIR}'; npm start"
        open_powershell(cmd)
        self._write("Opened Frontend window (port 3000).")

    def start_endpoint(self) -> None:
        if os.path.isfile(ENDPOINT_GUI_EXE):
            subprocess.Popen([ENDPOINT_GUI_EXE])
            self._write("Launched Endpoint Agent GUI.")
        else:
            self._write("EndpointAgent GUI exe not found next to this exe. "
                        "Build it with build_launchers.ps1, or start the agent manually.")

    def start_all(self) -> None:
        self.start_backend()
        time.sleep(1.0)
        self.start_frontend()
        self.start_endpoint()
        self._write("Started Backend + Frontend + Endpoint Agent.")

    def open_dashboard(self) -> None:
        webbrowser.open("http://localhost:3000")
        self._write("Opened dashboard in browser.")

    def stop_backend(self) -> None:
        self._stop_port(8000, "Backend")

    def stop_frontend(self) -> None:
        self._stop_port(3000, "Frontend")

    def stop_all(self) -> None:
        self._stop_port(8000, "Backend")
        self._stop_port(3000, "Frontend")

    def _stop_port(self, port: int, label: str) -> None:
        pids = pids_on_port(port)
        if not pids:
            self._write(f"{label}: nothing running on port {port}.")
            return

        targets = set(pids)
        for pid in pids:
            p = parent_pid(pid)
            if p and p not in ("0", "4"):
                targets.add(p)

        any_ok = False
        denied = []
        for pid in targets:
            ok, detail = kill_tree(pid)
            if ok:
                self._write(f"{label}: killed process {pid} (+ children).")
                any_ok = True
            elif "denied" in detail.lower():
                denied.append(pid)
                self._write(f"{label}: could not kill {pid} (Access denied -- escalating).")
            else:
                self._write(f"{label}: could not kill {pid} ({detail or 'already gone'}).")

        if denied:
            self._write(f"{label}: requesting elevation (UAC) to force-kill {len(denied)} process(es)...")
            kill_pids_elevated(denied)
            time.sleep(2.0)
            any_ok = True

        if any_ok:
            time.sleep(1.5)
        if port_is_open(port):
            self._write(f"{label}: WARNING -- port {port} still responding after stop.")
        else:
            self._write(f"{label}: stopped, port {port} is free.")


if __name__ == "__main__":
    App().mainloop()
