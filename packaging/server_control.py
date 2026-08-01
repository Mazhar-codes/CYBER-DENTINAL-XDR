"""
Cyber Sentinel XDR - Server Control Panel
=========================================

A small Tkinter GUI shipped alongside the frozen backend.exe. It lets the
operator, AFTER installation, edit the server configuration (MongoDB URI,
API key, JWT secret, port), test the database connection, and start/stop the
server + open the dashboard - without hand-editing .env or re-installing.

Layout when frozen (installed): {app}\server\
    backend.exe
    ServerControl.exe   <- this program
    .env                <- read/written here

Deps (small; bundled by PyInstaller onefile): tkinter (stdlib), pymongo,
dnspython (for mongodb+srv Atlas URIs). No torch.
"""
import os
import sys
import secrets
import subprocess
import threading
import webbrowser
import urllib.request

import tkinter as tk
from tkinter import ttk, messagebox

# --- Windows process-creation flags -----------------------------------------
CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008

# --- Locate the install dir (dir of this exe when frozen, else this file) ----
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PATH = os.path.join(BASE_DIR, ".env")
BACKEND_EXE = os.path.join(BASE_DIR, "backend.exe")

# Config keys the panel manages, in display order.
FIELDS = [
    ("MONGO_URI",       "MongoDB URI",       "mongodb://localhost:27017"),
    ("XDR_API_KEY",     "API Key",           ""),
    ("JWT_SECRET_KEY",  "JWT Secret",        ""),
    ("BACKEND_PORT",    "Port",              "8000"),
]

COLORS = {
    "bg": "#0a0f1e", "panel": "#111a2e", "fg": "#c9d6e8",
    "accent": "#22d3ee", "ok": "#22c55e", "bad": "#ef4444",
    "muted": "#64748b", "entry": "#0d1526",
}


def read_env():
    """Return (lines, values) — raw lines preserved, values dict for managed keys."""
    lines, values = [], {}
    if os.path.exists(ENV_PATH):
        with open(ENV_PATH, "r", encoding="utf-8", errors="replace") as f:
            lines = f.read().splitlines()
    for ln in lines:
        s = ln.strip()
        if not s or s.startswith("#") or "=" not in s:
            continue
        k, v = s.split("=", 1)
        values[k.strip()] = v.strip()
    return lines, values


def write_env(new_values):
    """Update/append managed keys, preserving other lines. Written WITHOUT a BOM."""
    lines, _ = read_env()
    seen = set()
    out = []
    for ln in lines:
        s = ln.strip()
        if s and not s.startswith("#") and "=" in s:
            k = s.split("=", 1)[0].strip()
            if k in new_values:
                out.append(f"{k}={new_values[k]}")
                seen.add(k)
                continue
        out.append(ln)
    for k, v in new_values.items():
        if k not in seen:
            out.append(f"{k}={v}")
    with open(ENV_PATH, "w", encoding="ascii", newline="\n") as f:
        f.write("\n".join(out) + "\n")


class ControlPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Sentinel XDR - Server Control Panel")
        self.configure(bg=COLORS["bg"])
        self.geometry("700x580")
        self.minsize(600, 520)
        self.resizable(True, True)
        self.entries = {}
        _, values = read_env()
        self._build_ui(values)
        self._poll_status()

    # -- UI ------------------------------------------------------------------
    def _build_ui(self, values):
        tk.Label(self, text="CYBER SENTINEL XDR", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 18, "bold")).pack(pady=(18, 0))
        tk.Label(self, text="Server Control Panel", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 10)).pack(pady=(0, 12))

        form = tk.Frame(self, bg=COLORS["bg"])
        form.pack(fill="x", padx=28)
        for i, (key, label, default) in enumerate(FIELDS):
            tk.Label(form, text=label, bg=COLORS["bg"], fg=COLORS["fg"],
                     font=("Consolas", 10), anchor="w").grid(row=i, column=0, sticky="w", pady=6)
            var = tk.StringVar(value=values.get(key, default))
            show = "*" if key == "JWT_SECRET_KEY" else ""
            ent = tk.Entry(form, textvariable=var, width=52, show=show,
                           bg=COLORS["entry"], fg=COLORS["fg"], insertbackground=COLORS["accent"],
                           relief="flat", font=("Consolas", 9))
            ent.grid(row=i, column=1, sticky="ew", padx=8)
            self.entries[key] = var
            if key in ("XDR_API_KEY", "JWT_SECRET_KEY"):
                tk.Button(form, text="Regenerate", command=lambda k=key: self._regen(k),
                          bg=COLORS["panel"], fg=COLORS["accent"], relief="flat",
                          font=("Consolas", 8), cursor="hand2").grid(row=i, column=2, padx=4)
        form.grid_columnconfigure(1, weight=1)

        # Status line
        self.status = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["muted"],
                               font=("Consolas", 10))
        self.status.pack(pady=14)

        # Buttons
        row1 = tk.Frame(self, bg=COLORS["bg"]); row1.pack(pady=4)
        self._btn(row1, "Test Database", self._test_db, COLORS["accent"])
        self._btn(row1, "Save Config", self._save, COLORS["accent"])
        row2 = tk.Frame(self, bg=COLORS["bg"]); row2.pack(pady=4)
        self._btn(row2, "Start Server", self._start, COLORS["ok"])
        self._btn(row2, "Stop Server", self._stop, COLORS["bad"])
        self._btn(row2, "Open Dashboard", self._open_dash, COLORS["accent"])

        tk.Label(self, text=f"Config file: {ENV_PATH}", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 8)).pack(side="bottom", pady=8)

    def _btn(self, parent, text, cmd, color):
        tk.Button(parent, text=text, command=cmd, bg=COLORS["panel"], fg=color,
                  activebackground=color, activeforeground=COLORS["bg"], relief="flat",
                  font=("Consolas", 10, "bold"), width=15, height=2, cursor="hand2",
                  bd=0).pack(side="left", padx=6)

    # -- actions -------------------------------------------------------------
    def _regen(self, key):
        self.entries[key].set(secrets.token_hex(32))

    def _port(self):
        return (self.entries["BACKEND_PORT"].get().strip() or "8000")

    def _save(self):
        vals = {k: v.get().strip() for k, v in self.entries.items()}
        if len(vals.get("XDR_API_KEY", "")) < 16:
            messagebox.showerror("Invalid", "API Key must be at least 16 characters.")
            return
        if not vals.get("MONGO_URI"):
            messagebox.showerror("Invalid", "MongoDB URI is required.")
            return
        try:
            write_env(vals)
            messagebox.showinfo("Saved", "Configuration saved to .env.\nRestart the server (Stop then Start) to apply.")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _test_db(self):
        uri = self.entries["MONGO_URI"].get().strip()
        self.status.config(text="Testing database connection...", fg=COLORS["muted"])
        def work():
            try:
                import pymongo  # noqa: PLC0415
                c = pymongo.MongoClient(uri, serverSelectionTimeoutMS=8000)
                c.admin.command("ping")
                c.close()
                self.status.config(text="Database: CONNECTED", fg=COLORS["ok"])
            except Exception as e:
                msg = str(e).split(",")[0][:80]
                self.status.config(text=f"Database: FAILED - {msg}", fg=COLORS["bad"])
        threading.Thread(target=work, daemon=True).start()

    def _start(self):
        if not os.path.exists(BACKEND_EXE):
            messagebox.showerror("Not found", f"backend.exe not found at:\n{BACKEND_EXE}")
            return
        try:
            subprocess.Popen([BACKEND_EXE], cwd=BASE_DIR,
                             creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS,
                             close_fds=True)
            self.status.config(text="Server starting (models load ~30s)...", fg=COLORS["accent"])
        except Exception as e:
            messagebox.showerror("Start failed", str(e))

    def _stop(self):
        try:
            subprocess.run(["taskkill", "/IM", "backend.exe", "/F"],
                           creationflags=CREATE_NO_WINDOW, capture_output=True)
            self.status.config(text="Server stopped.", fg=COLORS["muted"])
        except Exception as e:
            messagebox.showerror("Stop failed", str(e))

    def _open_dash(self):
        webbrowser.open(f"http://localhost:{self._port()}/")

    # -- status poll ---------------------------------------------------------
    def _poll_status(self):
        def work():
            running, mongo = False, None
            try:
                out = subprocess.run(["tasklist", "/FI", "IMAGENAME eq backend.exe"],
                                     creationflags=CREATE_NO_WINDOW, capture_output=True, text=True)
                running = "backend.exe" in (out.stdout or "")
            except Exception:
                pass
            if running:
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{self._port()}/health", timeout=3) as r:
                        import json  # noqa: PLC0415
                        mongo = bool(json.loads(r.read().decode()).get("mongo"))
                except Exception:
                    mongo = None
            self._render_status(running, mongo)
        threading.Thread(target=work, daemon=True).start()
        self.after(4000, self._poll_status)

    def _render_status(self, running, mongo):
        # Don't clobber a transient message (test/save) unless idle-ish.
        cur = self.status.cget("text")
        if cur.startswith("Testing") or cur.startswith("Server starting"):
            return
        if running:
            db = "DB connected" if mongo else ("DB OFFLINE" if mongo is False else "DB unknown")
            col = COLORS["ok"] if mongo else COLORS["bad"] if mongo is False else COLORS["muted"]
            self.status.config(text=f"Server: RUNNING  |  {db}", fg=col)
        else:
            self.status.config(text="Server: STOPPED", fg=COLORS["muted"])


if __name__ == "__main__":
    ControlPanel().mainloop()
