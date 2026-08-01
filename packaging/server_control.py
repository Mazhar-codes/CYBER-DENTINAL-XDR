"""
Cyber Sentinel XDR - Server Control Panel
=========================================

A small Tkinter GUI shipped alongside the frozen backend.exe. After installation
it lets the operator choose the database (MongoDB Atlas cloud OR a local MongoDB),
edit the API key / JWT / port, test the connection, and start/stop the server +
open the dashboard - without hand-editing .env or re-installing.

Whichever database is chosen, the backend auto-creates all 27 collections and
their indexes on first connect, so the structure is always identical.

Layout when frozen (installed): {app}\server\
    backend.exe
    ServerControl.exe   <- this program
    .env                <- read/written here
"""
import os
import sys
import secrets
import subprocess
import threading
import webbrowser
import urllib.request

import tkinter as tk
from tkinter import messagebox

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
LOCAL_URI = "mongodb://localhost:27017"

if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(sys.executable)
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))

ENV_PATH = os.path.join(BASE_DIR, ".env")
BACKEND_EXE = os.path.join(BASE_DIR, "backend.exe")

COLORS = {
    "bg": "#0a0f1e", "panel": "#111a2e", "fg": "#c9d6e8",
    "accent": "#22d3ee", "ok": "#22c55e", "bad": "#ef4444",
    "muted": "#64748b", "entry": "#0d1526", "hint": "#7c8aa5",
}


def read_env():
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
    lines, _ = read_env()
    seen, out = set(), []
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


def friendly_error(err, uri):
    """Turn a raw pymongo error into clear, actionable guidance."""
    e = err.lower()
    if "10061" in e or "actively refused" in e or "refused" in e or "connection refused" in e:
        if "localhost" in uri or "127.0.0.1" in uri:
            return ("No local MongoDB is running. Install MongoDB Community "
                    "(mongodb.com/try/download/community), start it, then Test again.")
        return "Connection refused - the database server isn't reachable at that address."
    if "resolution" in e or "dns" in e or ("srv" in uri.lower() and "timed out" in e):
        return ("DNS/SRV lookup failed (common on some Wi-Fi/ISP networks with mongodb+srv). "
                "Use the STANDARD connection string from Atlas -> Connect -> Drivers -> "
                "'I don't see my driver version' (starts with mongodb:// and lists 3 servers).")
    if "auth" in e or "authentication failed" in e or "bad auth" in e:
        return "Authentication failed - the username or password in the URI is wrong."
    if "timed out" in e or "serverselection" in e:
        return "Timed out reaching the database - check your internet, or that MongoDB is running."
    if "ssl" in e or "tls" in e:
        return "TLS/SSL handshake failed - unstable network, or a firewall is blocking the DB port."
    return err[:110]


class ControlPanel(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Cyber Sentinel XDR - Server Control Panel")
        self.configure(bg=COLORS["bg"])
        self.geometry("700x600")
        self.minsize(620, 560)
        self.resizable(True, True)

        _, values = read_env()
        cur_uri = values.get("MONGO_URI", "")
        self.db_type = tk.StringVar(value="local" if ("localhost" in cur_uri or "127.0.0.1" in cur_uri) else "atlas")
        self._atlas_cache = "" if self.db_type.get() == "local" else cur_uri
        self.uri = tk.StringVar(value=cur_uri or LOCAL_URI)
        self.api = tk.StringVar(value=values.get("XDR_API_KEY", ""))
        self.jwt = tk.StringVar(value=values.get("JWT_SECRET_KEY", ""))
        self.port = tk.StringVar(value=values.get("BACKEND_PORT", "8000"))
        self._build_ui()
        self._poll_status()

    def _build_ui(self):
        tk.Label(self, text="CYBER SENTINEL XDR", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 18, "bold")).pack(pady=(16, 0))
        tk.Label(self, text="Server Control Panel", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 10)).pack(pady=(0, 10))

        # --- Database type chooser ---
        dbframe = tk.Frame(self, bg=COLORS["bg"])
        dbframe.pack(fill="x", padx=28)
        tk.Label(dbframe, text="Database:", bg=COLORS["bg"], fg=COLORS["fg"],
                 font=("Consolas", 10, "bold")).pack(side="left")
        for val, text in (("atlas", "MongoDB Atlas (cloud)"), ("local", "Local MongoDB")):
            tk.Radiobutton(dbframe, text=text, value=val, variable=self.db_type,
                           command=self._on_db_type, bg=COLORS["bg"], fg=COLORS["fg"],
                           selectcolor=COLORS["entry"], activebackground=COLORS["bg"],
                           activeforeground=COLORS["accent"], font=("Consolas", 9),
                           highlightthickness=0).pack(side="left", padx=8)

        # --- Fields ---
        form = tk.Frame(self, bg=COLORS["bg"])
        form.pack(fill="x", padx=28, pady=(8, 0))
        rows = [("MongoDB URI", self.uri, ""),
                ("API Key", self.api, "regen_api"),
                ("JWT Secret", self.jwt, "regen_jwt"),
                ("Port", self.port, "")]
        for i, (label, var, act) in enumerate(rows):
            tk.Label(form, text=label, bg=COLORS["bg"], fg=COLORS["fg"],
                     font=("Consolas", 10), anchor="w").grid(row=i, column=0, sticky="w", pady=6)
            show = "*" if label == "JWT Secret" else ""
            ent = tk.Entry(form, textvariable=var, show=show, bg=COLORS["entry"], fg=COLORS["fg"],
                           insertbackground=COLORS["accent"], relief="flat", font=("Consolas", 9))
            ent.grid(row=i, column=1, sticky="ew", padx=8)
            if label == "MongoDB URI":
                self.uri_entry = ent
            if act == "regen_api":
                tk.Button(form, text="Regenerate", command=lambda: self.api.set(secrets.token_hex(32)),
                          bg=COLORS["panel"], fg=COLORS["accent"], relief="flat",
                          font=("Consolas", 8), cursor="hand2").grid(row=i, column=2, padx=4)
            elif act == "regen_jwt":
                tk.Button(form, text="Regenerate", command=lambda: self.jwt.set(secrets.token_hex(32)),
                          bg=COLORS["panel"], fg=COLORS["accent"], relief="flat",
                          font=("Consolas", 8), cursor="hand2").grid(row=i, column=2, padx=4)
        form.grid_columnconfigure(1, weight=1)

        self.hint = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["hint"],
                             font=("Consolas", 8), wraplength=620, justify="left")
        self.hint.pack(fill="x", padx=30, pady=(6, 0))

        self.status = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["muted"],
                               font=("Consolas", 9), wraplength=640, justify="center")
        self.status.pack(pady=12)

        row1 = tk.Frame(self, bg=COLORS["bg"]); row1.pack(pady=4)
        self._btn(row1, "Test Database", self._test_db, COLORS["accent"])
        self._btn(row1, "Save Config", self._save, COLORS["accent"])
        row2 = tk.Frame(self, bg=COLORS["bg"]); row2.pack(pady=4)
        self._btn(row2, "Start Server", self._start, COLORS["ok"])
        self._btn(row2, "Stop Server", self._stop, COLORS["bad"])
        self._btn(row2, "Open Dashboard", self._open_dash, COLORS["accent"])

        tk.Label(self, text=f"Config file: {ENV_PATH}", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 8)).pack(side="bottom", pady=8)
        self._on_db_type()

    def _btn(self, parent, text, cmd, color):
        tk.Button(parent, text=text, command=cmd, bg=COLORS["panel"], fg=color,
                  activebackground=color, activeforeground=COLORS["bg"], relief="flat",
                  font=("Consolas", 10, "bold"), width=15, height=2, cursor="hand2",
                  bd=0).pack(side="left", padx=6)

    def _on_db_type(self):
        if self.db_type.get() == "local":
            if "localhost" not in self.uri.get() and "127.0.0.1" not in self.uri.get():
                self._atlas_cache = self.uri.get()
            self.uri.set(LOCAL_URI)
            self.hint.config(text="Local mode: uses a MongoDB installed on THIS computer. If Test says "
                                  "'no local MongoDB', install MongoDB Community (mongodb.com), start it, "
                                  "then Test again. The 27 collections are created automatically on first start.")
        else:
            if "localhost" in self.uri.get() or "127.0.0.1" in self.uri.get():
                self.uri.set(self._atlas_cache)
            self.hint.config(text="Atlas mode: paste your MongoDB Atlas connection string. Tip: if a "
                                  "mongodb+srv:// link fails with a DNS error, use the STANDARD string "
                                  "(mongodb:// with 3 servers) from Atlas -> Connect -> Drivers.")

    def _port_val(self):
        return (self.port.get().strip() or "8000")

    def _save(self):
        vals = {"MONGO_URI": self.uri.get().strip(), "XDR_API_KEY": self.api.get().strip(),
                "JWT_SECRET_KEY": self.jwt.get().strip(), "BACKEND_PORT": self._port_val(),
                "BACKEND_HOST": "0.0.0.0"}
        if len(vals["XDR_API_KEY"]) < 16:
            messagebox.showerror("Invalid", "API Key must be at least 16 characters. Use Regenerate.")
            return
        if not vals["MONGO_URI"]:
            messagebox.showerror("Invalid", "MongoDB URI is required.")
            return
        try:
            write_env(vals)
            messagebox.showinfo("Saved", "Configuration saved.\nClick Stop then Start to apply it.")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def _test_db(self):
        uri = self.uri.get().strip()
        self.status.config(text="Testing database connection...", fg=COLORS["muted"])
        def work():
            try:
                import pymongo  # noqa: PLC0415
                c = pymongo.MongoClient(uri, serverSelectionTimeoutMS=9000)
                c.admin.command("ping")
                c.close()
                self.status.config(text="Database: CONNECTED", fg=COLORS["ok"])
            except Exception as e:
                self.status.config(text="Database: FAILED - " + friendly_error(str(e), uri), fg=COLORS["bad"])
        threading.Thread(target=work, daemon=True).start()

    def _start(self):
        if not os.path.exists(BACKEND_EXE):
            messagebox.showerror("Not found", f"backend.exe not found at:\n{BACKEND_EXE}")
            return
        try:
            subprocess.Popen([BACKEND_EXE], cwd=BASE_DIR,
                             creationflags=CREATE_NO_WINDOW | DETACHED_PROCESS, close_fds=True)
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
        webbrowser.open(f"http://localhost:{self._port_val()}/")

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
                    with urllib.request.urlopen(f"http://127.0.0.1:{self._port_val()}/health", timeout=3) as r:
                        import json  # noqa: PLC0415
                        mongo = bool(json.loads(r.read().decode()).get("mongo"))
                except Exception:
                    mongo = None
            self._render_status(running, mongo)
        threading.Thread(target=work, daemon=True).start()
        self.after(4000, self._poll_status)

    def _render_status(self, running, mongo):
        cur = self.status.cget("text")
        if cur.startswith("Testing") or cur.startswith("Server starting") or cur.startswith("Database:"):
            return
        if running:
            db = "DB connected" if mongo else ("DB OFFLINE" if mongo is False else "DB checking")
            col = COLORS["ok"] if mongo else COLORS["bad"] if mongo is False else COLORS["muted"]
            self.status.config(text=f"Server: RUNNING  |  {db}", fg=col)
        else:
            self.status.config(text="Server: STOPPED", fg=COLORS["muted"])


if __name__ == "__main__":
    ControlPanel().mainloop()
