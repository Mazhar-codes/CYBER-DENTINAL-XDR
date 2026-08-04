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
import re
import sys
import glob
import json
import time
import shutil
import socket
import secrets
import tempfile
import subprocess
import threading
import webbrowser
import urllib.request

import tkinter as tk
from tkinter import messagebox, ttk

# Licensing / activation core (frozen into ServerControl.exe alongside this file).
try:
    import xdr_license
    _LICENSING = True
except Exception:  # pragma: no cover - only if the module is missing in dev
    _LICENSING = False

_PRODUCT = "server"

MONGO_CURRENT_JSON = "https://downloads.mongodb.org/current.json"

CREATE_NO_WINDOW = 0x08000000
DETACHED_PROCESS = 0x00000008
LOCAL_URI = "mongodb://localhost:27017"

# Network detection prerequisites - NOT bundled/silently installed (Npcap's driver
# install can require a reboot, and Suricata needs the operator to pick the right
# capture interface), so the Control Panel just links out to the official installers
# instead of running them unattended. Versions match what packaging/*.iss developers
# have validated against (Suricata-7.0.15-1-64bit.msi / npcap-1.87.exe elsewhere in
# this repo) - bump these constants when validating a newer release.
SURICATA_VERSION = "7.0.15"
SURICATA_DOWNLOAD_URL = "https://suricata.io/download/"
NPCAP_VERSION = "1.87"
NPCAP_DOWNLOAD_URL = "https://npcap.com/#download"

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

        # --- Licensing gate -------------------------------------------------
        # The Control Panel is the launcher for the whole server. If this
        # machine is not activated (or the trial has expired) we show a locked
        # Activation screen instead of the dashboard controls, and nothing can
        # be started until a valid, unused activation code is entered.
        self._license_status = None
        if not self._enforce_license():
            return

        self._build_ui()
        self._poll_status()

    # ------------------------------------------------------------------
    # Licensing
    # ------------------------------------------------------------------
    def _enforce_license(self):
        """Return True if licensed (build the dashboard); otherwise show the
        Activation screen and return False."""
        if not _LICENSING:
            return True
        st = xdr_license.check_license(_PRODUCT)
        self._license_status = st
        if st["status"] == "ACTIVE":
            return True
        self._build_activation_ui(st)
        return False

    def _build_activation_ui(self, st):
        for w in self.winfo_children():
            w.destroy()
        self.title("Cyber Sentinel XDR - Activation")

        tk.Label(self, text="CYBER SENTINEL XDR", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 18, "bold")).pack(pady=(28, 0))
        tk.Label(self, text="Server - Product Activation", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 10)).pack(pady=(0, 16))

        locked = tk.Frame(self, bg=COLORS["panel"])
        locked.pack(fill="x", padx=36, pady=(0, 8))
        status = st.get("status")
        if status == "EXPIRED":
            head, col = "TRIAL EXPIRED", COLORS["bad"]
            sub = ("Your trial period has ended. Enter a NEW activation code to "
                   "continue. A previously used code will not work again.")
        elif status == "TAMPERED":
            head, col = "LICENSE LOCKED", COLORS["bad"]
            sub = st.get("message", "Please enter a new activation code.")
        else:
            head, col = "ACTIVATION REQUIRED", COLORS["accent"]
            sub = ("This copy of Cyber Sentinel XDR Server is not activated. "
                   "Enter the activation code you were given to unlock it.")
        tk.Label(locked, text=head, bg=COLORS["panel"], fg=col,
                 font=("Consolas", 13, "bold")).pack(pady=(12, 4))
        tk.Label(locked, text=sub, bg=COLORS["panel"], fg=COLORS["fg"], wraplength=560,
                 justify="center", font=("Consolas", 9)).pack(padx=16, pady=(0, 12))

        tk.Label(self, text="Activation code", bg=COLORS["bg"], fg=COLORS["fg"],
                 font=("Consolas", 10)).pack(pady=(12, 2))
        self._code_var = tk.StringVar()
        entry = tk.Entry(self, textvariable=self._code_var, justify="center",
                         bg=COLORS["entry"], fg=COLORS["fg"], insertbackground=COLORS["accent"],
                         relief="flat", font=("Consolas", 13), width=42)
        entry.pack(pady=(0, 4), ipady=6)
        entry.focus_set()
        entry.bind("<Return>", lambda _e: self._do_activate())

        tk.Label(self, text="Example:  CSXS-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXX",
                 bg=COLORS["bg"], fg=COLORS["hint"], font=("Consolas", 8)).pack(pady=(0, 10))

        self._act_status = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["bad"],
                                    wraplength=560, justify="center", font=("Consolas", 9))
        self._act_status.pack(pady=(0, 8))

        btnrow = tk.Frame(self, bg=COLORS["bg"])
        btnrow.pack(pady=(4, 0))
        tk.Button(btnrow, text="Activate", command=self._do_activate, bg=COLORS["panel"],
                  fg=COLORS["ok"], activebackground=COLORS["ok"], activeforeground=COLORS["bg"],
                  relief="flat", font=("Consolas", 11, "bold"), width=16, height=2,
                  cursor="hand2").pack(side="left", padx=6)
        tk.Button(btnrow, text="Quit", command=self.destroy, bg=COLORS["panel"],
                  fg=COLORS["bad"], relief="flat", font=("Consolas", 11, "bold"),
                  width=10, height=2, cursor="hand2").pack(side="left", padx=6)

    def _do_activate(self):
        code = self._code_var.get().strip()
        if not code:
            self._act_status.config(text="Please enter your activation code.", fg=COLORS["bad"])
            return
        res = xdr_license.activate(code, _PRODUCT)
        if res["ok"]:
            for w in self.winfo_children():
                w.destroy()
            self.title("Cyber Sentinel XDR - Server Control Panel")
            self._license_status = xdr_license.check_license(_PRODUCT)
            self._build_ui()
            self._poll_status()
        else:
            self._act_status.config(text=res["message"], fg=COLORS["bad"])

    def _build_ui(self):
        tk.Label(self, text="CYBER SENTINEL XDR", bg=COLORS["bg"], fg=COLORS["accent"],
                 font=("Consolas", 18, "bold")).pack(pady=(16, 0))
        tk.Label(self, text="Server Control Panel", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 10)).pack(pady=(0, 4))

        # License banner (trial countdown / licensed)
        st = self._license_status or {}
        if st.get("kind") == "universal":
            lic_txt, lic_col = "Licensed", COLORS["ok"]
        elif st.get("remaining") is not None:
            lic_txt = f"Trial license - {xdr_license.format_remaining(st['remaining'])} remaining"
            lic_col = COLORS["ok"] if st["remaining"] > 86400 else COLORS["accent"]
        else:
            lic_txt, lic_col = "Licensed", COLORS["ok"]
        tk.Label(self, text=lic_txt, bg=COLORS["bg"], fg=lic_col,
                 font=("Consolas", 8, "bold")).pack(pady=(0, 8))

        # --- Endpoint URL (what to paste into endpoint agents) ---
        self._ip = self._lan_ip()
        epf = tk.Frame(self, bg=COLORS["panel"])
        epf.pack(fill="x", padx=28, pady=(0, 4))
        tk.Label(epf, text="Endpoint URL:", bg=COLORS["panel"], fg=COLORS["muted"],
                 font=("Consolas", 9)).pack(side="left", padx=(8, 4), pady=6)
        self.epurl = tk.StringVar(value=self._endpoint_url())
        tk.Label(epf, textvariable=self.epurl, bg=COLORS["panel"], fg=COLORS["ok"],
                 font=("Consolas", 11, "bold")).pack(side="left", pady=6)
        tk.Button(epf, text="Copy", command=self._copy_url, bg=COLORS["bg"], fg=COLORS["accent"],
                  relief="flat", font=("Consolas", 8), cursor="hand2").pack(side="right", padx=8)
        tk.Label(self, text="Give this Endpoint URL + the API Key (below) to each endpoint agent.",
                 bg=COLORS["bg"], fg=COLORS["hint"], font=("Consolas", 8)).pack(padx=30, pady=(0, 6))

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
        self.status.pack(pady=(12, 2))

        # --- Progress bar (hidden until a long operation runs, e.g. MongoDB install) ---
        style = ttk.Style(self)
        try:
            style.theme_use("clam")  # 'clam' honours custom colours reliably
        except tk.TclError:
            pass
        style.configure("XDR.Horizontal.TProgressbar", troughcolor=COLORS["entry"],
                        background=COLORS["accent"], bordercolor=COLORS["bg"],
                        lightcolor=COLORS["accent"], darkcolor=COLORS["accent"])
        self.progbar = ttk.Progressbar(self, style="XDR.Horizontal.TProgressbar",
                                       mode="indeterminate", length=520)
        self.prog_label = tk.Label(self, text="", bg=COLORS["bg"], fg=COLORS["accent"],
                                   font=("Consolas", 8), wraplength=640, justify="center")
        # Not packed yet - shown on demand via _progress_show().
        self._progress_active = False

        row1 = tk.Frame(self, bg=COLORS["bg"]); row1.pack(pady=4)
        self._btn(row1, "Test Database", self._test_db, COLORS["accent"])
        self._btn(row1, "Setup Local DB", self._setup_local, COLORS["accent"])
        self._btn(row1, "Save Config", self._save, COLORS["accent"])
        row2 = tk.Frame(self, bg=COLORS["bg"]); row2.pack(pady=4)
        self._btn(row2, "Start Server", self._start, COLORS["ok"])
        self._btn(row2, "Stop Server", self._stop, COLORS["bad"])
        self._btn(row2, "Open Dashboard", self._open_dash, COLORS["accent"])

        # --- Network detection prerequisites (Suricata + Npcap) ---
        tk.Label(self, text="Network Detection (optional)", bg=COLORS["bg"], fg=COLORS["fg"],
                 font=("Consolas", 9, "bold")).pack(pady=(14, 0))
        tk.Label(self, text="Required for port-scan / DDoS / C2-beaconing detection. Not required for the "
                             "dashboard, malware, system or user-behavior detection to work.",
                 bg=COLORS["bg"], fg=COLORS["hint"], font=("Consolas", 8),
                 wraplength=620, justify="center").pack(pady=(0, 4))
        row3 = tk.Frame(self, bg=COLORS["bg"]); row3.pack(pady=4)
        self._btn(row3, f"Install Suricata {SURICATA_VERSION}", self._open_suricata_download, COLORS["accent"])
        self._btn(row3, f"Install Npcap {NPCAP_VERSION}", self._open_npcap_download, COLORS["accent"])

        tk.Label(self, text=f"Config file: {ENV_PATH}", bg=COLORS["bg"], fg=COLORS["muted"],
                 font=("Consolas", 8)).pack(side="bottom", pady=8)
        self._on_db_type()

    # ---- Network detection prerequisites ------------------------------------
    def _open_suricata_download(self):
        webbrowser.open(SURICATA_DOWNLOAD_URL)

    def _open_npcap_download(self):
        webbrowser.open(NPCAP_DOWNLOAD_URL)

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
            self.hint.config(text="Local mode: uses a MongoDB installed on THIS computer. No account, username or "
                                  "password is needed - local MongoDB has no login. Click 'Setup Local DB' to "
                                  "download + install it automatically (shows a progress %). The 27 collections "
                                  "are created automatically on first start.")
            self._local_status()
        else:
            if "localhost" in self.uri.get() or "127.0.0.1" in self.uri.get():
                self.uri.set(self._atlas_cache)
            self.hint.config(text="Atlas mode: paste your MongoDB Atlas connection string. Tip: if a "
                                  "mongodb+srv:// link fails with a DNS error, use the STANDARD string "
                                  "(mongodb:// with 3 servers) from Atlas -> Connect -> Drivers.")

    # ---- Local MongoDB detection + guided install --------------------------
    def _mongo_running(self):
        try:
            s = socket.create_connection(("127.0.0.1", 27017), timeout=2); s.close(); return True
        except Exception:
            return False

    def _mongo_installed(self):
        if shutil.which("mongod"):
            return True
        if glob.glob(r"C:\Program Files\MongoDB\Server\*\bin\mongod.exe"):
            return True
        try:
            out = subprocess.run(["sc", "query", "MongoDB"], creationflags=CREATE_NO_WINDOW,
                                 capture_output=True, text=True)
            if "STATE" in (out.stdout or ""):
                return True
        except Exception:
            pass
        return False

    def _local_status(self):
        def work():
            if self._mongo_running():
                self.status.config(text="Local MongoDB: RUNNING and reachable - click Test Database.", fg=COLORS["ok"])
            elif self._mongo_installed():
                self.status.config(text="MongoDB is installed but NOT running - click 'Setup Local DB' to start it.",
                                   fg=COLORS["muted"])
            else:
                self.status.config(text="MongoDB is NOT installed - click 'Setup Local DB' to install it.",
                                   fg=COLORS["bad"])
        threading.Thread(target=work, daemon=True).start()

    def _setup_local(self):
        """Detect -> start service if installed, or offer to install MongoDB Community."""
        if self._mongo_running():
            messagebox.showinfo("Ready", "Local MongoDB is already running.\n\nMake sure Database is set to "
                                "'Local MongoDB', click Save Config, then Start Server.")
            self._local_status(); return
        if self._mongo_installed():
            try:
                subprocess.run(["net", "start", "MongoDB"], creationflags=CREATE_NO_WINDOW, capture_output=True)
            except Exception:
                pass
            if self._mongo_running():
                messagebox.showinfo("Started", "Local MongoDB service started. Click Test Database.")
            else:
                messagebox.showwarning("Manual start needed",
                    "MongoDB is installed but couldn't be started automatically (needs admin).\n\n"
                    "Open Services (services.msc), find 'MongoDB', right-click -> Start. "
                    "Or run this in an admin PowerShell:\n\n    net start MongoDB")
            self._local_status(); return
        # Not installed -> offer winget auto-install, else the download page
        choice = messagebox.askyesno("Install MongoDB",
            "MongoDB is not installed on this computer.\n\n"
            "Install it automatically now with winget?\n"
            "(needs internet + admin approval; takes a few minutes)\n\n"
            "Yes = auto-install    No = open the download page")
        if choice:
            self._install_mongodb()
        else:
            webbrowser.open("https://www.mongodb.com/try/download/community")
            messagebox.showinfo("Manual install",
                "Download 'MongoDB Community Server' (MSI), install with the default options "
                "(keep 'Install as a Windows Service' checked), then come back and click "
                "'Setup Local DB' again.")

    # ---- Progress bar helpers (thread-safe: worker threads call via self.after) ----
    def _progress_show(self, text=""):
        """Reveal the progress bar in animated (marquee) mode."""
        if not self._progress_active:
            self.progbar.pack(padx=40, pady=(2, 0), fill="x")
            self.prog_label.pack(padx=30, pady=(2, 6))
            self._progress_active = True
        self.progbar.config(mode="indeterminate")
        try:
            self.progbar.start(12)
        except tk.TclError:
            pass
        if text:
            self.prog_label.config(text=text)

    def _progress_text(self, text):
        """Update the phase/percent line under the bar."""
        if self._progress_active:
            self.prog_label.config(text=text)

    def _progress_percent(self, pct, text=""):
        """Switch the bar to a precise value (0-100) when we have a real percentage."""
        if not self._progress_active:
            return
        try:
            self.progbar.stop()
        except tk.TclError:
            pass
        self.progbar.config(mode="determinate", maximum=100, value=max(0, min(100, pct)))
        if text:
            self.prog_label.config(text=text)

    def _progress_hide(self):
        try:
            self.progbar.stop()
        except tk.TclError:
            pass
        if self._progress_active:
            self.progbar.pack_forget()
            self.prog_label.pack_forget()
            self._progress_active = False

    @staticmethod
    def _winget_phase(line):
        """Map a raw winget output line to a friendly phase message (or '' to ignore)."""
        low = line.lower()
        if "found" in low and "mongodb" in low:
            return "Found MongoDB Community - starting download..."
        if "downloading" in low:
            return "Downloading MongoDB Community..."
        if "verifying" in low or "hash" in low:
            return "Verifying download..."
        if "installing" in low:
            return "Installing MongoDB (this is the longest step)..."
        if "successfully installed" in low or "successfully" in low:
            return "Install finished - starting the database service..."
        if "restart" in low:
            return "Install finished - a restart may be required."
        return ""

    # ---- Direct MongoDB download+install with a REAL percentage bar ------------
    def _fetch_mongo_msi_url(self):
        """Resolve the latest production MongoDB Community Windows MSI URL + version."""
        req = urllib.request.Request(MONGO_CURRENT_JSON, headers={"User-Agent": "CyberSentinelXDR"})
        with urllib.request.urlopen(req, timeout=30) as r:
            data = json.loads(r.read().decode("utf-8", "replace"))

        def pick(versions, prod_only):
            for v in versions:
                if prod_only and not v.get("production_release", False):
                    continue
                for d in v.get("downloads", []):
                    if ("windows" in str(d.get("target", "")).lower()
                            and d.get("arch") == "x86_64" and d.get("edition") == "base"
                            and d.get("msi")):
                        return d["msi"], v.get("version")
            return None, None

        versions = data.get("versions", [])
        url, ver = pick(versions, True)
        if not url:
            url, ver = pick(versions, False)
        return url, ver

    def _emit_dl_progress(self, done, total, elapsed):
        mb = done / 1048576.0
        speed = (done / elapsed / 1048576.0) if elapsed > 0 else 0.0
        if total > 0:
            pct = min(100, int(done * 100 / total))
            tot_mb = total / 1048576.0
            eta = ((total - done) / (done / elapsed)) if (done > 0 and elapsed > 0) else 0
            txt = ("Downloading MongoDB  %d%%   %.0f / %.0f MB   %.1f MB/s   ETA %dm %02ds"
                   % (pct, mb, tot_mb, speed, int(eta // 60), int(eta % 60)))
            self.after(0, lambda p=pct, t=txt: self._progress_percent(p, t))
        else:
            txt = "Downloading MongoDB  %.0f MB   %.1f MB/s" % (mb, speed)
            self.after(0, lambda t=txt: self._progress_show(t))

    def _download_with_progress(self, url, dest):
        req = urllib.request.Request(url, headers={"User-Agent": "CyberSentinelXDR"})
        with urllib.request.urlopen(req, timeout=60) as r:
            total = int(r.headers.get("Content-Length", 0) or 0)
            done, start, last_ui = 0, time.time(), 0.0
            with open(dest, "wb") as f:
                while True:
                    chunk = r.read(262144)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    now = time.time()
                    if now - last_ui >= 0.4:
                        last_ui = now
                        self._emit_dl_progress(done, total, now - start)
            self._emit_dl_progress(done, total, max(0.001, time.time() - start))
        return (total == 0) or (done >= total)

    def _install_mongodb(self):
        """Primary path: download the official MSI (with a % bar) and install it as
        a Windows service. Falls back to winget, then to the download page."""
        self.after(0, lambda: self._progress_show("Locating the latest MongoDB Community installer..."))
        self.after(0, lambda: self.status.config(
            text="Installing MongoDB (large download, ~800 MB). Keep this window open - the % and ETA below "
                 "update live; total time depends on your internet speed.",
            fg=COLORS["accent"]))

        def work():
            url, ver = None, None
            try:
                url, ver = self._fetch_mongo_msi_url()
            except Exception:
                url = None

            if url:
                msi = os.path.join(tempfile.gettempdir(), "cyber_sentinel_mongodb.msi")
                try:
                    self.after(0, lambda v=ver: self._progress_show(
                        "Downloading MongoDB %s ..." % (v or "Community")))
                    ok = self._download_with_progress(url, msi)
                    if ok and os.path.exists(msi) and os.path.getsize(msi) > 50 * 1024 * 1024:
                        self.after(0, lambda: self._progress_show(
                            "Installing MongoDB as a Windows service (about a minute)..."))
                        # Documented MongoDB unattended install: server + service, no Compass.
                        subprocess.run(
                            ["msiexec", "/i", msi, "/qn", "/norestart",
                             'ADDLOCAL=ServerService,Client', 'SHOULD_INSTALL_COMPASS=0'],
                            creationflags=CREATE_NO_WINDOW)
                        self._finish_mongo_install()
                        return
                    else:
                        self.after(0, lambda: self._progress_show(
                            "Direct download incomplete - trying winget instead..."))
                except Exception:
                    self.after(0, lambda: self._progress_show(
                        "Direct download failed - trying winget instead..."))
                finally:
                    try:
                        os.remove(msi)
                    except Exception:
                        pass

            # Fallback path (no percentage, but works if the direct download is blocked).
            self._winget_install_fallback()

        threading.Thread(target=work, daemon=True).start()

    def _finish_mongo_install(self):
        try:
            subprocess.run(["net", "start", "MongoDB"], creationflags=CREATE_NO_WINDOW, capture_output=True)
        except Exception:
            pass
        self.after(0, self._progress_hide)
        if self._mongo_running():
            self.after(0, self._auto_config_local_after_install)
        elif self._mongo_installed():
            self.after(0, lambda: self.status.config(
                text="MongoDB installed. Click 'Setup Local DB' once more to start the service.",
                fg=COLORS["muted"]))
        else:
            self.after(0, lambda: self.status.config(
                text="Install could not be confirmed - see mongodb.com/try/download/community to install manually.",
                fg=COLORS["bad"]))

    def _auto_config_local_after_install(self):
        """MongoDB is up: switch to Local, save .env, and tell the user no account is needed."""
        self.db_type.set("local")
        self.uri.set(LOCAL_URI)
        saved_ok = True
        try:
            write_env({"MONGO_URI": LOCAL_URI, "BACKEND_HOST": "0.0.0.0",
                       "BACKEND_PORT": self._port_val()})
        except Exception:
            saved_ok = False
        self.status.config(text="Local MongoDB is installed, running, and configured. Click 'Start Server'.",
                           fg=COLORS["ok"])
        msg = ("MongoDB is installed and running on this computer.\n\n"
               "No account, username, or password is needed - local MongoDB has no login. "
               "Cyber Sentinel XDR creates all of its collections automatically the first time "
               "the server starts.\n\n")
        msg += ("I've set the database to 'Local MongoDB' and saved the configuration for you.\n\n"
                if saved_ok else
                "Set Database to 'Local MongoDB' and click 'Save Config'.\n\n")
        msg += "Next step: click 'Start Server', then 'Open Dashboard'."
        messagebox.showinfo("MongoDB ready", msg)
        self._local_status()

    def _winget_install_fallback(self):
        """Secondary installer via winget (streamed; no reliable percentage)."""
        self.after(0, lambda: self._progress_show("Installing MongoDB via winget (fallback)..."))
        try:
            proc = subprocess.Popen(
                ["winget", "install", "-e", "--id", "MongoDB.Server",
                 "--accept-package-agreements", "--accept-source-agreements",
                 "--disable-interactivity"],
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace",
                bufsize=1, creationflags=CREATE_NO_WINDOW)
        except FileNotFoundError:
            self.after(0, self._progress_hide)
            self.after(0, lambda: self.status.config(
                text="Could not auto-install - opening the MongoDB download page...", fg=COLORS["bad"]))
            webbrowser.open("https://www.mongodb.com/try/download/community")
            return
        except Exception as e:
            self.after(0, self._progress_hide)
            self.after(0, lambda: self.status.config(text="Install error: " + str(e)[:80], fg=COLORS["bad"]))
            return
        try:
            for raw in iter(proc.stdout.readline, ""):
                phase = self._winget_phase(raw.strip())
                if phase:
                    self.after(0, lambda ph=phase: self._progress_show(ph))
        except Exception:
            pass
        proc.wait()
        self._finish_mongo_install()

    def _lan_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.settimeout(1)
            s.connect(("8.8.8.8", 80)); ip = s.getsockname()[0]; s.close(); return ip
        except Exception:
            return "127.0.0.1"

    def _endpoint_url(self):
        ip = getattr(self, "_ip", None) or self._lan_ip()
        return f"http://{ip}:{self._port_val()}"

    def _copy_url(self):
        self.clipboard_clear(); self.clipboard_append(self._endpoint_url())
        self.status.config(text="Endpoint URL copied to clipboard.", fg=COLORS["accent"])

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
            self.status.config(text="Server stopped. Dashboard is now offline (you can close its browser tab).", fg=COLORS["muted"])
        except Exception as e:
            messagebox.showerror("Stop failed", str(e))

    def _open_dash(self):
        webbrowser.open(f"http://localhost:{self._port_val()}/")

    def _poll_status(self):
        if hasattr(self, "epurl"):
            self.epurl.set(self._endpoint_url())
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
        # Don't clobber an in-progress long operation (e.g. MongoDB install).
        if getattr(self, "_progress_active", False):
            return
        cur = self.status.cget("text")
        if (cur.startswith("Testing") or cur.startswith("Server starting")
                or cur.startswith("Database:") or cur.startswith("Installing MongoDB")):
            return
        if running:
            db = "DB connected" if mongo else ("DB OFFLINE" if mongo is False else "DB checking")
            col = COLORS["ok"] if mongo else COLORS["bad"] if mongo is False else COLORS["muted"]
            self.status.config(text=f"Server: RUNNING  |  {db}", fg=col)
        else:
            self.status.config(text="Server: STOPPED", fg=COLORS["muted"])


def _headless_cli(argv) -> int:
    """Installer-facing license CLI (no GUI). Returns a process exit code.
        ServerControl.exe --activate <CODE>   -> validate + persist, 0 on success
        ServerControl.exe --license-status    -> 0 if activated, 1 otherwise
    """
    if not _LICENSING:
        print("Licensing module unavailable.")
        return 1
    cmd = argv[0]
    if cmd == "--activate":
        code = argv[1] if len(argv) > 1 else ""
        res = xdr_license.activate(code, _PRODUCT)
        print(("OK: " if res["ok"] else "FAIL: ") + res["message"])
        return 0 if res["ok"] else 1
    if cmd == "--license-status":
        st = xdr_license.check_license(_PRODUCT)
        print(f"{st['status']}: {st['message']}")
        return 0 if st["status"] == "ACTIVE" else 1
    print("Unknown option.")
    return 2


if __name__ == "__main__":
    _argv = sys.argv[1:]
    if _argv and _argv[0] in ("--activate", "--license-status"):
        sys.exit(_headless_cli(_argv))
    ControlPanel().mainloop()
