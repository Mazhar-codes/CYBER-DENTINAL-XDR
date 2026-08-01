# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for the Cyber Sentinel XDR **backend server** (onedir).

Produces packaging/dist/backend/backend.exe plus its _internal folder. onedir
(NOT onefile) is mandatory here — the ML stack (torch ~500 MB) makes a onefile
exe multi-GB and painfully slow to start (it would re-extract to temp each run).

Model files are bundled preserving the dev layout (<bundle>/Backend,
<bundle>/User Behavior, <bundle>/System Behavior) so config.py's frozen-aware
BASE_DIR (= sys._MEIPASS/Backend) resolves them exactly as in development.

Build via packaging/build_backend.ps1 (uses the Backend venv, which already has
torch + all deps, so nothing heavy is re-downloaded).
"""
import glob
import os
import sys

from PyInstaller.utils.hooks import collect_all, collect_submodules

# PyInstaller sets SPECPATH to the directory CONTAINING this .spec (packaging/),
# not a file path — so use it directly, do NOT take its dirname.
SPEC_DIR    = os.path.abspath(SPECPATH)
REPO_DIR    = os.path.normpath(os.path.join(SPEC_DIR, ".."))
BACKEND_DIR = os.path.join(REPO_DIR, "Backend")

# Make the backend's own flat modules importable during analysis.
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

# ---------------------------------------------------------------------------
# 1. Bundle model artifacts, preserving the repo-relative layout.
# ---------------------------------------------------------------------------
datas = []

# Backend/*.pkl, *.pt, *.jpg, *.json  ->  <bundle>/Backend
for pat in ("*.pkl", "*.pt", "*.jpg", "*.json"):
    for f in glob.glob(os.path.join(BACKEND_DIR, pat)):
        datas.append((f, "Backend"))

# User Behavior/final_model_backend_only/*  ->  same relative path
_ub = os.path.join(REPO_DIR, "User Behavior", "final_model_backend_only")
_ub_dest = os.path.join("User Behavior", "final_model_backend_only")
_ub_bundled = set()
for f in glob.glob(os.path.join(_ub, "*")):
    if os.path.isfile(f):
        datas.append((f, _ub_dest))
        _ub_bundled.add(os.path.basename(f))

# These three are load-bearing for the User Behavior agent (xdr_runtime import +
# IsolationForest model + scaler). A build that ships without them boots with
# "xdr_runtime not importable ... UserBehaviorAgent will return empty results" and
# the insider-threat layer is silently dead. Fail the build LOUD instead.
_ub_required = ("xdr_runtime.py", "user_model.pkl", "user_scaler.pkl")
_ub_missing = [f for f in _ub_required if f not in _ub_bundled]
if _ub_missing:
    raise SystemExit(
        f"[backend.spec] FATAL: required User Behavior files missing from "
        f"{_ub}: {_ub_missing}. The frozen server would run without the user-"
        f"behavior model. Restore these files before building."
    )

# System Behavior/.../DETECTOR1/**  ->  same relative tree (models + source .py)
_sb = os.path.join(REPO_DIR, "System Behavior", "System_Behavior_Model", "DETECTOR1")
for root, _dirs, files in os.walk(_sb):
    for fn in files:
        full = os.path.join(root, fn)
        dest = os.path.relpath(root, REPO_DIR)
        datas.append((full, dest))

# Built React dashboard  ->  <bundle>/frontend  (served same-origin by backend;
# config.py frozen frontend_dir = sys._MEIPASS/frontend).
_fe_build = os.path.join(REPO_DIR, "Cyber Sentinal XDR Frontend", "build")
if os.path.isdir(_fe_build):
    for root, _dirs, files in os.walk(_fe_build):
        for fn in files:
            full = os.path.join(root, fn)
            dest = os.path.join("frontend", os.path.relpath(root, _fe_build))
            datas.append((full, dest))
else:
    print(f"[backend.spec] WARNING: dashboard build not found at {_fe_build} "
          f"(run `npm run build` first) — server will be API-only")

# ---------------------------------------------------------------------------
# 2. Collect heavy third-party packages (data + binaries + submodules).
# ---------------------------------------------------------------------------
binaries = []
hiddenimports = []

for pkg in (
    "torch", "sklearn", "scipy", "numpy", "pandas", "shap", "xgboost", "lightgbm",
    "reportlab", "pymongo", "dns", "engineio", "socketio", "uvicorn", "pefile",
    "joblib", "pyotp", "qrcode", "jose", "passlib", "bcrypt", "numba", "llvmlite",
    "dateutil", "certifi", "anyio", "sniffio", "h11", "click", "dotenv",
):
    try:
        d, b, h = collect_all(pkg)
        datas += d
        binaries += b
        hiddenimports += h
    except Exception as exc:  # package not installed — skip
        print(f"[backend.spec] collect_all skipped {pkg}: {exc}")

# ---------------------------------------------------------------------------
# 3. The app's own modules + framework internals that are imported dynamically.
# ---------------------------------------------------------------------------
hiddenimports += [
    "config", "backend", "fusion_engine", "response_engine",
    "report_generator", "attack_graph",
    "uvicorn.logging", "uvicorn.loops.auto",
    "uvicorn.protocols.http.auto", "uvicorn.protocols.websockets.auto",
    "uvicorn.lifespan.on",
    "engineio.async_drivers.asgi",
]
for pkg in ("agents", "auth"):
    try:
        hiddenimports += collect_submodules(pkg)
    except Exception as exc:
        print(f"[backend.spec] collect_submodules skipped {pkg}: {exc}")

# ---------------------------------------------------------------------------
# 4. Analysis / build.
# ---------------------------------------------------------------------------
a = Analysis(
    [os.path.join(SPEC_DIR, "backend_entry.py")],
    pathex=[BACKEND_DIR, REPO_DIR],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tensorflow", "tkinter", "matplotlib.tests", "torch.test"],
    noarchive=False,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,   # onedir: binaries go into _internal, not the exe
    name="backend",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,               # UPX + torch DLLs is a known crash source — keep off
    console=True,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="backend",
)
