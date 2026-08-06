# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for the Cyber Sentinel XDR **endpoint agent**.

Produces a single self-contained CyberSentinelAgent.exe that needs no Python,
no pip, and no dependencies on the target machine — everything is baked in.

Build:
    pyinstaller --clean --noconfirm packaging/agent.spec
(or run packaging/build_agent.ps1 which sets up the environment first.)

The agent's only real dependencies are httpx + psutil; the entire ML stack is
excluded so the exe stays small (~15-20 MB) and builds fast.
"""
import os

# SPECPATH is injected by PyInstaller; it is the folder containing this .spec.
AGENT_DIR = os.path.normpath(os.path.join(SPECPATH, "..", "endpoint_agent"))

a = Analysis(
    [os.path.join(AGENT_DIR, "agent.py")],
    pathex=[AGENT_DIR],
    binaries=[],
    datas=[],
    hiddenimports=[
        # agent.py imports these flat (after sys.path.insert of the agent dir)
        "identity", "sender", "honeypot", "command_listener", "xdr_license",
        "collectors",
        "collectors.network_collector",
        "collectors.system_collector",
        "collectors.user_collector",
        "collectors.malware_collector",
        # runtime deps
        "httpx", "psutil",
    ],
    hookspath=[],
    runtime_hooks=[],
    # The endpoint agent does NOT use the ML stack — exclude it to keep the exe
    # small and prevent PyInstaller from dragging in huge optional libraries.
    excludes=[
        "torch", "tensorflow", "sklearn", "scipy", "numpy", "pandas",
        "lightgbm", "xgboost", "shap", "matplotlib", "PIL", "cv2",
        "notebook", "IPython",
    ],
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="CyberSentinelAgent",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    # No console: the boot-time scheduled task runs this non-interactively as
    # SYSTEM (no window regardless), and AgentControl.exe's Start Agent always
    # redirects stdout/stderr to agent_out.log/agent_err.log - so a console
    # subsystem only ever risked an unwanted flash if launched some other way.
    # For `--simulate` testing, run from source instead: `python agent.py --simulate`.
    console=False,
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
