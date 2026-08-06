# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller build spec for the Cyber Sentinel XDR **Endpoint Agent Control
Panel** (agent_control.py) - a small Tkinter GUI shipped alongside
CyberSentinelAgent.exe so operators can edit backend URL / API key /
intervals and Start/Stop the agent without re-running the installer.

Build:
    pyinstaller --clean --noconfirm packaging/AgentControl.spec
(or packaging/build_agent_control.ps1, which sets up the environment first.)
"""

a = Analysis(
    ['agent_control.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        "torch", "tensorflow", "sklearn", "scipy", "numpy", "pandas",
        "lightgbm", "xgboost", "shap", "matplotlib", "PIL", "cv2",
        "notebook", "IPython",
    ],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AgentControl',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    # GUI app - no console window.
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    # SOAR command execution (block_ip/isolate_host/etc.) needs Administrator;
    # CyberSentinelAgent.exe already warns loudly when it isn't elevated, so
    # this panel requests elevation up front like ServerControl.exe does,
    # and CyberSentinelAgent.exe inherits that elevated token when launched
    # from here.
    uac_admin=True,
)
