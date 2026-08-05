# -*- mode: python ; coding: utf-8 -*-
from PyInstaller.utils.hooks import collect_submodules, collect_all

hiddenimports = []
hiddenimports += collect_submodules('pymongo')
hiddenimports += collect_submodules('dns')

# certifi's *module* gets auto-detected via pymongo's own conditional import, but
# PyInstaller's default analysis doesn't bundle its cacert.pem *data* file unless
# told to - without it, certifi.where() (used by _test_db()'s tlsCAFile) points at
# a path that doesn't exist inside the frozen exe and every Atlas TLS handshake
# fails. backend.spec already force-collects this; ServerControl.spec did not.
datas = []
binaries = []
_certifi_datas, _certifi_binaries, _certifi_hidden = collect_all('certifi')
datas += _certifi_datas
binaries += _certifi_binaries
hiddenimports += _certifi_hidden

a = Analysis(
    ['server_control.py'],
    pathex=[],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='ServerControl',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    uac_admin=True,
)
