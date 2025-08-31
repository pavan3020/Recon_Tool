# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['automatic_recon_gui.py'],
    pathex=[],
    binaries=[],
    datas=[('output', 'output'), ('assets', 'assets'), ('C:/msys64/ucrt64/lib/python3.11/site-packages/builtwith/apps.json.py', 'builtwith')],
    hiddenimports=[],
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
    name='automatic_recon_gui',
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
)
