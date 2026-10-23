# -*- mode: python ; coding: utf-8 -*-
"""
Сборка GUI Mail Forensic Pro (основная ветка).

Запуск из каталога Scripts/Analyzer_App:
  pyinstaller --clean MailForensicPro.spec
"""
from pathlib import Path
from typing import Optional, Tuple
import site


def _app_dir() -> Path:
    for key in ("SPEC", "SPECPATH"):
        raw = globals().get(key)
        if not raw:
            continue
        p = Path(raw)
        if p.is_file() and p.suffix.lower() == ".spec":
            return p.parent.resolve()
        if p.is_dir():
            return p.resolve()
    return Path(__file__).resolve().parent


def _tkinterdnd2() -> Optional[Tuple[str, str]]:
    candidates: list[Path] = []
    try:
        candidates.append(Path(site.getusersitepackages()))
    except Exception:
        pass
    try:
        candidates.extend(Path(p) for p in site.getsitepackages())
    except Exception:
        pass
    for root in candidates:
        if not root:
            continue
        cand = root / "tkinterdnd2"
        if cand.is_dir():
            return str(cand), "tkinterdnd2"
    return None


APP_DIR = _app_dir()
PROJECT_ROOT = APP_DIR.parents[1]
SCRIPTS_DIR = PROJECT_ROOT / "01_Core_Engines" if (PROJECT_ROOT / "01_Core_Engines").is_dir() else APP_DIR.parent

datas = [(str(SCRIPTS_DIR), "Scripts")]
_tk = _tkinterdnd2()
if _tk:
    datas.append(_tk)

a = Analysis(
    [str(APP_DIR / "mail_forensic_pro.py")],
    pathex=[str(APP_DIR)],
    binaries=[],
    datas=datas,
    hiddenimports=["tkinterdnd2", "requests"],
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
    name="MailForensicPro",
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
