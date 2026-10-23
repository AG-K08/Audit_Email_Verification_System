# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block4_activex.py
Назначение: Блок 4: Анализ элементов управления ActiveX и внедренных форм.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import json
import logging
import sys
import time
import uuid
from pathlib import Path

try:
    import olefile
except ImportError:
    olefile = None

from core.models import BlockResult, ThreatIndicator, ThreatLevel

log = logging.getLogger("Block4")

BLOCK_NAME = "block4_activex"

ACTIVEX_COUNT_THRESHOLD = 150
CLSID_DB_PATH = Path(__file__).parent.parent / "core" / "clsid_db.json"

DANGEROUS_PROGID_PATTERNS: dict[str, tuple[ThreatLevel, str]] = {
    "WScript.Shell":              (ThreatLevel.HIGH,     "Windows Script Host Shell"),
    "Shell.Application":          (ThreatLevel.HIGH,     "Shell.Application — навигация и выполнение"),
    "Scripting.FileSystemObject": (ThreatLevel.HIGH,     "FileSystemObject — доступ к файловой системе"),
    "MSXML2.XMLHTTP":             (ThreatLevel.HIGH,     "HTTP-запросы через MSXML"),
    "Microsoft.XMLHTTP":          (ThreatLevel.HIGH,     "HTTP-запросы через XMLHTTP"),
    "WScript":                    (ThreatLevel.MEDIUM,   "Windows Script Host"),
    "Scriptlet.TypeLib":          (ThreatLevel.CRITICAL, "Scriptlet.TypeLib — уязвимый компонент"),
    "MSScriptControl":            (ThreatLevel.HIGH,     "Script Control — выполнение скриптов"),
}

WINREG_AVAILABLE = sys.platform == "win32"


def run(block0_raw: dict) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {"activex_objects": []}

    clsid_db = _load_clsid_db()
    registry_cache: dict[str, dict | None] = {}
    temp_dir_str = block0_raw.get("temp_dir")
    file_format = block0_raw.get("file_format", "unknown")

    if not temp_dir_str:
        return BlockResult(
            block_name=BLOCK_NAME,
            success=False,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            error_message="temp_dir не передан из Block0",
        )

    temp_dir = Path(temp_dir_str)

    if file_format == "openxml":
        activex_objects = _parse_openxml_activex(temp_dir)
    elif file_format == "ole2":
        activex_objects = _parse_ole2_activex(temp_dir)
    else:
        activex_objects = []

    raw["activex_objects"] = activex_objects
    raw["activex_count"] = len(activex_objects)

    eval_result = _evaluate_activex_objects(activex_objects, clsid_db, registry_cache)
    indicators.extend(eval_result["indicators"])
    raw["activex_whitelist_count"] = eval_result["whitelist_count"]
    raw["activex_suspicious_count"] = eval_result["suspicious_count"]

    suspicious_count = eval_result["suspicious_count"]
    if suspicious_count > ACTIVEX_COUNT_THRESHOLD:
        indicators.append(
            _build_activex_count_indicator(
                activex_objects,
                eval_result["whitelist_count"],
                suspicious_count,
            )
        )

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _build_activex_count_indicator(
    activex_objects: list[dict],
    whitelist_count: int,
    suspicious_count: int,
) -> ThreatIndicator:
    unique_clsids = sorted({
        obj["clsid"]
        for obj in activex_objects
        if obj.get("clsid")
    })

    clsid_lines = [f"  {clsid}" for clsid in unique_clsids]
    clsid_block = "\n".join(clsid_lines)

    evidence = (
        f"Всего объектов: {len(activex_objects)}, "
        f"из них легитимных (whitelist): {whitelist_count} — не учитываются в счётчике\n"
        f"Подозрительных: {suspicious_count}, "
        f"уникальных CLSID: {len(unique_clsids)}\n"
        f"{clsid_block}"
    )

    return ThreatIndicator(
        indicator_id="B4.ACTIVEX_COUNT",
        level=ThreatLevel.MEDIUM,
        description=(
            f"Аномально большое количество подозрительных ActiveX-объектов: {suspicious_count} "
            f"(всего в документе: {len(activex_objects)}, "
            f"легитимных MSForms/whitelist: {whitelist_count}). "
            f"Уникальных CLSID: {len(unique_clsids)} — "
            f"если все CLSID легитимны (кнопки, чекбоксы), угроза низкая."
        ),
        evidence=evidence,
        location="document",
    )


def _load_clsid_db() -> dict:
    try:
        with CLSID_DB_PATH.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as exc:
        log.warning("Не удалось загрузить clsid_db.json: %s", exc)
        return {}


def _parse_openxml_activex(temp_dir: Path) -> list[dict]:
    objects: list[dict] = []
    for bin_file in temp_dir.rglob("activeX*.bin"):
        clsid = _extract_clsid_from_bin(bin_file)
        objects.append({
            "source": bin_file.name,
            "clsid": clsid,
            "format": "openxml",
        })
    return objects


def _parse_ole2_activex(temp_dir: Path) -> list[dict]:
    objects: list[dict] = []
    for bin_file in temp_dir.rglob("*.bin"):
        if bin_file.name.lower().startswith("vbaproject"):
            continue
        if not olefile.isOleFile(bin_file):
            continue
        try:
            with olefile.OleFileIO(str(bin_file)) as ole:
                clsid = _extract_clsid_from_ole(ole)
                if clsid:
                    objects.append({
                        "source": bin_file.name,
                        "clsid": clsid,
                        "format": "ole2",
                    })
        except Exception as exc:
            log.debug("Не удалось прочитать OLE2 ActiveX %s: %s", bin_file.name, exc)
    return objects


def _extract_clsid_from_bin(bin_file: Path) -> str | None:
    try:
        data = bin_file.read_bytes()
        if len(data) < 20:
            return None
        clsid_bytes = data[4:20]
        parsed = uuid.UUID(bytes_le=clsid_bytes)
        return "{" + str(parsed).upper() + "}"
    except Exception:
        return None


def _extract_clsid_from_ole(ole: olefile.OleFileIO) -> str | None:
    try:
        clsid = ole.root.clsid
        if clsid and clsid != "00000000-0000-0000-0000-000000000000":
            return "{" + clsid.upper() + "}"
        return None
    except Exception:
        return None


def _evaluate_activex_objects(
    objects: list[dict],
    clsid_db: dict,
    registry_cache: dict,
) -> dict:
    indicators: list[ThreatIndicator] = []
    whitelist_count = 0
    suspicious_count = 0
    seen_clsids: set[str] = set()

    for obj in objects:
        clsid = obj.get("clsid")
        if not clsid or clsid in seen_clsids:
            continue
        seen_clsids.add(clsid)

        db_entry = clsid_db.get(clsid)

        if db_entry and db_entry.get("whitelist"):
            whitelist_count += 1
            indicators.append(ThreatIndicator(
                indicator_id="B4.CLSID_WHITELIST",
                level=ThreatLevel.INFO,
                description=f"Легитимный системный объект: {db_entry['name']}",
                evidence=clsid,
                location=obj.get("source", "unknown"),
            ))
            continue

        suspicious_count += 1

        if db_entry:
            cve_str = ", ".join(db_entry.get("cve", [])) or "н/д"
            source = db_entry.get("source", "")
            source_url = db_entry.get("source_url", "")
            evidence_parts = [clsid]
            if cve_str != "н/д":
                evidence_parts.append(f"CVE: {cve_str}")
            if source:
                evidence_parts.append(f"Источник: {source}")
            if source_url:
                evidence_parts.append(f"Ссылка: {source_url}")
            level = ThreatLevel(db_entry.get("level", "MEDIUM"))
            indicators.append(ThreatIndicator(
                indicator_id=f"B4.CLSID.{clsid[1:9]}",
                level=level,
                description=(
                    f"Опасный ActiveX CLSID: {db_entry['name']} — "
                    f"{db_entry['description']}"
                ),
                evidence="\n".join(evidence_parts),
                location=obj.get("source", "unknown"),
            ))
        else:
            indicators.extend(
                _evaluate_unknown_clsid(clsid, obj.get("source", "unknown"), registry_cache)
            )

    return {
        "indicators": indicators,
        "whitelist_count": whitelist_count,
        "suspicious_count": suspicious_count,
    }


def _evaluate_unknown_clsid(
    clsid: str,
    source: str,
    registry_cache: dict,
) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []
    reg_info = _resolve_clsid_via_registry(clsid, registry_cache)

    if reg_info is None:
        indicators.append(ThreatIndicator(
            indicator_id="B4.CLSID_UNKNOWN_UNREGISTERED",
            level=ThreatLevel.MEDIUM,
            description="Неизвестный CLSID не зарегистрирован в системе — подозрительно",
            evidence=clsid,
            location=source,
        ))
        return indicators

    progid = reg_info.get("progid", "")
    dll_path = reg_info.get("dll_path", "")
    exe_path = reg_info.get("exe_path", "")
    path_info = dll_path or exe_path or "н/д"

    indicators.append(ThreatIndicator(
        indicator_id="B4.CLSID_UNKNOWN_RESOLVED",
        level=ThreatLevel.INFO,
        description=f"Неизвестный CLSID разрешён через реестр: {progid or 'ProgID не найден'}",
        evidence=f"CLSID: {clsid}\nProgID: {progid}\nPath: {path_info}",
        location=source,
    ))

    progid_upper = progid.upper()
    for pattern, (level, description) in DANGEROUS_PROGID_PATTERNS.items():
        if progid_upper.startswith(pattern.upper()):
            indicators.append(ThreatIndicator(
                indicator_id="B4.PROGID_DANGEROUS",
                level=level,
                description=f"Опасный ProgID: {description} ({progid})",
                evidence=f"ProgID: {progid}\nCLSID: {clsid}\nPath: {path_info}",
                location=source,
            ))
            break

    return indicators


def _resolve_clsid_via_registry(
    clsid: str,
    cache: dict,
) -> dict | None:
    if clsid in cache:
        return cache[clsid]

    if not WINREG_AVAILABLE:
        cache[clsid] = None
        return None

    import winreg

    base_key = f"CLSID\\{clsid}"
    result: dict = {"progid": "", "dll_path": "", "exe_path": ""}
    found = False

    try:
        with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, base_key):
            found = True
    except OSError:
        cache[clsid] = None
        return None

    for sub_key, field in [
        ("ProgID", "progid"),
        ("InprocServer32", "dll_path"),
        ("LocalServer32", "exe_path"),
    ]:
        try:
            with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT, f"{base_key}\\{sub_key}") as key:
                value, _ = winreg.QueryValueEx(key, "")
                result[field] = value
        except OSError:
            pass

    cache[clsid] = result
    return result