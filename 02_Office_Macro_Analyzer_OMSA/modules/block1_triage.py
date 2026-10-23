# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block1_triage.py
Назначение: Блок 1: Сигнатурный триаж и экспресс-анализ подозрительных потоков.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import sys
import os
import subprocess
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import logging
import re
import time
import xml.etree.ElementTree as ET
from pathlib import Path

from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.config import AnalyzerConfig

try:
    from oletools.olevba import VBA_Parser
    from oletools.mraptor import MacroRaptor
    OLETOOLS_AVAILABLE = True
except ImportError as e:
    OLETOOLS_AVAILABLE = False
    log_import = logging.getLogger("Block1")
    log_import.error("oletools не установлен: %s", e)

try:
    import xlrd2
    XLRD2_AVAILABLE = True
except ImportError:
    XLRD2_AVAILABLE = False

log = logging.getLogger("Block1")
BLOCK_NAME = "block1_triage"

AUTOEXEC_TRIGGERS = {
    "workbook_open", "document_open", "auto_open", "autoexec",
    "autonew", "autoclose", "document_close", "workbook_close",
}

DANGEROUS_XLM_FUNCTIONS = {"call", "exec", "register", "run"}

XLM_WORKBOOK_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XLM_MACROSHEET_NS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
XLM_R_NS = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"

# Матрица опасных XLM-функций для структурного анализа OpenXML
XLM_FUNCTION_MATRIX: list[tuple[tuple[str, ...], str, str]] = [
    (("CALL", "REGISTER"),              "CRITICAL", "B1.XLM_CALL_REGISTER"),
    (("EXEC", "RUN"),                   "CRITICAL", "B1.XLM_EXEC_RUN"),
    (("FORMULA", "FORMULA.FILL"),       "HIGH",     "B1.XLM_SELF_MOD"),
    (("GET.WORKSPACE", "GET.DOCUMENT"), "MEDIUM",   "B1.XLM_SANDBOX_CHECK"),
    (("HALT", "GOTO", "RETURN"),        "INFO",     "B1.XLM_FLOW_CONTROL"),
]

_XLM_LEVEL_MAP: dict[str, ThreatLevel] = {
    "CRITICAL": ThreatLevel.CRITICAL,
    "HIGH":     ThreatLevel.HIGH,
    "MEDIUM":   ThreatLevel.MEDIUM,
    "LOW":      ThreatLevel.LOW,
    "INFO":     ThreatLevel.INFO,
}


def run(file_path: Path, cfg: AnalyzerConfig, block0_raw: dict | None = None) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {}

    olevba_result = _run_olevba_api(file_path)

    if not olevba_result.get("has_macros") and not olevba_result.get("vba_code"):
        log.info("VBA_Parser не обнаружил макросов — запускаем OLE fallback")
        fallback_result = run_ole_fallback(file_path, cfg.subprocess_timeout_sec)

        if fallback_result.get("fallback_unavailable"):
            indicators.append(ThreatIndicator(
                indicator_id="B1.OLEDUMP_UNAVAILABLE",
                level=ThreatLevel.INFO,
                description="oledump не установлен — OLE fallback недоступен",
                evidence="shutil.which('oledump') = None",
                location=str(file_path),
            ))
        elif fallback_result.get("has_macros"):
            macro_stream_ids = [
                s["stream_id"]
                for s in fallback_result.get("fallback_streams", [])
                if s["has_macro"]
            ]
            indicators.append(ThreatIndicator(
                indicator_id="B1.OLEDUMP_MACROS_FOUND",
                level=ThreatLevel.HIGH,
                description="oledump обнаружил VBA-макросы в нестандартных OLE-потоках",
                evidence=f"Потоки с макросами: {', '.join(macro_stream_ids)}",
                location=str(file_path),
            ))
        else:
            indicators.append(ThreatIndicator(
                indicator_id="B1.OLEDUMP_NO_MACROS",
                level=ThreatLevel.INFO,
                description="oledump: потоки с макросами не найдены",
                evidence="oledump fallback выполнен, M-потоков нет",
                location=str(file_path),
            ))

        olevba_result = fallback_result

    raw["vba_stomping"] = olevba_result.get("vba_stomping", False)
    raw["macro_names"] = olevba_result.get("macro_names", [])
    raw["decoded_strings"] = olevba_result.get("decoded_strings", [])
    raw["olevba_indicators"] = olevba_result.get("indicators", [])
    raw["vba_code"] = olevba_result.get("vba_code", "")
    raw["has_macros"] = olevba_result.get("has_macros", False)
    raw["fallback_used"] = olevba_result.get("fallback_used", False)
    raw["fallback_streams"] = olevba_result.get("fallback_streams", [])
    raw["fallback_unavailable"] = olevba_result.get("fallback_unavailable", False)

    raw["mraptor_verdict"] = _run_mraptor_api(olevba_result.get("vba_code", ""))

    xlm_result = _check_xlm_macros_api(olevba_result)
    raw["xlm_found"] = xlm_result["found"]
    raw["xlm_dangerous_functions"] = xlm_result["dangerous_functions"]
    raw["xlm_dangerous_details"] = xlm_result.get("dangerous_details", [])

    xlm_content_result = _check_xlm_content(block0_raw=block0_raw or {}, file_path=file_path)
    raw["xlm_content_analysis"] = xlm_content_result
    indicators.extend(_build_xlm_content_indicators(xlm_content_result))

    indicators.extend(_build_indicators(olevba_result, xlm_result))

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _run_olevba_api(file_path: Path) -> dict:
    if not OLETOOLS_AVAILABLE:
        log.error("oletools не установлен")
        return _empty_olevba_result()

    try:
        parser = VBA_Parser(str(file_path))
        vba_code_parts: list[str] = []
        macro_names: list[str] = []
        xlm_modules: list[str] = []
        for vba_filename, stream_path, vba_filename2, vba_code in (parser.extract_macros() or []):
            macro_names.append(vba_filename2 or vba_filename)
            vba_code_parts.append(vba_code or "")

        full_vba_code = "\n".join(vba_code_parts)

        has_macros = parser.detect_macros() if hasattr(parser, 'detect_macros') else bool(full_vba_code)

        # Проверка XLM-модулей
        for module in parser.modules:
            if hasattr(module, 'type') and str(module.type) == 'XLM':
                xlm_modules.append(getattr(module, 'name', 'unknown'))

        # Анализ макросов через API
        raw_indicators: list[dict] = []
        decoded_strings: list[str] = []
        vba_stomping = False

        try:
            for kw_type, keyword, description in parser.analyze_macros():
                raw_indicators.append({
                    "type": kw_type,
                    "keyword": keyword,
                    "description": description,
                })
                if "Stomping" in description or "P-code" in description:
                    vba_stomping = True
                # Декодированные строки из olevba
                if kw_type in ("Suspicious", "IOC") and keyword:
                    decoded_strings.append(keyword)
        except Exception as exc:
            log.warning("analyze_macros упал: %s", exc)

        parser.close()

        return {
            "vba_code": full_vba_code,
            "macro_names": macro_names,
            "xlm_modules": xlm_modules,
            "indicators": raw_indicators,
            "decoded_strings": decoded_strings,
            "vba_stomping": vba_stomping,
            "has_macros": has_macros,
        }

    except Exception as exc:
        log.error("Ошибка VBA_Parser: %s", exc)
        return _empty_olevba_result()


def _run_mraptor_api(vba_code: str) -> str:
    if not vba_code:
        return "NOT_SUSPICIOUS"
    try:
        mraptor = MacroRaptor(vba_code)
        mraptor.scan()
        if mraptor.suspicious:
            return "SUSPICIOUS"
        return "NOT_SUSPICIOUS"
    except ImportError:
        log.warning("mraptor недоступен")
        return "ERROR"
    except Exception as exc:
        log.error("Ошибка mraptor API: %s", exc)
        return "ERROR"


def _check_xlm_macros_api(olevba_result: dict) -> dict:
    xlm_modules = olevba_result.get("xlm_modules", [])
    vba_code = olevba_result.get("vba_code", "")
    xlm_present = bool(xlm_modules)

    # Дополнительная проверка через индикаторы olevba
    if not xlm_present:
        for ind in olevba_result.get("indicators", []):
            if "XLM" in ind.get("description", "") or "Excel 4" in ind.get("keyword", ""):
                xlm_present = True
                break

    if not xlm_present:
        return {"found": False, "dangerous_functions": [], "dangerous_details": []}

    found_dangerous: list[dict] = []
    lines = vba_code.splitlines()

    for i, line in enumerate(lines):
        line_upper = line.upper()
        for func in DANGEROUS_XLM_FUNCTIONS:
            if func in line_upper:
                context_start = max(0, i - 2)
                context_end = min(len(lines), i + 3)
                context = "\n".join(lines[context_start:context_end])
                found_dangerous.append({
                    "function": func.upper(),
                    "line": line.strip(),
                    "context": context,
                    "line_number": i,
                })

    return {
        "found": xlm_present,
        "dangerous_functions": list({d["function"] for d in found_dangerous}),
        "dangerous_details": found_dangerous,
    }


def _extract_xlm_context_line(olevba_result: dict) -> str:
    for ind in olevba_result.get("indicators", []):
        desc = ind.get("description", "")
        kw = ind.get("keyword", "")
        if "XLM" in desc or "Excel 4" in desc or "XLM" in kw:
            return f"{kw}: {desc}"[:200]
    modules = olevba_result.get("xlm_modules", [])
    if modules:
        return f"XLM модули: {', '.join(modules[:5])}"
    return "olevba API: XLM detected"


def _build_indicators(olevba_result: dict, xlm_result: dict) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    if olevba_result.get("vba_stomping"):
        indicators.append(ThreatIndicator(
            indicator_id="B1.VBA_STOMPING",
            level=ThreatLevel.HIGH,
            description="VBA Stomping: исходный код и p-code отличаются",
            evidence="olevba API: P-code mismatch detected",
            location="vbaProject.bin",
        ))

    autoexec_found = [
        ind["keyword"] for ind in olevba_result.get("indicators", [])
        if ind.get("type") == "AutoExec"
    ]
    for trigger in autoexec_found:
        if trigger.lower() in AUTOEXEC_TRIGGERS:
            indicators.append(ThreatIndicator(
                indicator_id=f"B1.AUTOEXEC.{trigger.upper()}",
                level=ThreatLevel.MEDIUM,
                description=f"AutoExec триггер: {trigger}",
                evidence=trigger,
                location="vbaProject.bin",
            ))

    if xlm_result["dangerous_functions"]:
        details = xlm_result.get("dangerous_details", [])
        evidence_lines = [
            f"{d['function']} | строка {d['line_number']}: {d['line'][:80]}"
            for d in details[:5]
        ]
        indicators.append(ThreatIndicator(
            indicator_id="B1.XLM_DANGEROUS",
            level=ThreatLevel.HIGH,
            description=(
                f"Найдены потенциально опасные XLM-функции: "
                f"{', '.join(sorted(set(xlm_result['dangerous_functions'])))}. "
                f"Требует ручной проверки — совпадение может быть в имени "
                f"VBA-процедуры или комментарии."
            ),
            evidence="\n".join(evidence_lines),
            location="XLM macros",
        ))
    elif xlm_result["found"]:
        xlm_context = _extract_xlm_context_line(olevba_result)
        indicators.append(ThreatIndicator(
            indicator_id="B1.XLM_PRESENT",
            level=ThreatLevel.LOW,
            description="XLM/Excel 4.0 макросы присутствуют (опасных функций не найдено)",
            evidence=xlm_context,
            location="XLM macros",
        ))

    return indicators


def _empty_olevba_result() -> dict:
    return {
        "vba_code": "",
        "macro_names": [],
        "xlm_modules": [],
        "indicators": [],
        "decoded_strings": [],
        "vba_stomping": False,
        "has_macros": False,
    }


# ---------------------------------------------------------------------------
# _check_xlm_content — структурный анализ XLM/Excel 4.0
# ---------------------------------------------------------------------------


def _check_xlm_content(block0_raw: dict, file_path: Path) -> dict:
    """
    Структурный анализ XLM-макросов.

    Приоритет 1: OpenXML — парсинг xl/macrosheets/*.xml из temp_dir.
    Приоритет 2: OLE2 — xlrd2 (опциональная зависимость).

    Возвращает dict с ключами: indicators, hidden_sheets, ole2_skipped.
    """
    result: dict = {
        "indicators": [],
        "hidden_sheets": [],
        "ole2_skipped": False,
    }

    doc_format = block0_raw.get("file_format", "unknown")
    temp_dir_str = block0_raw.get("temp_dir", "")
    temp_dir = Path(temp_dir_str) if temp_dir_str else None

    if doc_format == "openxml" and temp_dir and temp_dir.is_dir():
        _xlm_openxml(temp_dir, result)
        return result

    if doc_format == "ole2":
        if not XLRD2_AVAILABLE:
            result["ole2_skipped"] = True
        else:
            _xlm_ole2(file_path, result)
        return result

    return result


def _xlm_openxml(temp_dir: Path, result: dict) -> None:
    """Анализ XLM в OpenXML: парсинг xl/macrosheets/*.xml."""
    macrosheets_dir = temp_dir / "xl" / "macrosheets"
    if not macrosheets_dir.is_dir():
        return

    for sheet_file in macrosheets_dir.glob("*.xml"):
        sheet_name = sheet_file.stem
        try:
            raw_text = sheet_file.read_text(encoding="utf-8", errors="replace")
            tree = ET.fromstring(raw_text)
        except (OSError, ET.ParseError):
            continue

        ns = XLM_MACROSHEET_NS
        for cell in tree.iter(f"{{{ns}}}c"):
            cell_ref = cell.get("r", "?")
            formula_elem = cell.find(f"{{{ns}}}f")
            if formula_elem is None or not formula_elem.text:
                continue

            formula_text = formula_elem.text
            formula_upper = formula_text.upper()

            for func_group, level_str, indicator_code in XLM_FUNCTION_MATRIX:
                for func_name in func_group:
                    if func_name in formula_upper:
                        evidence = (
                            f"sheet={sheet_name} cell={cell_ref} "
                            f"formula={formula_text[:120]}"
                        )
                        result["indicators"].append({
                            "code": indicator_code,
                            "level": level_str,
                            "evidence": evidence,
                            "location": f"xl/macrosheets/{sheet_file.name}",
                        })
                        break

    _xlm_check_hidden_sheets(temp_dir, result)


def _xlm_check_hidden_sheets(temp_dir: Path, result: dict) -> None:
    """
    Поиск veryHidden листов с макросами в xl/workbook.xml.

    Читает <sheet state="veryHidden"> и проверяет r:id на macrosheet.
    """
    workbook_xml = temp_dir / "xl" / "workbook.xml"
    if not workbook_xml.is_file():
        return

    try:
        tree = ET.parse(str(workbook_xml))
        root = tree.getroot()
    except (OSError, ET.ParseError):
        return

    # Собрать r:id всех macrosheet из workbook.xml.rels
    macrosheet_rids: set[str] = set()
    rels_path = temp_dir / "xl" / "_rels" / "workbook.xml.rels"
    if rels_path.is_file():
        try:
            rels_tree = ET.parse(str(rels_path))
            rels_root = rels_tree.getroot()
            rels_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
            for rel in rels_root.iter(f"{{{rels_ns}}}Relationship"):
                rel_type = rel.get("Type", "")
                if "macrosheet" in rel_type.lower():
                    macrosheet_rids.add(rel.get("Id", ""))
        except (OSError, ET.ParseError):
            pass

    wb_ns = XLM_WORKBOOK_NS
    for sheet_elem in root.iter(f"{{{wb_ns}}}sheet"):
        state = sheet_elem.get(f"{{{wb_ns}}}state") or sheet_elem.get("state", "")
        rid = sheet_elem.get(f"{{{XLM_R_NS}}}id", "")
        name = sheet_elem.get("name", "?")

        if state == "veryHidden" and (not macrosheet_rids or rid in macrosheet_rids):
            result["hidden_sheets"].append(name)
            result["indicators"].append({
                "code": "B1.XLM_VERY_HIDDEN_SHEET",
                "level": "HIGH",
                "evidence": f"sheet={name} r:id={rid} state=veryHidden",
                "location": "xl/workbook.xml",
            })


def _xlm_ole2(file_path: Path, result: dict) -> None:
    """
    Анализ XLM в OLE2 через xlrd2.

    Итерирует листы с visibility==2 (veryHidden) и ищет опасные функции
    по тексту формул.
    """
    try:
        wb = xlrd2.open_workbook(str(file_path), formatting_info=False)
    except Exception as exc:
        log.warning("xlrd2 не смог открыть файл: %s", exc)
        return

    for sheet_idx in range(wb.nsheets):
        sheet = wb.sheet_by_index(sheet_idx)

        # visibility: 0=visible, 1=hidden, 2=veryHidden
        if sheet.visibility == 2:
            result["hidden_sheets"].append(sheet.name)
            result["indicators"].append({
                "code": "B1.XLM_VERY_HIDDEN_SHEET",
                "level": "HIGH",
                "evidence": f"sheet={sheet.name} visibility=veryHidden (xlrd2)",
                "location": file_path.name,
            })

        for row_idx in range(sheet.nrows):
            for col_idx in range(sheet.ncols):
                cell = sheet.cell(row_idx, col_idx)
                # xlrd2 тип 6 = формула
                if cell.ctype != 6:
                    continue
                formula_text = str(cell.value)
                formula_upper = formula_text.upper()

                for func_group, level_str, indicator_code in XLM_FUNCTION_MATRIX:
                    for func_name in func_group:
                        if func_name in formula_upper:
                            evidence = (
                                f"sheet={sheet.name} "
                                f"cell=R{row_idx+1}C{col_idx+1} "
                                f"formula={formula_text[:120]}"
                            )
                            result["indicators"].append({
                                "code": indicator_code,
                                "level": level_str,
                                "evidence": evidence,
                                "location": file_path.name,
                            })
                            break


def _build_xlm_content_indicators(xlm_content_result: dict) -> list[ThreatIndicator]:
    """
    Преобразовать raw-индикаторы из _check_xlm_content в ThreatIndicator.

    Также добавляет B1.XLM_OLE2_SKIPPED если xlrd2 недоступен.
    """
    indicators: list[ThreatIndicator] = []

    if xlm_content_result.get("ole2_skipped"):
        indicators.append(ThreatIndicator(
            indicator_id="B1.XLM_OLE2_SKIPPED",
            level=ThreatLevel.INFO,
            description="xlrd2 не установлен, XLM в OLE2 не проанализирован",
            evidence="XLRD2_AVAILABLE = False",
            location="block1_triage",
        ))
        return indicators

    for ind in xlm_content_result.get("indicators", []):
        level = _XLM_LEVEL_MAP.get(ind.get("level", "INFO"), ThreatLevel.INFO)
        indicators.append(ThreatIndicator(
            indicator_id=ind["code"],
            level=level,
            description=_xlm_indicator_description(ind["code"]),
            evidence=ind.get("evidence", ""),
            location=ind.get("location", ""),
        ))

    return indicators


def _xlm_indicator_description(code: str) -> str:
    """Человекочитаемое описание по коду индикатора."""
    descriptions = {
        "B1.XLM_CALL_REGISTER":    "XLM: вызов CALL/REGISTER — возможна загрузка DLL",
        "B1.XLM_EXEC_RUN":         "XLM: вызов EXEC/RUN — выполнение внешней команды",
        "B1.XLM_SELF_MOD":         "XLM: FORMULA/FORMULA.FILL — самомодификация ячеек",
        "B1.XLM_SANDBOX_CHECK":    "XLM: GET.WORKSPACE/GET.DOCUMENT — проверка окружения",
        "B1.XLM_FLOW_CONTROL":     "XLM: управляющие функции HALT/GOTO/RETURN",
        "B1.XLM_VERY_HIDDEN_SHEET": "XLM: macrosheet скрыт с состоянием veryHidden",
    }
    return descriptions.get(code, f"XLM индикатор: {code}")


OLEDUMP_STREAM_PATTERN = re.compile(
    r'^\s*(\w+)\s+(\d+)\s+(M\s+)?(\d+)\s+(.*)$'
)
OLEDUMP_MACRO_MARKER = "M"


def run_ole_fallback(file_path: Path, timeout_sec: int) -> dict:
    """
    Запускается когда VBA_Parser.detect_macros() вернул False.
    Возвращает структуру аналогичную _empty_olevba_result() с заполненным vba_code.
    """
    result = _empty_olevba_result()
    result["fallback_used"] = True
    result["fallback_streams"] = []
    result["fallback_target_path"] = str(file_path)

    oledump_executable = _find_oledump()
    if not oledump_executable:
        log.warning("oledump не найден — OLE fallback недоступен")
        result["fallback_unavailable"] = True
        return result

    stream_list = _list_ole_streams(file_path, oledump_executable, timeout_sec)
    macro_streams = [s for s in stream_list if s["has_macro"]]
    result["fallback_streams"] = stream_list

    if not macro_streams:
        log.info("oledump: потоки с макросами не найдены")
        return result

    log.info(
        "oledump: найдены потоки с макросами: %s",
        [s["stream_id"] for s in macro_streams],
    )

    vba_code_parts: list[str] = []
    for stream in macro_streams:
        code = _extract_stream_code(
            file_path, stream["stream_id"], oledump_executable, timeout_sec
        )
        if code:
            vba_code_parts.append(f"' === Stream {stream['stream_id']} ===\n{code}")
            stream["extracted_code"] = code

    result["vba_code"] = "\n\n".join(vba_code_parts)
    result["has_macros"] = bool(vba_code_parts)

    return result


def _find_oledump() -> str | None:
    local_path = Path(__file__).parent / "oledump.py"
    if local_path.exists():
        return str(local_path)
    import shutil
    return shutil.which("oledump.py") or shutil.which("oledump")


def _list_ole_streams(
    file_path: Path,
    oledump_executable: str,
    timeout_sec: int,
) -> list[dict]:
    try:
        result = subprocess.run(
            [sys.executable, oledump_executable, str(file_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
        return _parse_oledump_stream_list(result.stdout)
    except subprocess.TimeoutExpired:
        log.warning("oledump --list превысил таймаут")
        return []
    except Exception as exc:
        log.error("Ошибка запуска oledump: %s", exc)
        return []


def _extract_stream_code(
    file_path: Path,
    stream_id: str,
    oledump_executable: str,
    timeout_sec: int,
) -> str:
    try:
        result = subprocess.run(
            [sys.executable, oledump_executable, str(file_path), "-s", stream_id, "-v"],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout.strip()
    except subprocess.TimeoutExpired:
        log.warning("oledump -s %s превысил таймаут", stream_id)
        return ""
    except Exception as exc:
        log.error("Ошибка извлечения потока %s: %s", stream_id, exc)
        return ""


def _parse_oledump_stream_list(oledump_output: str) -> list[dict]:
    streams: list[dict] = []
    for line in oledump_output.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        parts = stripped.split()
        if len(parts) < 3:
            continue
        stream_id = parts[0].rstrip(":")
        has_macro = any(p.upper() == "M" for p in parts)
        streams.append({
            "stream_id": stream_id,
            "has_macro": has_macro,
            "raw_line": stripped,
            "extracted_code": "",
        })
    return streams