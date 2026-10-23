# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block2_vba_source.py
Назначение: Блок 2: Декомпиляция и статический анализ исходного кода VBA.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import sys
import os
import logging
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from oletools.olevba import VBA_Parser
    OLETOOLS_AVAILABLE = True
except ImportError:
    OLETOOLS_AVAILABLE = False
    logging.getLogger("Block2").error("oletools не установлен")

import re
import time
from pathlib import Path

from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.config import AnalyzerConfig
from core.utils import calculate_entropy

log = logging.getLogger("Block2")

BLOCK_NAME = "block2_vba_source"

# Каждая запись: pattern -> (level, description, indicator_short_code)
SIGNATURES: list[tuple[str, ThreatLevel, str, str]] = [
    # NETWORK — CRITICAL
    (
        r"URLDownloadToFile|URLDownloadToCacheFile",
        ThreatLevel.CRITICAL, "Загрузка файла из сети", "NET_DOWNLOAD",
    ),
    (
        r"XMLHTTP|WinHttpRequest|InternetOpen|InternetOpenUrl|ADODB\.Stream|Winsock",
        ThreatLevel.CRITICAL, "Сетевое взаимодействие из VBA", "NET_HTTP",
    ),
    # SELF_MOD — CRITICAL
    (
        r"VBProject|AddFromString|AddFromFile|CodeModule|VBComponents"
        r"|Application\.VBE|InsertLines|DeleteLines|ReplaceLine",
        ThreatLevel.CRITICAL, "Самомодификация VBA-проекта", "SELF_MOD",
    ),
    # EXECUTION — HIGH
    (
        r"Application\.OnTime",
        ThreatLevel.HIGH, "Отложенный вызов (persistence механизм)", "EXEC_ONTIME",
    ),
    (
        r'CreateObject\s*\(\s*["\']WScript\.Shell',
        ThreatLevel.HIGH, "CreateObject WScript.Shell", "EXEC_WSCRIPT",
    ),
    (
        r'CreateObject\s*\(\s*["\']Scripting\.FileSystemObject',
        ThreatLevel.HIGH, "CreateObject FileSystemObject", "EXEC_FSO",
    ),
    (
        r"CreateObject|GetObject",
        ThreatLevel.HIGH, "Создание COM-объекта", "EXEC_COM",
    ),
    (
        r"Shell\s*\(|Shell\s+[^\n]",
        ThreatLevel.HIGH, "Вызов Shell", "EXEC_SHELL",
    ),
    (
        r"CallByName|Application\.Run|ExecuteExcel4Macro|MacroOptions",
        ThreatLevel.HIGH, "Динамический вызов кода", "EXEC_DYN",
    ),
    # PROCESS — HIGH
    (
        r"CreateProcessW|CreateProcess\b|ShellExecuteEx|ShellExecute\b|Win32_Process",
        ThreatLevel.HIGH, "Управление процессами", "PROC_CREATE",
    ),
    # REGISTRY — MEDIUM
    (
        r"RegRead|RegWrite|RegDelete|HKEY_|WScript\.RegWrite|RegOpenKey|RegSetValue",
        ThreatLevel.MEDIUM, "Операции с реестром", "REG_OPS",
    ),
    # FILESYSTEM — MEDIUM
    (
        r"Open\s+\S+\s+For\s+(Input|Output|Append|Binary|Random)"
        r"|FileSystemObject|Kill\s+|FileCopy|MkDir|CreateTextFile|OpenTextFile",
        ThreatLevel.MEDIUM, "Файловые операции", "FS_OPS",
    ),
]

# Утилиты ищутся в строковых литералах
SYSTEM_UTILITIES: dict[str, ThreatLevel] = {
    "powershell":    ThreatLevel.CRITICAL,
    "mshta.exe":     ThreatLevel.CRITICAL,
    "certutil.exe":  ThreatLevel.CRITICAL,
    "regsvr32.exe":  ThreatLevel.CRITICAL,
    "rundll32.exe":  ThreatLevel.CRITICAL,
    "bitsadmin":     ThreatLevel.CRITICAL,
    "cmd.exe":       ThreatLevel.HIGH,
    "wscript.exe":   ThreatLevel.HIGH,
    "cscript.exe":   ThreatLevel.HIGH,
}

BASE64_PATTERN = re.compile(r'[A-Za-z0-9+/]{40,}={0,2}')
CHR_CONCAT_PATTERN = re.compile(r'Chr[W]?\s*\(\s*\d+\s*\)', re.IGNORECASE)
UNICODE_WIDE_LATIN = re.compile(r'[\uFF21-\uFF3A\uFF41-\uFF5A]')
FUNCTION_NAME_PATTERN = re.compile(
    r'^\s*(?:Private|Public|Friend)?\s*(?:Static\s+)?(?:Sub|Function)\s+(\w+)',
    re.IGNORECASE | re.MULTILINE,
)
FUNCTION_END_PATTERN = re.compile(
    r'^\s*End\s+(?:Sub|Function)',
    re.IGNORECASE | re.MULTILINE,
)

DANGEROUS_DECODED_KEYWORDS = [
    "http://", "https://", "powershell", "cmd.exe", ".exe", "shell",
]


def run(file_path: Path, block0_raw: dict, cfg: AnalyzerConfig) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {"modules": []}

    vba_modules = _extract_vba_modules_api(file_path)
    raw["module_count"] = len(vba_modules)

    for module in vba_modules:
        module_name = module["name"]
        code = module["code"]

        module_indicators: list[ThreatIndicator] = []
        module_indicators.extend(_check_signatures(code, module_name))
        module_indicators.extend(_check_system_utilities(code, module_name))
        module_indicators.extend(_check_obfuscation(code, module_name, cfg.entropy_threshold))
        module_indicators.extend(_check_encoded_strings(code, module_name))

        func_line_counts = _extract_function_line_counts(code)
        entropy = _calculate_entropy(code)

        raw["modules"].append({
            "name": module_name,
            "type": module.get("type", "unknown"),
            "line_count": len(code.splitlines()),
            "functions": list(func_line_counts.keys()),
            "function_line_counts": func_line_counts,
            "entropy": entropy,
            "code": code,
        })

        indicators.extend(module_indicators)

    raw["all_functions"] = [
        func
        for m in raw["modules"]
        for func in m["function_line_counts"]
    ]

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _extract_vba_modules_api(file_path: Path) -> list[dict]:
    if not OLETOOLS_AVAILABLE:
        log.error("oletools не установлен")
        return []
    try:
        parser = VBA_Parser(str(file_path))
        if not parser.detect_macros():
            parser.close()
            return []

        modules: list[dict] = []
        for vba_filename, stream_path, vba_filename2, vba_code in parser.extract_macros():
            name = vba_filename2 or vba_filename or "unknown"
            modules.append({
                "name": name,
                "code": vba_code or "",
                "type": "vba",
            })

        parser.close()
        return modules

    except Exception as exc:
        log.error("Ошибка VBA_Parser в Block2: %s", exc)
        return []


def _check_signatures(code: str, module_name: str) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    for pattern, level, description, short_code in SIGNATURES:
        match = re.search(pattern, code, re.IGNORECASE)
        if not match:
            continue
        indicators.append(ThreatIndicator(
            indicator_id=f"B2.SIG.{short_code}",
            level=level,
            description=description,
            evidence=match.group(0)[:120],
            location=module_name,
        ))

    return indicators


def _check_system_utilities(code: str, module_name: str) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []
    string_literals = re.findall(r'"([^"]*)"', code)
    found: set[str] = set()

    for literal in string_literals:
        literal_lower = literal.lower()
        for util, level in SYSTEM_UTILITIES.items():
            if util in literal_lower and util not in found:
                found.add(util)
                indicators.append(ThreatIndicator(
                    indicator_id=f"B2.UTIL.{util.upper().replace('.', '_').replace('-', '_')}",
                    level=level,
                    description=f"Системная утилита в строковом литерале: {util}",
                    evidence=f'"{literal[:80]}"',
                    location=module_name,
                ))

    return indicators


def _check_obfuscation(
    code: str,
    module_name: str,
    entropy_threshold: float,
) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    chr_matches = CHR_CONCAT_PATTERN.findall(code)
    if len(chr_matches) >= 3:
        first_pos = code.lower().find("chr")
        indicators.append(ThreatIndicator(
            indicator_id="B2.OBFUSC.CHR_CONCAT",
            level=ThreatLevel.HIGH,
            description=f"Обфускация через Chr()-конкатенацию ({len(chr_matches)} вызовов)",
            evidence=code[first_pos: first_pos + 80] if first_pos >= 0 else str(chr_matches[:3]),
            location=module_name,
        ))

    if UNICODE_WIDE_LATIN.search(code):
        indicators.append(ThreatIndicator(
            indicator_id="B2.OBFUSC.UNICODE_IDENT",
            level=ThreatLevel.HIGH,
            description="Unicode-идентификаторы (полноширинная латиница) в коде",
            evidence="Unicode U+FF21..U+FF5A в именах",
            location=module_name,
        ))

    entropy = _calculate_entropy(code)
    if entropy >= entropy_threshold:
        indicators.append(ThreatIndicator(
            indicator_id="B2.OBFUSC.HIGH_ENTROPY",
            level=ThreatLevel.LOW,
            description=(
                f"Высокая энтропия модуля: {entropy:.2f} бит/символ "
                f"(порог {entropy_threshold})"
            ),
            evidence=f"entropy={entropy:.2f}",
            location=module_name,
        ))

    return indicators


def _check_encoded_strings(code: str, module_name: str) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    for match in BASE64_PATTERN.finditer(code):
        candidate = match.group(0)
        decoded = _try_decode_base64(candidate)
        if decoded is None:
            continue

        level, description = _classify_decoded_content(decoded)
        if level is not None:
            indicators.append(ThreatIndicator(
                indicator_id=f"B2.BASE64.{hash(candidate) & 0xFFFF:04X}",
                level=level,
                description=description,
                evidence=f"base64: {candidate[:40]}... → {decoded[:60]}",
                location=module_name,
            ))

    return indicators


def _try_decode_base64(candidate: str) -> str | None:
    import base64
    try:
        padded = candidate + "=" * (4 - len(candidate) % 4)
        decoded_bytes = base64.b64decode(padded)
        text = decoded_bytes.decode("utf-8", errors="replace")
        printable_ratio = sum(1 for c in text if c.isprintable()) / max(len(text), 1)
        if printable_ratio < 0.7:
            return None
        return text
    except Exception:
        return None


def _classify_decoded_content(decoded: str) -> tuple[ThreatLevel | None, str]:
    decoded_lower = decoded.lower()
    for keyword in DANGEROUS_DECODED_KEYWORDS:
        if keyword in decoded_lower:
            return (
                ThreatLevel.CRITICAL,
                f"Base64-строка содержит опасное содержимое: {keyword}",
            )
    return ThreatLevel.MEDIUM, "Base64-закодированная строка"


def _extract_function_names(code: str) -> list[str]:
    return [m.group(1) for m in FUNCTION_NAME_PATTERN.finditer(code)]


def _extract_function_line_counts(code: str) -> dict[str, int]:
    """
    Извлечь имена функций и количество строк тела каждой.

    Считает строки от заголовка Sub/Function до End Sub/End Function включительно.
    Возвращает dict[func_name_lower, line_count].
    """
    result: dict[str, int] = {}
    lines = code.splitlines()
    total = len(lines)
    i = 0
    while i < total:
        m = FUNCTION_NAME_PATTERN.match(lines[i])
        if m:
            func_name = m.group(1).lower()
            start = i
            i += 1
            while i < total:
                if FUNCTION_END_PATTERN.match(lines[i]):
                    result[func_name] = i - start + 1
                    i += 1
                    break
                i += 1
            else:
                # End не найден — считаем до конца модуля
                result[func_name] = total - start
        else:
            i += 1
    return result


def _calculate_entropy(text: str) -> float:
    return calculate_entropy(text)