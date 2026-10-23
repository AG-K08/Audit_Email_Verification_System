# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block3_pcode.py
Назначение: Блок 3: Дизассемблирование P-code и выявление VBA Stomping.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import sys
import logging
import re
import subprocess
import time
from pathlib import Path

from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.config import AnalyzerConfig

log = logging.getLogger("Block3")

BLOCK_NAME = "block3_pcode"

# Stomping: p-code богаче исходника (заглушка в source, реальный код в p-code)
PCODE_STOMPING_RATIO_HIGH = 3.0
# Обратная ситуация: p-code беднее исходника (обфускация source)
PCODE_STOMPING_RATIO_LOW  = 0.15
# Абсолютные минимумы для защиты от шума на тривиальных функциях
PCODE_MIN_SOURCE_LINES    = 5
PCODE_MIN_INSTRUCTIONS    = 8

DANGEROUS_PCODE_CALLS = {
    "shell", "urldownloadtofile", "urldownloadtocachefile",
    "createobject", "wscript", "powershell", "cmd", "xmlhttp",
    "winhttp", "adodb",
}


def run(
    vba_project_path: Path | None,
    block2_raw: dict,
    vba_stomping_detected: bool,
    cfg: AnalyzerConfig,
) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {}

    should_run = vba_stomping_detected or cfg.always_run_pcode
    if not should_run:
        return BlockResult(
            block_name=BLOCK_NAME,
            success=True,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            raw_findings={"skipped": True, "reason": "VBA stomping не обнаружен, always_run_pcode=false"},
        )

    if vba_project_path is None or not vba_project_path.exists():
        return BlockResult(
            block_name=BLOCK_NAME,
            success=False,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            error_message="vbaProject.bin не найден",
        )

    pcode_output = _run_pcodedmp(vba_project_path, cfg.subprocess_timeout_sec)
    raw["pcode_raw"] = pcode_output

    pcode_functions = _extract_pcode_functions(pcode_output)
    raw["pcode_functions"] = {name: len(body) for name, body in pcode_functions.items()}

    source_functions: set[str] = {
        f.lower() for f in block2_raw.get("all_functions", [])
    }
    pcode_func_names: set[str] = {name.lower() for name in pcode_functions}

    only_in_pcode = pcode_func_names - source_functions
    only_in_source = source_functions - pcode_func_names
    raw["only_in_pcode"] = list(only_in_pcode)
    raw["only_in_source"] = list(only_in_source)

    for func_name in only_in_pcode:
        indicators.append(ThreatIndicator(
            indicator_id=f"B3.PCODE_ONLY.{func_name.upper()[:30]}",
            level=ThreatLevel.HIGH,
            description=f"Функция присутствует только в p-code (скрыта от анализа исходника): {func_name}",
            evidence=func_name,
            location="vbaProject.bin p-code",
        ))

    for func_name in only_in_source:
        indicators.append(ThreatIndicator(
            indicator_id=f"B3.SOURCE_ONLY.{func_name.upper()[:30]}",
            level=ThreatLevel.MEDIUM,
            description=f"Функция присутствует только в исходнике (нет в p-code): {func_name}",
            evidence=func_name,
            location="vbaProject.bin source",
        ))

    source_modules = block2_raw.get("modules", [])
    source_line_counts: dict[str, int] = {}
    for m in source_modules:
        for func_name, line_count in m.get("function_line_counts", {}).items():
            source_line_counts[func_name.lower()] = line_count

    for func_name, pcode_body in pcode_functions.items():
        func_lower = func_name.lower()
        source_lines = source_line_counts.get(func_lower)
        if source_lines is None or source_lines == 0:
            continue

        pcode_instruction_count = len(pcode_body)

        if source_lines < PCODE_MIN_SOURCE_LINES or pcode_instruction_count < PCODE_MIN_INSTRUCTIONS:
            continue

        ratio = pcode_instruction_count / source_lines

        if ratio > PCODE_STOMPING_RATIO_HIGH:
            dangerous_calls = _find_dangerous_calls_in_pcode(pcode_body)
            if dangerous_calls:
                level = ThreatLevel.CRITICAL
                description = (
                    f"Stomping подтверждён: p-code функции {func_name} "
                    f"богаче исходника (ratio={ratio:.2f}) и содержит опасные "
                    f"вызовы ({', '.join(dangerous_calls)}), отсутствующие в исходнике"
                )
            else:
                level = ThreatLevel.HIGH
                description = (
                    f"P-code функции {func_name} значительно богаче исходника — "
                    f"возможный stomping ({pcode_instruction_count} инструкций vs "
                    f"{source_lines} строк исходника, ratio={ratio:.2f})"
                )
            indicators.append(ThreatIndicator(
                indicator_id=f"B3.STOMPING_RATIO.{func_name.upper()[:30]}",
                level=level,
                description=description,
                evidence="\n".join(pcode_body[:10]),
                location=f"vbaProject.bin p-code / {func_name}",
            ))

        elif ratio < PCODE_STOMPING_RATIO_LOW:
            indicators.append(ThreatIndicator(
                indicator_id=f"B3.SHORT_BODY.{func_name.upper()[:30]}",
                level=ThreatLevel.MEDIUM,
                description=(
                    f"P-code функции {func_name} беднее исходника — "
                    f"возможна обфускация source ({pcode_instruction_count} инструкций vs "
                    f"{source_lines} строк исходника, ratio={ratio:.2f})"
                ),
                evidence="\n".join(pcode_body[:10]),
                location=f"vbaProject.bin p-code / {func_name}",
            ))

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _run_pcodedmp(vba_project_path: Path, timeout_sec: int) -> str:
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pcodedmp", str(vba_project_path)],
            capture_output=True,
            text=True,
            timeout=timeout_sec,
            encoding="utf-8",
            errors="replace",
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        log.warning("pcodedmp превысил таймаут %d сек", timeout_sec)
        return ""
    except Exception as exc:
        log.error("Ошибка запуска pcodedmp: %s", exc)
        return ""


def _extract_pcode_functions(pcode_output: str) -> dict[str, list[str]]:
    functions: dict[str, list[str]] = {}
    current_func: str | None = None
    current_body: list[str] = []

    funcdef_pattern = re.compile(
        r'FuncDefn\s+\((Sub|Function)\s+(\w+)', re.IGNORECASE
    )

    for line in pcode_output.splitlines():
        match = funcdef_pattern.search(line)
        if match:
            if current_func is not None:
                functions[current_func] = current_body
            current_func = match.group(2)
            current_body = []
            continue

        if current_func is not None:
            stripped = line.strip()
            if stripped and not stripped.startswith("Line #"):
                current_body.append(stripped)
            if "EndSub" in line or "EndFunc" in line:
                functions[current_func] = current_body
                current_func = None
                current_body = []

    if current_func is not None:
        functions[current_func] = current_body

    return functions


def _find_dangerous_calls_in_pcode(pcode_body: list[str]) -> list[str]:
    found: list[str] = []
    body_text = " ".join(pcode_body).lower()
    for dangerous in DANGEROUS_PCODE_CALLS:
        if dangerous in body_text:
            found.append(dangerous)
    return found