# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: report_generator.py
Назначение: Генератор структурированных отчетов OMSA (JSON, TXT, Markdown).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import logging
from datetime import datetime, timezone
from pathlib import Path

from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.threat_evaluator import (
    deduplicate_indicators,
    calculate_total_weight,
    get_threat_level_by_score,
    get_top_indicators,
)

log = logging.getLogger("ReportGenerator")

SEPARATOR = "=" * 80
SECTION_SEP = "-" * 60

SCORE_LEGEND_WEIGHTS = [
    ("CRITICAL", 100),
    ("HIGH",      50),
    ("MEDIUM",    20),
    ("LOW",        5),
    ("INFO",       0),
]

SCORE_LEGEND_THRESHOLDS = [
    (150, "КРИТИЧЕСКИЙ"),
    ( 80, "ВЫСОКИЙ"),
    ( 30, "СРЕДНИЙ"),
    (  5, "НИЗКИЙ"),
    (  0, "ЧИСТО"),
]

LEVEL_LABELS: dict[ThreatLevel, str] = {
    ThreatLevel.CRITICAL: "КРИТИЧЕСКИЙ",
    ThreatLevel.HIGH: "ВЫСОКИЙ",
    ThreatLevel.MEDIUM: "СРЕДНИЙ",
    ThreatLevel.LOW: "НИЗКИЙ",
    ThreatLevel.INFO: "ИНФО",
}

RECOMMENDATIONS: dict[str, list[str]] = {
    "КРИТИЧЕСКИЙ": [
        "НЕ открывайте этот файл на рабочей станции",
        "Анализируйте только в изолированной среде (sandbox)",
        "Заблокируйте файл на почтовом шлюзе",
        "Проверьте, не был ли файл уже открыт — проведите проверку хостов",
        "Сообщите в SOC/CERT",
    ],
    "ВЫСОКИЙ": [
        "Открывайте только в изолированной среде",
        "Отключите макросы перед открытием",
        "Проверьте файл актуальным антивирусом",
        "Выясните источник файла",
    ],
    "СРЕДНИЙ": [
        "Файл содержит подозрительные элементы",
        "Отключите макросы перед открытием",
        "Будьте внимательны при переходе по ссылкам из документа",
    ],
    "НИЗКИЙ": [
        "Файл содержит незначительные подозрительные элементы",
        "Соблюдайте стандартные меры предосторожности",
    ],
    "ЧИСТО": [
        "Явных признаков вредоносного кода не обнаружено",
        "Тем не менее, соблюдайте стандартные меры предосторожности",
    ],
}

FALSE_POSITIVE_HINTS: dict[str, str] = {
    "B1.XLM_DANGEROUS": (
        "Слова CALL/RUN/EXEC могут встречаться в именах VBA-процедур и комментариях. "
        "Проверьте evidence вручную — убедитесь, что это реальный XLM-код, "
        "а не артефакт парсинга."
    ),
    "B0.EMBEDDED_OLE": (
        "Вложенный OLE-объект может быть стандартной частью документа (например, диаграмма). "
        "Проверьте имя файла в evidence — если это не vbaProject.bin и не известный компонент, "
        "извлеките и проанализируйте отдельно."
    ),
    "B4.ACTIVEX_COUNT": (
        "Большое количество ActiveX может объясняться сложным легитимным интерфейсом "
        "(кнопки, чекбоксы). Проверьте CLSID объектов — если среди них нет опасных "
        "(WScript.Shell, XMLHTTP), угроза низкая."
    ),
    "B2.OBFUSC.HIGH_ENTROPY": (
        "Высокая энтропия может быть вызвана легитимными встроенными данными "
        "(иконки в UserForm, Base64-закодированные ресурсы). "
        "Проверьте модуль вручную."
    ),
    "B1.VBA_STOMPING": (
        "VBA Stomping встречается в легитимных файлах, редактировавшихся "
        "в разных версиях Excel. Требует детального анализа p-code (Блок 3)."
    ),
    "B7.HYPERLINK_EXTERNAL": (
        "Внешние гиперссылки часто являются легитимными — ссылки на источники, "
        "справочные материалы, корпоративные порталы. "
        "Проверьте Target в evidence: если домен известен и ожидаем, угрозы нет."
    ),
}

def generate(
    file_path: Path,
    block_results: dict[str, BlockResult],
    work_dir: Path,
    top_threats_count: int,
) -> Path:
    all_indicators = _collect_all_indicators(block_results)
    unique_indicators = deduplicate_indicators(all_indicators)
    total_score = calculate_total_weight(unique_indicators)
    threat_level = get_threat_level_by_score(total_score)
    top_indicators = get_top_indicators(unique_indicators, top_threats_count)

    block0_raw = block_results.get(
        "block0_extraction",
        BlockResult(block_name="block0_extraction", success=False),
    ).raw_findings

    lines = _build_report_lines(
        file_path=file_path,
        block0_raw=block0_raw,
        block_results=block_results,
        unique_indicators=unique_indicators,
        total_score=total_score,
        threat_level=threat_level,
        top_indicators=top_indicators,
    )

    report_path = work_dir / f"{file_path.stem}_report.txt"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.info("Отчёт сохранён: %s", report_path)

    return report_path


def _collect_all_indicators(
    block_results: dict[str, BlockResult],
) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []
    for result in block_results.values():
        if result and result.success:
            indicators.extend(result.threat_indicators)
    return indicators


def _build_report_lines(
    file_path: Path,
    block0_raw: dict,
    block_results: dict[str, BlockResult],
    unique_indicators: list[ThreatIndicator],
    total_score: int,
    threat_level: str,
    top_indicators: list[ThreatIndicator],
) -> list[str]:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines: list[str] = []

    lines += _section_header("OFFICE MACRO SECURITY ANALYZER — ОТЧЁТ")
    lines += _kv_block({
        "Файл": file_path.name,
        "Путь": str(file_path),
        "Дата анализа": now,
        "Итоговый уровень угрозы": threat_level,
        "Суммарный вес угроз": str(total_score),
        "Уникальных индикаторов": str(len(unique_indicators)),
    })

    lines += _section_header("ХЕШИ ФАЙЛА")
    hashes = block0_raw.get("hashes", {})
    lines += _kv_block({
        "MD5":    hashes.get("md5", "н/д"),
        "SHA1":   hashes.get("sha1", "н/д"),
        "SHA256": hashes.get("sha256", "н/д"),
        "ssdeep": hashes.get("ssdeep", "н/д"),
    })

    lines += _section_header("МЕТАДАННЫЕ ДОКУМЕНТА")
    block5_raw = block_results.get(
        "block5_metadata",
        BlockResult(block_name="", success=False),
    ).raw_findings
    metadata_lines: list[str] = []
    for key, value in block5_raw.items():
        if not isinstance(value, str):
            continue
        metadata_lines.append(f"  {key:<35} {value}")
    if metadata_lines:
        lines += metadata_lines
    else:
        lines.append("  н/д")

    lines += _section_header(
        f"ИТОГОВАЯ ОЦЕНКА: {threat_level} (вес: {total_score})"
    )
    lines += _threats_by_level(unique_indicators)

    lines += _section_header(f"ТОП-{len(top_indicators)} УГРОЗ")
    for i, ind in enumerate(top_indicators, 1):
        level_label = LEVEL_LABELS.get(ind.level, ind.level.value)
        lines.append(f"  {i}. [{level_label}] {ind.description}")
        if ind.evidence:
            # Многострочное evidence выводим как есть, однострочное — без обрезки
            evidence_lines = ind.evidence.splitlines()
            if len(evidence_lines) == 1:
                lines.append(f"     Свидетельство: {ind.evidence}")
            else:
                lines.append(f"     Свидетельство:")
                for ev_line in evidence_lines:
                    lines.append(f"       {ev_line}")
        if ind.location:
            lines.append(f"     Расположение:  {ind.location}")
        lines.append("")

    lines += _section_header("ИНДИКАТОРЫ КОМПРОМЕТАЦИИ (IoC)")
    lines += _ioc_section(block_results)

    block6_raw = block_results.get(
        "block6_ioc",
        BlockResult(block_name="", success=False),
    ).raw_findings
    yara_hits = block6_raw.get("yara_hits", 0)
    if yara_hits:
        lines += _section_header("YARA СРАБАТЫВАНИЯ")
        yara_indicators = [
            ind
            for result in block_results.values()
            for ind in result.threat_indicators
            if ind.indicator_id.startswith("B6.YARA.")
        ]
        for ind in yara_indicators:
            lines.append(f"  • {ind.indicator_id}: {ind.description}")
            lines.append(f"    [{ind.level.value}] {ind.evidence}")
            lines.append("")

    lines += _section_header("РЕЗУЛЬТАТЫ БЛОКОВ")
    for block_name, result in block_results.items():
        skipped = result.raw_findings.get("skipped", False)
        if skipped:
            status = "—"
        elif result.success:
            status = "✓"
        else:
            status = "✗"
        error_suffix = f" | {result.error_message}" if result.error_message else ""
        lines.append(
            f"  {status} {block_name}: "
            f"{len(result.threat_indicators)} индикаторов, "
            f"{result.execution_time_ms} мс"
            f"{error_suffix}"
        )
    lines.append("")

    lines += _section_header("РЕКОМЕНДАЦИИ")
    for rec in RECOMMENDATIONS.get(threat_level, RECOMMENDATIONS["ЧИСТО"]):
        lines.append(f"  • {rec}")
    lines.append("")

    lines += _score_legend_section()

    lines.append(SEPARATOR)

    lines += _false_positive_section(unique_indicators)

    return lines


def _threats_by_level(indicators: list[ThreatIndicator]) -> list[str]:
    lines: list[str] = []
    by_level: dict[ThreatLevel, list[ThreatIndicator]] = {
        level: [] for level in ThreatLevel
    }
    for ind in indicators:
        by_level[ind.level].append(ind)

    for level in [
        ThreatLevel.CRITICAL,
        ThreatLevel.HIGH,
        ThreatLevel.MEDIUM,
        ThreatLevel.LOW,
        ThreatLevel.INFO,
    ]:
        group = by_level[level]
        if not group:
            continue
        label = LEVEL_LABELS[level]
        lines.append(f"\n  [{label}] — {len(group)} шт.")
        for ind in group:
            lines.append(f"    • {ind.description}")
            if ind.evidence:
                evidence_lines = ind.evidence.splitlines()
                if len(evidence_lines) == 1:
                    lines.append(f"      └ {ind.evidence}")
                else:
                    lines.append(f"      └")
                    for ev_line in evidence_lines:
                        lines.append(f"        {ev_line}")

    lines.append("")
    return lines


def _ioc_section(block_results: dict[str, BlockResult]) -> list[str]:
    lines: list[str] = []
    block6_raw = block_results.get(
        "block6_ioc",
        BlockResult(block_name="", success=False),
    ).raw_findings

    def _print_ioc_list(label: str, items: list) -> list[str]:
        if not items:
            return []
        result = [f"\n  {label} ({len(items)}):"]
        for item in items[:20]:
            result.append(f"    • {str(item)[:120]}")
        if len(items) > 20:
            result.append(f"    ... и ещё {len(items) - 20}")
        return result

    lines += _print_ioc_list("URL",           block6_raw.get("urls", []))
    lines += _print_ioc_list("IP-адреса",     block6_raw.get("ips", []))
    lines += _print_ioc_list("Ключи реестра", block6_raw.get("registry_keys", []))
    lines += _print_ioc_list("Пути Windows",  block6_raw.get("win_paths", []))
    lines += _print_ioc_list("Пути Unix",     block6_raw.get("unix_paths", []))

    lines.append("")
    return lines


def _false_positive_section(indicators: list[ThreatIndicator]) -> list[str]:
    lines: list[str] = []
    hints_shown: set[str] = set()

    for ind in indicators:
        hint = FALSE_POSITIVE_HINTS.get(ind.indicator_id)
        if hint and ind.indicator_id not in hints_shown:
            hints_shown.add(ind.indicator_id)
            if not lines:
                lines += _section_header(
                    "⚠  ТРЕБУЕТ РУЧНОЙ ПРОВЕРКИ — возможные ложные срабатывания"
                )
            lines.append(f"\n  [{ind.indicator_id}] {ind.description}")
            lines.append(f"  Пояснение: {hint}")
            lines.append("")

    return lines


def _section_header(title: str) -> list[str]:
    return ["", SEPARATOR, title, SEPARATOR]


def _kv_block(data: dict) -> list[str]:
    lines = []
    for key, value in data.items():
        lines.append(f"  {key:<25} {value or 'н/д'}")
    return lines


def _score_legend_section() -> list[str]:
    lines = _section_header("КАК РАССЧИТЫВАЕТСЯ ВЕС УГРОЗЫ")
    lines.append("  Каждый индикатор имеет вес в зависимости от уровня:")
    lines.append("")
    for level_name, weight in SCORE_LEGEND_WEIGHTS:
        lines.append(f"    {level_name:<10} = {weight} очков")
    lines.append("")
    lines.append("  Итоговый вес = сумма весов всех уникальных индикаторов.")
    lines.append("  Итоговый уровень угрозы определяется по порогам:")
    lines.append("")
    for threshold, label in SCORE_LEGEND_THRESHOLDS:
        lines.append(f"    >= {threshold:<5} → {label}")
    lines.append("")
    return lines