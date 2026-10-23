# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: report_generator_verbose.py
Назначение: Генератор детализированных отчетов OMSA с дампом псевдокода.

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
)

log = logging.getLogger("ReportGeneratorVerbose")

SEPARATOR = "═" * 80
THIN_SEP = "─" * 60


def generate_verbose(
    file_path: Path,
    block_results: dict[str, BlockResult],
    work_dir: Path,
    artifacts_dir: Path | None,
) -> Path:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    all_indicators = [
        ind for result in block_results.values() for ind in result.threat_indicators
    ]
    unique_indicators = deduplicate_indicators(all_indicators)
    total_score = calculate_total_weight(unique_indicators)
    threat_level = get_threat_level_by_score(total_score)

    lines: list[str] = []
    lines += _header(file_path, block_results, now, threat_level, total_score)
    lines += _chapter_block0(block_results.get("block0_extraction"))
    lines += _chapter_block1(block_results.get("block1_triage"))
    lines += _chapter_block2(block_results.get("block2_vba_source"))
    lines += _chapter_block3(block_results.get("block3_pcode"))
    lines += _chapter_block4(block_results.get("block4_activex"))
    lines += _chapter_block5(block_results.get("block5_metadata"))
    lines += _chapter_block6(block_results.get("block6_ioc"))
    lines += _chapter_block7(block_results.get("Block7_DocumentThreats"))
    lines += _final_summary(threat_level, total_score, unique_indicators, artifacts_dir)

    report_path = work_dir / f"{file_path.stem}_report_verbose.txt"
    report_path.write_text("\n".join(lines), encoding="utf-8")
    log.info("Подробный отчёт сохранён: %s", report_path)
    return report_path


def _header(
    file_path: Path,
    block_results: dict[str, BlockResult],
    now: str,
    threat_level: str,
    total_score: int,
) -> list[str]:
    block0_raw = block_results.get("block0_extraction", BlockResult(
        block_name="", success=False
    )).raw_findings
    hashes = block0_raw.get("hashes", {})

    return [
        SEPARATOR,
        "OFFICE MACRO SECURITY ANALYZER — ПОДРОБНЫЙ ОТЧЁТ",
        SEPARATOR,
        f"  Файл:              {file_path.name}",
        f"  Путь:              {file_path}",
        f"  Дата анализа:      {now}",
        f"  Итоговая оценка:   {threat_level} (вес: {total_score})",
        f"  MD5:               {hashes.get('md5', 'н/д')}",
        f"  SHA256:            {hashes.get('sha256', 'н/д')}",
        "",
    ]


def _section(title: str) -> list[str]:
    return ["", SEPARATOR, title, SEPARATOR]


def _what_we_did(description: str) -> list[str]:
    return [f"  ЧТО ДЕЛАЛИ: {description}"]


def _finding(text: str) -> list[str]:
    return [f"  РЕЗУЛЬТАТ:  {text}"]


def _no_findings() -> list[str]:
    return ["  РЕЗУЛЬТАТ:  Проверка выполнена — подозрительных признаков не обнаружено."]


def _indicators_summary(indicators: list[ThreatIndicator]) -> list[str]:
    if not indicators:
        return []
    lines = ["  ИНДИКАТОРЫ:"]
    for ind in indicators:
        lines.append(f"    [{ind.level.value}] {ind.indicator_id} — {ind.description}")
        if ind.evidence:
            lines.append(f"           Свидетельство: {ind.evidence[:120]}")
    return lines


def _block_skipped(block_name: str, reason: str) -> list[str]:
    return [f"  СТАТУС: Пропущен — {reason}"]


def _chapter_block0(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 1. ИЗВЛЕЧЕНИЕ И ПОДГОТОВКА (Block0)")
    lines += _what_we_did(
        "Определяли формат файла по magic bytes. Вычисляли хеши (MD5, SHA1, SHA256). "
        "Распаковывали контейнер. Искали vbaProject.bin и embedded OLE-объекты."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    lines += _finding(f"Формат файла: {raw.get('file_format', 'неизвестен')}")
    lines += _finding(f"Размер файла: {raw.get('file_size_bytes', 0) / 1024:.1f} КБ")

    vba_path = raw.get("vba_project_path")
    if vba_path:
        lines += _finding(f"vbaProject.bin: найден → {vba_path}")
    else:
        lines += _finding("vbaProject.bin: не найден в корне temp, будет выполнен рекурсивный поиск в Block1 fallback")

    embedded = raw.get("embedded_objects", [])
    if embedded:
        lines += _finding(f"Embedded OLE-объекты: {len(embedded)} шт. — {', '.join(embedded[:3])}")
    else:
        lines += _finding("Embedded OLE-объекты: не найдены")

    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block1(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 2. ТРИАЖ (Block1)")
    lines += _what_we_did(
        "Запускали VBA_Parser (oletools) для обнаружения макросов стандартным методом. "
        "Проверяли наличие VBA Stomping, AutoExec триггеров, XLM-макросов."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    has_macros = raw.get("has_macros", False)
    fallback_used = raw.get("fallback_used", False)
    fallback_unavailable = raw.get("fallback_unavailable", False)

    if not fallback_used:
        lines += _finding(
            f"VBA_Parser: {'макросы обнаружены' if has_macros else 'макросы не обнаружены'}"
        )
    else:
        lines += _finding("VBA_Parser: макросы не обнаружены")
        lines += ["", "  → Активирован OLE Fallback (oledump)"]
        vba_project_path = raw.get("fallback_target_path", "vbaProject.bin (извлечён из ZIP Block0)")
        lines += _what_we_did(
            f"Файл vbaProject.bin является OLE2-контейнером извлечённым из ZIP-архива документа. "
            f"Путь: {vba_project_path}. "
            f"Запускали oledump на этом OLE2-контейнере для поиска VBA-потоков."
        )

        if fallback_unavailable:
            lines += _finding("oledump не установлен — fallback недоступен")
        else:
            streams = raw.get("fallback_streams", [])
            macro_streams = [s for s in streams if s.get("has_macro")]
            if macro_streams:
                stream_ids = ", ".join(s["stream_id"] for s in macro_streams)
                lines += _finding(f"Найдены потоки с маркером M (macro): {stream_ids}")
                lines += _what_we_did(
                    f"Извлекали содержимое потоков {stream_ids} через oledump -s <id> -v. "
                    "Извлечённый код передан в Блок 2 для сигнатурного анализа."
                )
                lines += _finding(
                    f"Код извлечён из {len(macro_streams)} потока(ов), "
                    f"суммарно {len(raw.get('vba_code', ''))} символов"
                )
            else:
                lines += _finding("oledump: потоков с маркером M не найдено")

    vba_stomping = raw.get("vba_stomping", False)
    lines += _finding(f"VBA Stomping: {'обнаружен' if vba_stomping else 'не обнаружен'}")

    macro_names = raw.get("macro_names", [])
    if macro_names:
        lines += _finding(f"Модули: {', '.join(macro_names[:10])}")

    mraptor = raw.get("mraptor_verdict", "")
    if mraptor:
        lines += _finding(f"mraptor: {mraptor}")

    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block2(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 3. АНАЛИЗ ИСХОДНОГО КОДА VBA (Block2)")
    lines += _what_we_did(
        "Анализировали VBA-код по сигнатурным категориям: сеть, выполнение кода, "
        "реестр, файловая система, управление процессами, самомодификация, "
        "системные утилиты в строковых литералах. "
        "Проверяли обфускацию: Chr()-конкатенация, Unicode-идентификаторы, энтропия. "
        "Искали Base64-закодированные строки с опасным содержимым."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    module_count = raw.get("module_count", 0)

    if module_count == 0:
        lines += _finding("VBA-модули не найдены — анализ сигнатур не выполнялся")
        return lines

    lines += _finding(f"Проверено модулей: {module_count}")

    for module in raw.get("modules", []):
        lines += [
            "",
            f"  {THIN_SEP}",
            f"  Модуль: {module['name']} "
            f"({module['line_count']} строк, энтропия: {module.get('entropy', 0):.2f})",
        ]

    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block3(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 4. АНАЛИЗ P-CODE / VBA STOMPING (Block3)")

    if not result:
        lines += _block_skipped("Block3", "нет данных")
        return lines

    if result.raw_findings.get("skipped"):
        reason = result.raw_findings.get("reason", "VBA Stomping не обнаружен, always_run_pcode=false")
        lines += _block_skipped("Block3", reason)
        return lines

    lines += _what_we_did(
        "Дизассемблировали p-code из vbaProject.bin через pcodedmp. "
        "Сравнивали список функций в p-code и исходном коде. "
        "Искали функции присутствующие только в p-code (признак stomping)."
    )
    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block4(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 5. АНАЛИЗ ActiveX (Block4)")
    lines += _what_we_did(
        "Сканировали ActiveX-объекты в документе. "
        "Извлекали CLSID каждого объекта и сверяли с базой опасных CLSID "
        "(WScript.Shell, XMLHTTP, FSO, MSCOMCTL и др.). "
        "Проверяли общее количество объектов на аномальность."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    count = raw.get("activex_count", 0)
    suspicious = raw.get("activex_suspicious_count", count)
    whitelist = raw.get("activex_whitelist_count", 0)
    lines += _finding(f"Найдено ActiveX-объектов всего: {count}")
    if whitelist > 0:
        lines += _finding(
            f"Из них легитимных (MSForms whitelist): {whitelist} — не учитываются в оценке угрозы"
        )
    lines += _finding(f"Подозрительных (вне whitelist): {suspicious}")
    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block5(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 6. МЕТАДАННЫЕ ДОКУМЕНТА (Block5)")
    lines += _what_we_did(
        "Извлекали метаданные документа: автор, дата создания и изменения, ревизия, "
        "версия приложения, шаблон. "
        "Проверяли Template Injection (внешний шаблон по http/UNC). "
        "Проверяли аномалии дат и признаки автогенерации (Revision=1)."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    lines += _finding(f"Автор (Creator):       {raw.get('creator', 'н/д')}")
    lines += _finding(f"Последний редактор:    {raw.get('last_modified_by', 'н/д')}")
    lines += _finding(f"Дата создания:         {raw.get('created', 'н/д')}")
    lines += _finding(f"Дата изменения:        {raw.get('modified', 'н/д')}")
    lines += _finding(f"Ревизия:               {raw.get('revision', 'н/д')}")
    lines += _finding(f"Шаблон:                {raw.get('template', 'н/д') or 'не задан'}")
    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block6(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 7. ИЗВЛЕЧЕНИЕ IoC (Block6)")
    lines += _what_we_did(
        "Извлекали из VBA-кода и декодированных строк: URL, IP-адреса, "
        "пути файловой системы, ключи реестра, имена системных утилит. "
        "При наличии API-ключа проверяли URL через VirusTotal. "
        "При наличии YARA-правил — выполняли сканирование кода."
    )

    if not result or not result.success:
        lines += _finding("Блок завершился с ошибкой: " + (result.error_message if result else "нет данных"))
        return lines

    raw = result.raw_findings
    ioc_count = raw.get("iocs_count", 0) if "iocs_count" in raw else sum(
        len(v) for v in raw.get("iocs", {}).values()
    )

    if ioc_count == 0:
        lines += _finding("IoC не обнаружены")
    else:
        lines += _finding(f"Найдено IoC: {ioc_count}")
        for ioc_type, values in raw.get("iocs", {}).items():
            if values:
                lines += [f"    {ioc_type}: {', '.join(list(values)[:5])}"]

    lines += _indicators_summary(result.threat_indicators)
    lines += [f"  Время выполнения: {result.execution_time_ms} мс"]
    return lines


def _chapter_block7(result: BlockResult | None) -> list[str]:
    lines = _section("ГЛАВА 8. УГРОЗЫ В XML-РАЗМЕТКЕ ДОКУМЕНТА (Block7)")
    lines += _what_we_did(
        "Анализировали XML-содержимое документа на наличие DDE-инъекций "
        "(поля DDE/DDEAUTO в word/document.xml и xl/worksheets/*.xml). "
        "Проверяли OLE2-поток WordDocument на байтовые паттерны DDE. "
        "Сканировали все .rels файлы на предмет опасных внешних связей: "
        "Template Injection, OLE external, External Link, UNC-пути."
    )

    if not result:
        lines += _block_skipped("Block7", "нет данных")
        return lines

    raw = result.raw_findings if hasattr(result, "raw_findings") else {}

    if raw.get("skipped"):
        lines += _block_skipped("Block7", raw.get("skipped", "формат не поддерживается"))
        return lines

    if raw.get("error"):
        lines += _finding(f"Ошибка: {raw.get('error')}")
        return lines

    # --- DDE ---
    dde = raw.get("dde_analysis") or raw.get("ole2_dde") or []
    if dde:
        lines += _finding(f"DDE-инъекции: обнаружено {len(dde)} совпадений")
        for item in dde[:5]:
            lines += [
                f"    [{item.get('level', '?')}] {item.get('code', '?')} "
                f"в {item.get('source', '?')}",
                f"      Свидетельство: {str(item.get('evidence', ''))[:120]}",
            ]
        if len(dde) > 5:
            lines += [f"    ... и ещё {len(dde) - 5} совпадений"]
    else:
        lines += _finding("DDE-инъекции: не обнаружены")

    # --- Внешние связи ---
    rels = raw.get("external_rels", [])
    if rels:
        lines += _finding(f"Опасные внешние связи: обнаружено {len(rels)}")
        for item in rels[:10]:
            lines += [
                f"    [{item.get('level', '?')}] {item.get('code', '?')} "
                f"в {item.get('source', '?')}",
                f"      Target: {str(item.get('evidence', ''))[:120]}",
            ]
        if len(rels) > 10:
            lines += [f"    ... и ещё {len(rels) - 10} связей"]
    else:
        lines += _finding("Внешние связи: подозрительных не обнаружено")

    indicators = result.threat_indicators if hasattr(result, "threat_indicators") else []
    lines += _indicators_summary(indicators)
    score = result.score if hasattr(result, "score") else 0
    lines += [f"  Вес блока: {score}"]
    return lines


def _final_summary(
    threat_level: str,
    total_score: int,
    unique_indicators: list[ThreatIndicator],
    artifacts_dir: Path | None,
) -> list[str]:
    lines = _section("ИТОГОВАЯ ОЦЕНКА")
    lines += [
        f"  Уровень угрозы:    {threat_level}",
        f"  Суммарный вес:     {total_score}",
        f"  Уникальных угроз:  {len(unique_indicators)}",
    ]

    if artifacts_dir:
        lines += [f"  Артефакты:         {artifacts_dir}"]

    lines += ["", SEPARATOR]
    return lines