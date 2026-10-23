# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: office_analyzer.py
Назначение: Главная точка входа подсистемы Office Macro Security Analyzer (OMSA).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import argparse
import logging
import sys
import time
from pathlib import Path

_CURRENT_DIR = Path(__file__).resolve().parent
if str(_CURRENT_DIR) not in sys.path:
    sys.path.insert(0, str(_CURRENT_DIR))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


from core.config import load_config, AnalyzerConfig
from core.logger import setup_logging, get_logger
from core.models import BlockResult
from core.threat_evaluator import (
    deduplicate_indicators,
    calculate_total_weight,
    get_threat_level_by_score,
    get_top_indicators,
)
from core.artifacts import save_artifacts
from report_generator_verbose import generate_verbose

import modules.block0_extraction as block0
import modules.block1_triage as block1
import modules.block2_vba_source as block2
import modules.block3_pcode as block3
import modules.block4_activex as block4
import modules.block5_metadata as block5
import modules.block6_ioc as block6
from report_generator import generate as generate_report
import modules.block7_document_threats as block7

SUPPORTED_EXTENSIONS = {
    ".xlsx", ".xlsm", ".xlsb", ".docx", ".docm", ".dotx", ".dotm",
    ".pptx", ".pptm", ".xltx", ".xltm", ".potx", ".potm", ".ppsx", ".ppsm",
    ".xls", ".doc", ".xlt", ".dot", ".ppt", ".pot", ".pps",
    ".rtf", ".xml", ".mht", ".mhtml",
    ".vba", ".bas", ".cls", ".frm",
}

SEPARATOR_WIDE = "=" * 80


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Office Macro Security Analyzer v1.0"
    )
    parser.add_argument("file", nargs="?", help="Путь к анализируемому файлу")
    parser.add_argument("--file", dest="file_opt", help="Путь к анализируемому файлу (альтернативный флаг)")
    parser.add_argument("--config", type=Path, help="Путь к config.yaml")
    parser.add_argument("--offline", action="store_true", help="Отключить внешние запросы")
    parser.add_argument("--pcode", action="store_true", help="Всегда запускать анализ p-code")
    parser.add_argument("-o", "--output", "--output-dir", dest="output", type=Path, help="Рабочая директория для артефактов")
    args = parser.parse_args()
    if not args.file and getattr(args, "file_opt", None):
        args.file = args.file_opt
    return args


def _resolve_file_path(args: argparse.Namespace) -> Path:
    if args.file:
        return Path(args.file)
    raw = input("\nУкажите полный путь к файлу: ").strip().strip('"').strip("'")
    return Path(raw)


def _validate_file(file_path: Path) -> str | None:
    if not file_path.exists():
        return f"Файл не найден: {file_path}"
    if not file_path.is_file():
        return f"Указан путь к директории: {file_path}"
    if file_path.suffix.lower() not in SUPPORTED_EXTENSIONS:
        return None
    return None


def _prepare_work_dir(file_path: Path, cfg: AnalyzerConfig) -> Path:
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    work_dir = cfg.output_dir / f"{file_path.stem}_{timestamp}"
    work_dir.mkdir(parents=True, exist_ok=True)
    return work_dir


def _apply_cli_overrides(cfg: AnalyzerConfig, args: argparse.Namespace) -> AnalyzerConfig:
    data = cfg.model_dump()
    if args.offline:
        data["offline_mode"] = True
    if args.pcode:
        data["always_run_pcode"] = True
    if args.output:
        data["output_dir"] = args.output
    return AnalyzerConfig(**data)


def _print_block_result(block_name: str, result: BlockResult) -> None:
    if result.raw_findings.get("skipped"):
        print(f"  [-] {block_name}: пропущен")
        return
    if not result.success:
        print(f"  [ERROR] {block_name}: ОШИБКА — {result.error_message}")
        return
    count = len(result.threat_indicators)
    ms = result.execution_time_ms
    if count:
        print(f"  [ALERT] {block_name}: {count} индикаторов [{ms} мс]")
    else:
        print(f"  [OK] {block_name}: угроз не обнаружено [{ms} мс]")


def _cleanup_temp(work_dir: Path) -> None:
    temp_dir = work_dir / "temp_"
    for temp in work_dir.glob("temp_*"):
        if temp.is_dir():
            import shutil
            shutil.rmtree(temp, ignore_errors=True)


def main() -> int:
    print(SEPARATOR_WIDE)
    print(" " * 15 + "OFFICE MACRO SECURITY ANALYZER v1.0")
    print(SEPARATOR_WIDE)

    args = parse_args()
    cfg = load_config(args.config)
    cfg = _apply_cli_overrides(cfg, args)

    file_path = _resolve_file_path(args)
    error = _validate_file(file_path)
    if error:
        print(f"\n[FATAL] {error}")
        return 1

    work_dir = _prepare_work_dir(file_path, cfg)
    setup_logging(work_dir / "analysis.log")
    log = get_logger("Orchestrator")

    log.info("Анализ файла: %s", file_path)
    log.info("Рабочая директория: %s", work_dir)

    print(f"\n  Файл:    {file_path.name}")
    print(f"  Размер:  {file_path.stat().st_size / 1024:.1f} КБ")
    print(f"  Вывод:   {work_dir}\n")

    block_results: dict[str, BlockResult] = {}

    # --- Блок 0 ---
    print(f"[Блок 0] Извлечение и подготовка...")
    result_b0 = block0.run(
        file_path, work_dir,
        cfg.max_file_size_mb,
        cfg.max_extracted_size_mb,
    )
    block_results[result_b0.block_name] = result_b0
    _print_block_result("Блок 0", result_b0)

    if not result_b0.success and "zip_slip" in str(result_b0.error_message or "").lower():
        print("\n[FATAL] Zip slip обнаружен. Анализ прерван.")
        return 1

    # --- Блок 1 ---
    print(f"[Блок 1] Триаж...")
    result_b1 = block1.run(file_path, cfg, block0_raw=result_b0.raw_findings)
    block_results[result_b1.block_name] = result_b1
    _print_block_result("Блок 1", result_b1)

    # --- Блок 2 ---
    print(f"[Блок 2] Анализ исходного кода VBA...")
    result_b2 = block2.run(file_path, result_b0.raw_findings, cfg)
    block_results[result_b2.block_name] = result_b2
    _print_block_result("Блок 2", result_b2)

    # --- Блок 3 ---
    print(f"[Блок 3] Анализ p-code...")
    vba_project_path_str = result_b0.raw_findings.get("vba_project_path")
    vba_project_path = Path(vba_project_path_str) if vba_project_path_str else None
    vba_stomping = result_b1.raw_findings.get("vba_stomping", False)

    result_b3 = block3.run(vba_project_path, result_b2.raw_findings, vba_stomping, cfg)
    block_results[result_b3.block_name] = result_b3
    _print_block_result("Блок 3", result_b3)

    # --- Блок 4 ---
    print(f"[Блок 4] Анализ ActiveX...")
    result_b4 = block4.run(result_b0.raw_findings)
    block_results[result_b4.block_name] = result_b4
    _print_block_result("Блок 4", result_b4)

    # --- Блок 5 ---
    print(f"[Блок 5] Метаданные...")
    result_b5 = block5.run(file_path, result_b0.raw_findings)
    block_results[result_b5.block_name] = result_b5
    _print_block_result("Блок 5", result_b5)

    # --- Блок 6 ---
    print(f"[Блок 6] Извлечение IoC...")
    result_b6 = block6.run(
        result_b2.raw_findings,
        result_b3.raw_findings,
        result_b4.raw_findings,
        result_b5.raw_findings,
        work_dir,
        cfg,
    )
    block_results[result_b6.block_name] = result_b6
    _print_block_result("Блок 6", result_b6)

    # --- Блок 7 ---
    print(f"[Блок 7] Угрозы в XML-разметке документа...")
    result_b7 = block7.run(result_b0.raw_findings)
    block_results[result_b7.block_name] = result_b7
    _print_block_result("Блок 7", result_b7)

    # --- Отчёт ---
    print(f"\n[Отчёт] Генерация...")
    report_path = generate_report(
        file_path, block_results, work_dir, cfg.top_threats_count
    )

    # --- Артефакты ---
    artifacts_dir: Path | None = None
    if not cfg.cleanup_temp:
        artifacts_dir = save_artifacts(
            work_dir,
            block_results,
            result_b0.raw_findings,
        )

    # --- Подробный отчёт ---
    verbose_report_path = generate_verbose(
        file_path, block_results, work_dir, artifacts_dir
    )
    log.info("Подробный отчёт: %s", verbose_report_path)
    print(f"  Подробный отчёт: {verbose_report_path}")

    if cfg.cleanup_temp:
        _cleanup_temp(work_dir)

    # --- Итоговая сводка ---
    all_indicators = [
        ind
        for result in block_results.values()
        for ind in result.threat_indicators
    ]
    unique = deduplicate_indicators(all_indicators)
    score = calculate_total_weight(unique)
    level = get_threat_level_by_score(score)
    top = get_top_indicators(unique, cfg.top_threats_count)

    print(f"\n{SEPARATOR_WIDE}")
    print(f"  ИТОГ: {level}  (вес: {score}, индикаторов: {len(unique)})")
    print(SEPARATOR_WIDE)

    if top:
        print(f"\n  Топ-{len(top)} угроз:")
        for i, ind in enumerate(top, 1):
            print(f"    {i}. [{ind.level.value}] {ind.description}")

    print(f"\n  Отчёт: {report_path}")
    print(SEPARATOR_WIDE)

    return 0


if __name__ == "__main__":
    sys.exit(main())