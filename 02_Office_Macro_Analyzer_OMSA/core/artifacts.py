# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: artifacts.py
Назначение: Управление промежуточными артефактами декомпиляции.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import json
import logging
import shutil
from pathlib import Path

from core.models import BlockResult

log = logging.getLogger("Artifacts")

ARTIFACTS_DIR_PREFIX = "artifacts_"


def save_artifacts(
    work_dir: Path,
    block_results: dict[str, BlockResult],
    block0_raw: dict,
) -> Path:
    sha256 = block0_raw.get("hashes", {}).get("sha256", "unknown")
    artifacts_dir = work_dir / f"{ARTIFACTS_DIR_PREFIX}{sha256[:12]}"
    artifacts_dir.mkdir(parents=True, exist_ok=True)

    _save_ole_stream_artifacts(artifacts_dir, block_results)
    _save_vba_module_artifacts(artifacts_dir, block_results)
    _save_xml_parts(artifacts_dir, block0_raw)
    _save_binary_parts(artifacts_dir, block0_raw)

    log.info("Артефакты сохранены: %s", artifacts_dir)
    return artifacts_dir


def _save_ole_stream_artifacts(
    artifacts_dir: Path,
    block_results: dict[str, BlockResult],
) -> None:
    block1_raw = block_results.get("block1_triage", BlockResult(
        block_name="", success=False
    )).raw_findings

    if not block1_raw.get("fallback_used"):
        return

    ole_dir = artifacts_dir / "ole_streams"
    ole_dir.mkdir(exist_ok=True)

    for stream in block1_raw.get("fallback_streams", []):
        stream_id = stream["stream_id"]

        info_path = ole_dir / f"stream_{stream_id}_info.json"
        with info_path.open("w", encoding="utf-8") as f:
            json.dump({
                "stream_id": stream_id,
                "has_macro": stream["has_macro"],
                "raw_line": stream.get("raw_line", ""),
            }, f, indent=2, ensure_ascii=False)

        code = stream.get("extracted_code", "")
        if code:
            raw_path = ole_dir / f"stream_{stream_id}_raw.txt"
            raw_path.write_text(code, encoding="utf-8")


def _save_vba_module_artifacts(
    artifacts_dir: Path,
    block_results: dict[str, BlockResult],
) -> None:
    block2_raw = block_results.get("block2_vba_source", BlockResult(
        block_name="", success=False
    )).raw_findings

    modules = block2_raw.get("modules", [])
    if not modules:
        return

    vba_dir = artifacts_dir / "vba_source"
    vba_dir.mkdir(exist_ok=True)

    for module in modules:
        name = module.get("name", "unknown").replace("/", "_").replace("\\", "_")
        code = module.get("code", "")
        if code:
            module_path = vba_dir / f"{name}.vba"
            module_path.write_text(code, encoding="utf-8")


def _save_xml_parts(artifacts_dir: Path, block0_raw: dict) -> None:
    temp_dir_str = block0_raw.get("temp_dir")
    if not temp_dir_str:
        return

    temp_dir = Path(temp_dir_str)
    xml_dest = artifacts_dir / "xml_parts"
    xml_dest.mkdir(exist_ok=True)

    for xml_file in temp_dir.rglob("*.xml"):
        try:
            shutil.copy2(xml_file, xml_dest / xml_file.name)
        except Exception as exc:
            log.debug("Не удалось скопировать %s: %s", xml_file, exc)


def _save_binary_parts(artifacts_dir: Path, block0_raw: dict) -> None:
    temp_dir_str = block0_raw.get("temp_dir")
    if not temp_dir_str:
        return

    temp_dir = Path(temp_dir_str)
    bin_dest = artifacts_dir / "binary_parts"
    bin_dest.mkdir(exist_ok=True)

    for bin_file in temp_dir.rglob("*.bin"):
        try:
            shutil.copy2(bin_file, bin_dest / bin_file.name)
        except Exception as exc:
            log.debug("Не удалось скопировать %s: %s", bin_file, exc)