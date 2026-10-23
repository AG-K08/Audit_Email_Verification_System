# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block5_metadata.py
Назначение: Блок 5: Криминалистический анализ метаданных и временных меток.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import logging
import re
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from xml.etree import ElementTree

SUSPICIOUS_WHITESPACE_MIN_LENGTH = 10

import olefile

from core.models import BlockResult, ThreatIndicator, ThreatLevel

log = logging.getLogger("Block5")

BLOCK_NAME = "block5_metadata"

EXTERNAL_TEMPLATE_PATTERNS = [
    re.compile(r'^https?://', re.IGNORECASE),
    re.compile(r'^\\\\'),
]

MIN_REASONABLE_YEAR = 1990


def run(file_path: Path, block0_raw: dict) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {}

    file_format = block0_raw.get("file_format", "unknown")
    temp_dir_str = block0_raw.get("temp_dir")

    if not temp_dir_str:
        return BlockResult(
            block_name=BLOCK_NAME,
            success=False,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            error_message="temp_dir не передан из Block0",
        )

    temp_dir = Path(temp_dir_str)

    try:
        if file_format == "openxml":
            metadata = _read_openxml_metadata(temp_dir)
        elif file_format == "ole2":
            metadata = _read_ole2_metadata(file_path)
        else:
            metadata = {}
    except Exception as exc:
        log.error("Ошибка чтения метаданных: %s", exc)
        metadata = {}

    raw.update(metadata)

    try:
        new_indicators = _evaluate_metadata(metadata, file_path.name)
        indicators.extend(new_indicators)
    except Exception as exc:
        log.error("Ошибка оценки метаданных: %s", exc)

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _read_openxml_metadata(temp_dir: Path) -> dict:
    metadata: dict = {}

    core_xml = temp_dir / "docProps" / "core.xml"
    if core_xml.exists():
        metadata.update(_parse_core_xml(core_xml))

    app_xml = temp_dir / "docProps" / "app.xml"
    if app_xml.exists():
        metadata.update(_parse_app_xml(app_xml))

    return metadata


def _parse_core_xml(core_xml: Path) -> dict:
    NS = {
        "cp": "http://schemas.openxmlformats.org/package/2006/metadata/core-properties",
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
    }
    result: dict = {}
    try:
        tree = ElementTree.parse(core_xml)
        root = tree.getroot()
        for child in root:
            local_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            result[f"core_{local_name}"] = child.text
        # Алиасы для совместимости с остальным кодом
        result["creator"] = result.get("core_creator")
        result["last_modified_by"] = result.get("core_lastModifiedBy")
        result["created"] = result.get("core_created")
        result["modified"] = result.get("core_modified")
        result["revision"] = result.get("core_revision")
    except Exception as exc:
        log.debug("Ошибка парсинга core.xml: %s", exc)
    return result


def _parse_app_xml(app_xml: Path) -> dict:
    NS = {"": "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"}
    result: dict = {}
    try:
        tree = ElementTree.parse(app_xml)
        root = tree.getroot()
        for child in root:
            local_name = child.tag.split("}")[-1] if "}" in child.tag else child.tag
            result[f"app_{local_name}"] = child.text
        result["app_version"] = result.get("app_AppVersion")
        result["template"] = result.get("app_Template")
    except Exception as exc:
        log.debug("Ошибка парсинга app.xml: %s", exc)
    return result


def _xml_text(root: ElementTree.Element, tag: str, ns: dict) -> str | None:
    if ":" in tag:
        prefix, local = tag.split(":", 1)
        uri = ns.get(prefix, "")
        full_tag = f"{{{uri}}}{local}" if uri else local
    else:
        uri = ns.get("", "")
        full_tag = f"{{{uri}}}{tag}" if uri else tag
    el = root.find(full_tag)
    return el.text if el is not None else None


def _read_ole2_metadata(file_path: Path) -> dict:
    metadata: dict = {}
    try:
        with olefile.OleFileIO(str(file_path)) as ole:
            if ole.exists("\x05SummaryInformation"):
                props = ole.getproperties("\x05SummaryInformation", convert_time=True)
                metadata["creator"] = props.get(0x04)
                metadata["last_modified_by"] = props.get(0x08)
                metadata["created"] = str(props.get(0x0C, ""))
                metadata["modified"] = str(props.get(0x0D, ""))
                metadata["revision"] = str(props.get(0x09, ""))
                metadata["template"] = props.get(0x07)
    except Exception as exc:
        log.debug("Ошибка чтения OLE2 метаданных: %s", exc)
    return metadata


def _evaluate_metadata(metadata: dict, filename: str) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []

    for field_name, field_value in metadata.items():
        if not isinstance(field_value, str):
            continue
        if not re.search(r' {' + str(SUSPICIOUS_WHITESPACE_MIN_LENGTH) + r',}', field_value):
            continue
        stripped_tail = field_value.rstrip()
        tail_after_spaces = field_value[len(stripped_tail):]
        visible_after_spaces = re.sub(r'\s+', '', field_value[field_value.find('  '):])
        if visible_after_spaces:
            indicators.append(ThreatIndicator(
                indicator_id=f"B5.HIDDEN_CONTENT.{field_name.upper()[:30]}",
                level=ThreatLevel.HIGH,
                description=f"Подозрительный пробельный разрыв в поле метаданных: {field_name}",
                evidence=field_value,
                location=filename,
            ))

    template = metadata.get("template") or ""
    for pattern in EXTERNAL_TEMPLATE_PATTERNS:
        if pattern.search(template):
            indicators.append(ThreatIndicator(
                indicator_id="B5.TEMPLATE_INJECTION",
                level=ThreatLevel.HIGH,
                description="Внешний шаблон — возможный Template Injection вектор",
                evidence=template[:120],
                location=filename,
            ))
            break

    created = _parse_iso_date(metadata.get("created"))
    modified = _parse_iso_date(metadata.get("modified"))
    now = datetime.now(timezone.utc)

    if created and created > now:
        indicators.append(ThreatIndicator(
            indicator_id="B5.FUTURE_DATE_CREATED",
            level=ThreatLevel.LOW,
            description="Дата создания документа в будущем",
            evidence=str(created),
            location=filename,
        ))

    if modified and modified > now:
        indicators.append(ThreatIndicator(
            indicator_id="B5.FUTURE_DATE_MODIFIED",
            level=ThreatLevel.LOW,
            description="Дата изменения документа в будущем",
            evidence=str(modified),
            location=filename,
        ))

    if created and created.year < MIN_REASONABLE_YEAR:
        indicators.append(ThreatIndicator(
            indicator_id="B5.SUSPICIOUS_DATE",
            level=ThreatLevel.LOW,
            description=f"Подозрительная дата создания: {created.year}",
            evidence=str(created),
            location=filename,
        ))

    revision_str = str(metadata.get("revision") or "").strip()
    try:
        revision = int(revision_str)
    except ValueError:
        revision = None

    if revision == 1:
        indicators.append(ThreatIndicator(
            indicator_id="B5.REVISION_ONE",
            level=ThreatLevel.MEDIUM,
            description="Revision=1 — возможна автоматическая генерация документа",
            evidence=f"revision={revision}",
            location=filename,
        ))

    return indicators


def _parse_iso_date(date_str: str | None) -> datetime | None:
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
    except Exception:
        return None