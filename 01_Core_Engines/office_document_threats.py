# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: office_document_threats.py
Назначение: Выявление угроз документов Office без VBA (Remote Template, DDE, OLE).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import os
import re
import io
import tempfile
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

_ALLOWLIST_DOMAINS = (
    "microsoft.com",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "sharepoint.com",
    "office.com",
    "w3.org",
)

_OLE_MARKERS = (
    (b"Ole10Native", "OLE: встроенный Ole10Native (возможен исполняемый объект)"),
    (b"Package", "OLE: поток Package (встроенный файл)"),
    (b"Equation.3", "OLE: Equation Editor (CVE-2017-11882)"),
    (b"\x01Ole", "OLE: вложенный OLE-контейнер"),
)

_URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{6,200}", re.I)


def _is_allowlisted(url: str) -> bool:
    low = url.lower()
    return any(domain in low for domain in _ALLOWLIST_DOMAINS)


def _external_urls(data: bytes) -> list[str]:
    urls: list[str] = []
    for match in _URL_RE.findall(data):
        try:
            url = match.decode("ascii", errors="ignore").rstrip(".,;)")
        except Exception:
            continue
        if url and not _is_allowlisted(url):
            urls.append(url)

    # Word .doc часто хранит URL шаблона в UTF-16LE (remote template injection)
    for m in re.finditer(rb"h\x00t\x00t\x00p\x00(?:s\x00)?", data):
        start = m.start()
        chunk = data[start:start + 800]
        try:
            text = chunk.decode("utf-16le", errors="ignore")
        except Exception:
            continue
        for umatch in re.finditer(r"https?:/?[^\s\x00\"'<>]{6,200}", text, re.I):
            url = umatch.group(0).rstrip(".,;)\u0000")
            if url and not _is_allowlisted(url):
                urls.append(url)

    return list(dict.fromkeys(urls))


def _check_ole2_dde(data: bytes) -> list[str]:
    indicators: list[str] = []
    if b"\x13" not in data:
        return indicators
    if re.search(rb"\x13\s*DDEAUTO", data, re.I):
        indicators.append("DDE: DDEAUTO в потоке WordDocument (автозапуск)")
    elif re.search(rb"\x13\s*DDE", data, re.I):
        indicators.append("DDE: поле DDE в WordDocument")
    if b"DDEAUTO" in data.upper():
        indicators.append("DDE: строка DDEAUTO в OLE-документе")
    return indicators


def _check_ole2_streams_bytes(data: bytes) -> list[str]:
    indicators: list[str] = []
    try:
        import olefile
    except ImportError:
        return ["olefile не установлен — пропуск анализа OLE-потоков"]

    if not olefile.isOleFile(io.BytesIO(data)):
        return indicators

    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        for entry in ole.listdir():
            name = "/".join(entry)
            low = name.lower()
            if "ole10native" in low:
                indicators.append(f"OLE-поток: {name}")
            if low.endswith("package") or low == "package":
                indicators.append(f"OLE Package: {name}")
            if "equation" in low:
                indicators.append(f"Equation: {name}")

        if ole.exists("WordDocument"):
            stream = ole.openstream("WordDocument").read()
            indicators.extend(_check_ole2_dde(stream))
    finally:
        ole.close()
    return list(dict.fromkeys(indicators))


def _check_ole2_streams(path: Path) -> list[str]:
    try:
        return _check_ole2_streams_bytes(path.read_bytes())
    except OSError:
        return []


def _check_openxml_dde_and_fields(xml_text: str, source: str) -> list[str]:
    indicators: list[str] = []
    upper = xml_text.upper()
    if "DDEAUTO" in upper:
        indicators.append(f"DDE: DDEAUTO в {source}")
    elif re.search(r"\bDDE\b", xml_text, re.I):
        indicators.append(f"DDE: поле DDE в {source}")
    if "INCLUDEFIELD" in upper or "HYPERLINK" in upper:
        if re.search(r"https?://", xml_text, re.I):
            indicators.append(f"Word: поле HYPERLINK/INCLUDE с URL в {source}")
    return indicators


def _check_rels(rels_path: Path, rels_text: str) -> list[str]:
    indicators: list[str] = []
    rel_name = rels_path.name
    try:
        root = ET.fromstring(rels_text)
    except ET.ParseError:
        return indicators

    ns = "{http://schemas.openxmlformats.org/package/2006/relationships}"
    for rel in root.iter(f"{ns}Relationship"):
        target = rel.get("Target", "")
        rel_type = rel.get("Type", "")
        type_suffix = rel_type.rsplit("/", 1)[-1]
        if not target:
            continue
        if target.startswith("\\\\") or target.startswith("//"):
            indicators.append(f"UNC в {rel_name}: {target[:120]}")
            continue
        if not target.lower().startswith(("http://", "https://")):
            continue
        if _is_allowlisted(target):
            continue
        if type_suffix == "attachedTemplate":
            indicators.append(f"Remote Template Injection: {target}")
        elif type_suffix == "oleObject":
            indicators.append(f"Внешний OLE-объект: {target}")
        elif type_suffix == "externalLink":
            indicators.append(f"Внешняя ссылка externalLink: {target}")
        else:
            indicators.append(f"Внешняя связь ({type_suffix}): {target}")
    return indicators


def scan_office_threats(path: Path | bytes) -> dict[str, Any]:
    """Вернуть индикаторы угроз документа (без VBA). path — путь или raw bytes."""
    if isinstance(path, (bytes, bytearray)):
        data = bytes(path)
        virtual = Path("memory.doc")
    else:
        data = path.read_bytes()
        virtual = path
    ext = virtual.suffix.lower()

    if data[:2] == b"PK":
        return _scan_openxml_bytes(data)
    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" or ext in {".doc", ".xls", ".ppt", ".rtf"}:
        return _scan_ole2(virtual, data)

    return {"format": "unknown", "indicators": []}


def _scan_openxml_bytes(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"format": "openxml", "indicators": []}
    with tempfile.TemporaryDirectory(prefix="omsa_") as tmp:
        tmp_path = Path(tmp)
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                # Безопасное извлечение с защитой от Zip Slip и Zip Bomb
                safe_members = []
                total_sz = 0
                for member in zf.infolist():
                    total_sz += member.file_size
                    if total_sz > 50 * 1024 * 1024:
                        result["indicators"].append("OpenXML: превышен лимит распаковки (Zip Bomb риск)")
                        break
                    # Проверка на Path Traversal
                    tmp_resolved = tmp_path.resolve()
                    target_dst = (tmp_path / member.filename).resolve()
                    if target_dst != tmp_resolved and not str(target_dst).startswith(str(tmp_resolved) + os.sep):
                        result["indicators"].append(f"OpenXML: попытка обхода путей (Zip Slip) в {member.filename}")
                        continue
                    safe_members.append(member)
                zf.extractall(tmp_path, members=safe_members)
        except Exception as e:
            result["indicators"].append(f"OpenXML: ошибка распаковки архива ({e})")
            return result
        doc_xml = tmp_path / "word" / "document.xml"
        if doc_xml.is_file():
            text = doc_xml.read_text(encoding="utf-8", errors="replace")
            result["indicators"].extend(_check_openxml_dde_and_fields(text, "word/document.xml"))
        for rels in tmp_path.rglob("*.rels"):
            rel_text = rels.read_text(encoding="utf-8", errors="replace")
            result["indicators"].extend(_check_rels(rels, rel_text))
    result["indicators"] = list(dict.fromkeys(result["indicators"]))
    return result


def _scan_ole2(path: Path, data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"format": "ole2", "indicators": []}

    for marker, message in _OLE_MARKERS:
        if marker in data:
            result["indicators"].append(message)

    result["indicators"].extend(_check_ole2_streams_bytes(data))

    if b"attachedTemplate" in data or b"AttachedTemplate" in data:
        result["indicators"].append("Remote Template: маркер attachedTemplate в OLE")

    for token in (b"INCLUDEPICTURE", b"HYPERLINK", b"fldinst"):
        if token in data:
            result["indicators"].append(f"Word-поле: {token.decode('ascii', errors='ignore')}")

    urls = _external_urls(data)
    if urls:
        result["external_urls"] = urls[:15]
        for url in urls[:5]:
            result["indicators"].append(f"Внешний URL в документе: {url}")
        if any("attachedtemplate" in u.lower() or ".dot" in u.lower() for u in urls):
            result["indicators"].append("Remote Template Injection: URL шаблона в бинарнике")

    result["indicators"] = list(dict.fromkeys(result["indicators"]))
    return result


def main() -> int:
    import json
    import sys

    if len(sys.argv) < 2:
        print("Usage: python office_document_threats.py <file.doc|docx>")
        return 1
    path = Path(sys.argv[1])
    if not path.exists():
        print(f"File not found: {path}")
        return 1
    report = scan_office_threats(path)
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
