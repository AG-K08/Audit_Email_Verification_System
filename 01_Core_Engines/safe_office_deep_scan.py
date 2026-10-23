# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: safe_office_deep_scan.py
Назначение: Безопасный in-memory разбор структуры документов MS Office.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import argparse
import email
import hashlib
import io
import json
import re
import sys
from contextlib import redirect_stdout
from email import policy
from pathlib import Path
from typing import Any

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

from office_document_threats import scan_office_threats

ALLOWLIST = (
    "microsoft.com",
    "openxmlformats.org",
    "schemas.microsoft.com",
    "office.com",
    "w3.org",
    "trafficmanager.net",
    "cloudapp.azure.com",
)

URL_RE = re.compile(rb"https?://[^\s\x00\"'<>]{6,200}", re.I)
UNC_RE = re.compile(rb"\\\\[a-zA-Z0-9._$-]{2,}[^\s\x00\"'<>]{0,120}")
MHTML_RE = re.compile(rb"mhtml:[^\s\x00\"'<>]{6,200}", re.I)


def md5_hex(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def external_urls(data: bytes) -> list[str]:
    from office_document_threats import _external_urls

    return _external_urls(data)


def load_bytes(path: Path, attachment_index: int | None) -> tuple[bytes, str]:
    if path.suffix.lower() == ".eml":
        msg = email.message_from_bytes(path.read_bytes(), policy=policy.default)
        attachments: list[tuple[str, bytes]] = []
        for part in msg.walk():
            name = part.get_filename()
            payload = part.get_payload(decode=True)
            if name and payload:
                attachments.append((name, payload))
        if not attachments:
            raise ValueError("В письме нет вложений")
        idx = attachment_index if attachment_index is not None else 0
        if idx < 0 or idx >= len(attachments):
            raise IndexError(f"Индекс вложения {idx} выходит за границы (всего вложений: {len(attachments)})")
        name, data = attachments[idx]
        return data, name
    if path.suffix.lower() == ".msg":
        raise ValueError("Для .msg: analyze_email_full.py → затем safe_office_deep_scan.py на .eml")
    return path.read_bytes(), path.name


def analyze_streams_in_memory(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {"streams": [], "stream_hits": {}}
    try:
        import olefile
    except ImportError:
        result["error"] = "olefile не установлен"
        return result

    if data[:8] != b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return result

    ole = olefile.OleFileIO(io.BytesIO(data))
    try:
        result["streams"] = ["/".join(entry) for entry in ole.listdir()]
        for entry in ole.listdir():
            name = "/".join(entry)
            try:
                stream = ole.openstream(entry).read()
            except Exception:
                continue
            text = stream.decode("latin1", errors="replace")
            tokens: list[str] = []
            for token in (
                "attachedTemplate", "DDEAUTO", "DDE", "INCLUDEPICTURE",
                "HYPERLINK", "Ole10Native", "Package", "Equation.3", "Target",
                "mhtml:", "adnox",
            ):
                if token.lower() in text.lower():
                    tokens.append(token)
            urls = external_urls(stream)
            if tokens or urls:
                result["stream_hits"][name] = {
                    "tokens": tokens,
                    "external_urls": urls[:10],
                    "size": len(stream),
                }
    finally:
        ole.close()
    return result


def run_olevba_api(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"module": "olevba"}
    try:
        from oletools.olevba import VBA_Parser

        parser = VBA_Parser("memory.doc", data=data)
        try:
            out["has_macros"] = parser.detect_vba_macros()
            out["type"] = parser.type
            out["autoexec"] = [
                {"keyword": k, "desc": d}
                for k, d in parser.analyze_macros()
                if k in {"AutoExec", "Suspicious", "IOC", "Template Injection"}
            ][:20]
        finally:
            parser.close()
    except Exception as exc:
        out["error"] = str(exc)
    return out


def run_oleid_api(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"module": "oleid"}
    try:
        from oletools.oleid import OleID

        oid = OleID(filename="memory.doc", data=data)
        oid.check()
        out["indicators"] = [
            {"name": i.name, "value": str(i.value), "risk": i.risk}
            for i in oid.indicators
        ]
    except Exception as exc:
        out["error"] = str(exc)
    return out


def run_oleobj_api(data: bytes, display_name: str) -> dict[str, Any]:
    """In-memory аналог oleobj: внешние связи, OLE Package, customUI."""
    out: dict[str, Any] = {"module": "oleobj", "findings": []}
    try:
        from oletools.oleobj import (
            OleNativeStream,
            find_customUI,
            find_external_relationships,
            find_ole,
            is_zipfile,
        )
        from oletools.oleobj import XmlParser

        xml_parser = None
        if is_zipfile(io.BytesIO(data)):
            xml_parser = XmlParser(io.BytesIO(data))
            for _ in xml_parser.iter_xml():
                pass
            for rel_type, target in find_external_relationships(xml_parser):
                out["findings"].append(
                    f"External relationship '{rel_type}': {target}"
                )
            for target in find_customUI(xml_parser):
                out["findings"].append(f"customUI onLoad: {target}")

        for ole in find_ole(display_name, data, xml_parser):
            if ole is None:
                continue
            for path_parts in ole.listdir():
                if path_parts[-1].lower() != "\x01ole10native":
                    continue
                stream = None
                try:
                    stream = ole.openstream(path_parts)
                    opkg = OleNativeStream(stream)
                    if opkg.is_link:
                        out["findings"].append(
                            f"OLE link: filename={opkg.filename!r} "
                            f"src_path={opkg.src_path!r} temp_path={opkg.temp_path!r}"
                        )
                    else:
                        out["findings"].append(
                            f"OLE embedded: filename={opkg.filename!r} "
                            f"src_path={opkg.src_path!r}"
                        )
                except Exception:
                    pass
                finally:
                    if stream is not None:
                        stream.close()
    except Exception as exc:
        out["error"] = str(exc)
    return out


def run_msodde_api(data: bytes) -> dict[str, Any]:
    out: dict[str, Any] = {"module": "msodde", "dde_links": []}
    try:
        import olefile
        from oletools import msodde

        if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
            with olefile.OleFileIO(io.BytesIO(data)) as ole:
                text = msodde.process_doc(ole)
                if text:
                    out["dde_links"] = [line.strip() for line in text.splitlines() if line.strip()]
        elif data[:2] == b"PK":
            from oletools.oleobj import FakeFile

            text = msodde.process_docx(FakeFile(data))
            if text:
                out["dde_links"] = [line.strip() for line in text.splitlines() if line.strip()]
    except Exception as exc:
        out["error"] = str(exc)
    return out


def build_activation_candidates(report: dict[str, Any]) -> list[dict[str, Any]]:
    candidates: list[dict[str, Any]] = []

    for link in report.get("dde_links", []):
        candidates.append({"type": "DDE / Word field", "detail": link, "priority": "high"})

    for finding in report.get("oleobj_findings", []):
        candidates.append({"type": "External OLE / Template", "detail": finding, "priority": "high"})

    for url in report.get("external_urls_whole_file", []):
        candidates.append({"type": "URL in binary (cleartext)", "detail": url, "priority": "medium"})

    for stream, info in report.get("ole_streams", {}).get("stream_hits", {}).items():
        if info.get("external_urls") or "attachedTemplate" in info.get("tokens", []):
            candidates.append({
                "type": f"OLE stream: {stream}",
                "detail": info,
                "priority": "high",
            })

    for ind in report.get("document_threats", {}).get("indicators", []):
        low = ind.lower()
        prio = "high" if any(x in low for x in ("dde", "template", "ole", "equation")) else "medium"
        candidates.append({"type": "document_threats", "detail": ind, "priority": prio})

    for item in report.get("tools", {}).get("oleid", {}).get("indicators", []):
        if item.get("risk") in ("HIGH", "MEDIUM") and item.get("value") not in ("False", "0", ""):
            candidates.append({
                "type": "oleid",
                "detail": f"{item['name']}: {item['value']} (risk={item['risk']})",
                "priority": "medium",
            })

    return candidates


def build_report(data: bytes, display_name: str) -> dict[str, Any]:
    report: dict[str, Any] = {
        "file": display_name,
        "size": len(data),
        "md5": md5_hex(data),
        "sha256": sha256_hex(data),
        "analysis_mode": "in-memory (no Word, no disk write of sample)",
        "external_urls_whole_file": external_urls(data)[:20],
        "document_threats": scan_office_threats(data),
        "ole_streams": analyze_streams_in_memory(data),
        "tools": {},
    }

    report["tools"]["olevba"] = run_olevba_api(data)
    report["tools"]["oleid"] = run_oleid_api(data)

    oleobj = run_oleobj_api(data, display_name)
    report["tools"]["oleobj"] = oleobj
    report["oleobj_findings"] = oleobj.get("findings", [])

    msodde = run_msodde_api(data)
    report["tools"]["msodde"] = msodde
    report["dde_links"] = msodde.get("dde_links", [])

    report["activation_candidates"] = build_activation_candidates(report)

    if not report["activation_candidates"] and not report["tools"]["olevba"].get("has_macros"):
        report["interpretation"] = (
            "Статика не нашла явный URL/шаблон в открытом виде. "
            "Для Trojan-Downloader.MSOffice.Agent типичен скрытый remote template "
            "или поле Word, срабатывающее только при открытии в WINWORD.EXE."
        )
        report["safe_next_steps"] = [
            "Не открывать на рабочей станции.",
            "KATA / ANY.RUN в изолированной VM: смотреть DNS/HTTP из WINWORD.EXE.",
            "Зафиксировать скачанный .dotm/.doc и проанализировать его этим же скриптом.",
            "Заблокировать домены из сетевого отчёта (например adnox.ru).",
            "Для будущих писем: oleid → oleobj → msodde → olevba → KATA при чистой статике.",
        ]
    else:
        report["interpretation"] = "Найдены статические индикаторы, которые могут активировать сеть при открытии."
        report["safe_next_steps"] = [
            "Не открывать в Word на рабочей машине.",
            "Заблокировать найденные URL/домены на прокси.",
            "При external template — скачать шаблон в изоляции и повторить анализ.",
            "Подтвердить поведение в KATA.",
        ]

    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="Безопасный глубокий разбор Office (in-memory)")
    parser.add_argument("path", help="Путь к .doc/.docx или .eml с вложением")
    parser.add_argument("--attachment-index", type=int, default=None)
    parser.add_argument("--stdout", action="store_true", help="Вывести JSON в stdout")
    args = parser.parse_args()

    path = Path(args.path)
    if not path.exists():
        print(f"Файл не найден: {path}", file=sys.stderr)
        return 1

    try:
        data, name = load_bytes(path, args.attachment_index)
    except Exception as exc:
        print(f"Ошибка загрузки: {exc}", file=sys.stderr)
        return 1

    report = build_report(data, name)
    payload = json.dumps(report, ensure_ascii=False, indent=2)

    if args.stdout:
        print(payload)
    else:
        out = path.parent / f"deep_scan_{Path(name).stem[:40]}.json"
        out.write_text(payload, encoding="utf-8")
        print(f"Saved: {out}")
        print(f"Activation candidates: {len(report['activation_candidates'])}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
