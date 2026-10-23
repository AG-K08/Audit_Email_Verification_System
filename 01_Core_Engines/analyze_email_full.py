# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: analyze_email_full.py
Назначение: Полный статический анализ письма (.eml / .msg) по этапам 0–9.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import email
import hashlib
import io
import json
import os
import re
import shutil
import subprocess
import sys
import zipfile
import zlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.utils import parseaddr
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

# =============================================================================
# НАСТРОЙКА: укажите путь к письму (.eml или .msg)
# =============================================================================
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_SAMPLE = ROOT / "06_Audit_Tests_and_Samples" / "test.eml"
EMAIL_PATH = str(DEFAULT_SAMPLE if DEFAULT_SAMPLE.exists() else Path("test.eml"))

SCRIPTS = Path(__file__).resolve().parent
if str(SCRIPTS) not in sys.path:
    sys.path.insert(0, str(SCRIPTS))

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

from safe_office_deep_scan import build_report
from threat_detection_tools import (
    build_yara_cache,
    collect_urls_for_nuclei,
    run_nuclei_on_urls,
    scan_bytes_yara,
)

SUSPICIOUS_EXT = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".dll", ".iso", ".img", ".lnk", ".jar", ".msi",
    ".com", ".cpl", ".pif", ".docm", ".xlsm", ".pptm", ".url",
}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz"}
OFFICE_EXT = {".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".rtf", ".docm", ".xlsm", ".pptm"}
IMAGE_EXT = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tif", ".tiff"}

URL_RE = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
PHISHING_KW = re.compile(
    r"(обновите?\s+пароль|update\s+your\s+password|verify\s+your\s+account|"
    r"подтвердите\s+уч[её]тн|срочн.*парол|account\s+update|mailbox\s+full|"
    r"приостановлен.*почт|отключени.*почт|заблокирован)",
    re.I,
)
PASSWORD_RE = re.compile(
    r"(парол[ья]?\s*[:：]\s*\S+|password\s*[:：]\s*\S+)",
    re.I,
)
TECHNICAL_URL_PARTS = (
    "schemas.microsoft.com", "openxmlformats.org", "w3.org/TR/REC-html40",
    "purl.org", "xmlsoap.org", "schema.org",
)
# Типы-контейнеры, которые редко нужны в деловой переписке (HTML smuggling, OneNote, CHM и т.д.)
RISKY_CONTAINER_EXT = {".html", ".htm", ".svg", ".one", ".chm", ".xll", ".wsh"}
# Расширения-приманки для проверки двойного расширения (act.pdf.exe)
DECOY_EXT = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".csv",
}
# Лимиты распаковки (защита анализирующей машины от zip-bomb)
MAX_ARCHIVE_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 2000
MAX_ARCHIVE_DEPTH = 3
MAX_OBJSTM_BYTES = 20 * 1024 * 1024
OFFICE_SUSPICIOUS_TOKENS = ("powershell", "cmd.exe", "WScript.Shell", "CreateObject", "AutoOpen", "Document_Open")
BIDI_CONTROL_CHARS = ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068")

from phish_engine.checks_headers import get_registrable_domain as registrable_domain

PUBLIC_MAIL_DOMAINS = (
    "gmail.com", "yahoo.com", "mail.ru", "yandex.ru", "yandex.by",
    "outlook.com", "hotmail.com", "live.com", "bk.ru", "inbox.ru", "list.ru",
)


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def md5_bytes(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()


def same_registrable_domain(host: str, sender_domain: str) -> bool:
    """Сравнение по зарегистрируемому домену, а не по подстроке (partner-org.org.evil.com != partner-org.org)."""
    a, b = registrable_domain(host), registrable_domain(sender_domain)
    return bool(a) and a == b


def attachment_name_findings(name: str) -> list[str]:
    """RTLO/bidi-символы и двойное расширение в имени вложения."""
    findings: list[str] = []
    if any(ch in name for ch in BIDI_CONTROL_CHARS):
        findings.append("Управляющие bidi-символы (RTLO) в имени файла")
    suffixes = [s.lower() for s in Path(name).suffixes]
    if len(suffixes) >= 2:
        last, prev = suffixes[-1], suffixes[-2]
        if last in (SUSPICIOUS_EXT | RISKY_CONTAINER_EXT) and prev in DECOY_EXT:
            findings.append(f"Двойное расширение: {prev}{last}")
    return findings


_MAGIC_KINDS = (
    (b"MZ", "exe"),
    (b"%PDF", "pdf"),
    (b"\x89PNG", "png"),
    (b"\xff\xd8\xff", "jpg"),
    (b"GIF8", "gif"),
    (b"\xd0\xcf\x11\xe0", "ole"),
    (b"PK\x03\x04", "zip"),
    (b"Rar!", "rar"),
    (b"7z\xbc\xaf", "7z"),
)
_EXT_KINDS = {
    "exe": {".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx"},
    "pdf": {".pdf"},
    "png": {".png"},
    "jpg": {".jpg", ".jpeg"},
    "gif": {".gif"},
    "ole": {".doc", ".xls", ".ppt", ".msi", ".msg", ".dot", ".xlt", ".pps"},
    "zip": {
        ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar",
        ".odt", ".ods", ".apk", ".xlsb", ".epub",
    },
    "rar": {".rar"},
    "7z": {".7z"},
}


def magic_kinds(name: str, data: bytes) -> tuple[str, str]:
    """(тип по сигнатуре, тип по расширению); пустая строка — тип не определён."""
    detected = next((kind for sig, kind in _MAGIC_KINDS if data.startswith(sig)), "")
    ext = Path(name).suffix.lower()
    declared = next((kind for kind, exts in _EXT_KINDS.items() if ext in exts), "")
    return detected, declared


def magic_mismatch_is_benign_image(name: str, data: bytes) -> bool:
    """jpg под .png и т.п.: встречается у почтовых клиентов и сам по себе не опасен."""
    detected, declared = magic_kinds(name, data)
    return bool(detected and declared and detected != declared and {detected, declared} <= {"png", "jpg", "gif"})


def magic_extension_mismatch(name: str, data: bytes) -> str:
    """Непустая строка, если сигнатура файла не соответствует заявленному расширению."""
    detected, declared = magic_kinds(name, data)
    if not detected:
        return ""
    ext = Path(name).suffix.lower()
    if detected == "exe" and declared != "exe":
        return f"Исполняемый PE-файл (MZ) под расширением «{ext or 'без расширения'}»"
    if declared and declared != detected:
        return f"Сигнатура {detected} не соответствует расширению {ext}"
    return ""


def html_smuggling_findings(data: bytes) -> list[str]:
    """Признаки HTML smuggling: декодирование payload в JS + сборка/скачивание файла."""
    text = data.decode("utf-8", errors="ignore")
    low = text.lower()
    findings: list[str] = []
    decoders = [t for t in ("atob(", "fromcharcode", "unescape(") if t in low]
    builders = [
        t for t in ("new blob", "createobjecturl", "mssaveblob", "msSaveOrOpenBlob".lower(), ".download")
        if t in low
    ]
    if decoders and builders:
        findings.append(f"HTML smuggling: {', '.join(decoders)} + {', '.join(builders)}")
    if "data:application/" in low and len(text) > 5000:
        findings.append("HTML: встроенный data:application/* большого размера")
    return findings


def office_suspicious_tokens(data: bytes) -> list[str]:
    """Поиск подозрительных строк с учётом сжатия OOXML (zip), а не по сжатым байтам."""
    chunks: list[bytes] = []
    if zipfile.is_zipfile(io.BytesIO(data)):
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                budget = MAX_ARCHIVE_UNPACKED_BYTES
                for info in zf.infolist():
                    if info.file_size > budget:
                        continue
                    budget -= info.file_size
                    chunks.append(zf.read(info))
        except Exception:
            chunks = [data]
    else:
        chunks = [data]
    haystack = b"\n".join(chunks).decode("latin1", errors="ignore").lower()
    # UTF-16LE (OLE/.doc): убираем нулевые байты для поиска ASCII-строк
    haystack_u16 = b"\n".join(chunks).replace(b"\x00", b"").decode("latin1", errors="ignore").lower()
    return [
        token for token in OFFICE_SUSPICIOUS_TOKENS
        if token.lower() in haystack or token.lower() in haystack_u16
    ]


def safe_stem(path: Path) -> str:
    stem = path.stem
    cleaned = re.sub(r"[^\w\-. ()\[\]]+", "_", stem, flags=re.UNICODE).strip("._ ")
    return cleaned[:80] or "email"


def unique_path(directory: Path, filename: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / filename
    if not target.exists():
        return target
    base, ext = Path(filename).stem, Path(filename).suffix
    counter = 1
    while True:
        candidate = directory / f"{base}_{counter}{ext}"
        if not candidate.exists():
            return candidate
        counter += 1


@dataclass
class AttachmentRecord:
    name: str
    path: str
    size: int
    sha256: str
    md5: str
    ext: str
    source: str = "email"
    raw_data: bytes | None = None
    analysis: dict[str, Any] = field(default_factory=dict)
    indicators: list[str] = field(default_factory=list)


class FullEmailAnalyzer:
    def __init__(self, email_path: Path):
        self.email_path = email_path.resolve()
        self.stem = safe_stem(email_path)
        self.case_dir = email_path.parent
        self.extract_dir = self.case_dir / f"Extracted_{self.stem}"
        self.report_json = self.case_dir / f"analysis_{self.stem}.json"
        self.report_txt = self.case_dir / f"analysis_{self.stem}.txt"
        self.headers_txt = self.case_dir / f"headers_{self.stem}.txt"

        self.report: dict[str, Any] = {
            "meta": {
                "analyzer": "analyze_email_full.py",
                "scan_time": datetime.now(timezone.utc).astimezone().isoformat(),
                "email_file": str(self.email_path),
                "email_sha256": "",
                "extract_dir": str(self.extract_dir),
            },
            "stages": {},
            "email": {},
            "attachments": [],
            "warnings": [],
            "verdict": "CLEAN",
        }
        self.attachments: list[AttachmentRecord] = []
        self._header_text = ""
        self._body_text = ""
        self._body_html = ""

    def log_warning(self, message: str, severity: str = "SUSPICIOUS") -> None:
        entry = {"message": message, "severity": severity}
        self.report["warnings"].append(entry)
        print(f"[!] {message}")
        if severity == "MALICIOUS":
            self.report["verdict"] = "MALICIOUS"
        elif severity == "CRITICAL":
            self.report["verdict"] = "CRITICAL"
        elif self.report["verdict"] not in ("MALICIOUS", "CRITICAL") and severity == "SUSPICIOUS":
            self.report["verdict"] = "SUSPICIOUS"

    def run(self) -> dict[str, Any]:
        if not self.email_path.exists():
            raise FileNotFoundError(f"Файл не найден: {self.email_path}")

        print(f"[*] Анализ: {self.email_path.name}")
        self.extract_dir.mkdir(parents=True, exist_ok=True)

        self.stage_0_prepare()
        if self.email_path.suffix.lower() == ".msg":
            self._load_msg()
        elif self.email_path.suffix.lower() == ".eml":
            self._load_eml()
        else:
            raise ValueError("Поддерживаются только .eml и .msg")

        self.headers_txt.write_text(self._header_text, encoding="utf-8", errors="replace")

        self.stage_1_triage()
        self.stage_2_headers()
        self.stage_3_body()
        self.stage_4_extract_attachments()
        self.stage_5_deep_attachments()
        self.stage_6_yara()
        self.stage_7_nuclei()
        self.stage_8_sandbox_note()
        self.stage_9_finalize()

        self.report_json.write_text(
            json.dumps(self.report, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        self._write_text_report()
        print(f"[+] Вложения: {self.extract_dir}")
        print(f"[+] JSON: {self.report_json}")
        print(f"[+] TXT:  {self.report_txt}")
        print(f"[+] Вердикт: {self.report['verdict']}")
        return self.report

    # ------------------------------------------------------------------ stages

    def stage_0_prepare(self) -> None:
        print("[*] Этап 0: Подготовка кейса")
        raw = self.email_path.read_bytes()
        self.report["meta"]["email_sha256"] = sha256_bytes(raw)
        self.report["meta"]["email_size"] = len(raw)
        self.report["stages"]["0_prepare"] = {
            "status": "ok",
            "extract_dir": str(self.extract_dir),
            "sha256": self.report["meta"]["email_sha256"],
        }

    def stage_1_triage(self) -> None:
        print("[*] Этап 1: Быстрый триаж")
        flags = []
        sender = self.report["email"].get("sender", "")
        sender_email = self.report["email"].get("sender_email", "")
        reply_to = self.report["email"].get("reply_to", "")

        if reply_to and sender and reply_to.lower() not in sender.lower():
            flags.append("Reply-To отличается от From")
            self.log_warning("Reply-To отличается от From", "SUSPICIOUS")

        display, email_addr = parseaddr(sender)
        if display and email_addr:
            brand_tokens = ("enterprise", "microsoft", "google", "банк", "it ", "поддержк", "security")
            if any(token in display.lower() for token in brand_tokens):
                domain = email_addr.split("@")[-1].lower()
                if domain in PUBLIC_MAIL_DOMAINS:
                    flags.append("Подмена Display Name (бренд + публичная почта)")
                    self.log_warning(
                        f"Подмена имени отправителя: «{display}» с {email_addr}",
                        "SUSPICIOUS",
                    )

        self.report["stages"]["1_triage"] = {"flags": flags}

    def stage_2_headers(self) -> None:
        print("[*] Этап 2: Анализ заголовков")
        auth = self._extract_auth(self._header_text)
        self.report["email"]["auth"] = auth

        for check, bad_values in (
            ("spf", ("fail", "softfail", "fail/softfail")),
            ("dkim", ("fail", "none", "fail/none")),
            ("dmarc", ("fail",)),
        ):
            value = auth.get(check, "")
            if any(bad in value for bad in bad_values):
                self.log_warning(f"{check.upper()}={value}", "SUSPICIOUS")

        unfolded_headers = re.sub(r"\r?\n[ \t]+", " ", self._header_text).lower()
        if not any(
            name in unfolded_headers
            for name in ("authentication-results:", "received-spf:", "arc-authentication-results:")
        ):
            # ~40% чистых писем в архиве без части auth -> слабый сигнал: фиксируем, но вердикт не меняем
            self.log_warning("Заголовки аутентификации (SPF/DKIM/DMARC) отсутствуют", "INFO")

        received = [
            line.strip()
            for line in self._header_text.splitlines()
            if line.lower().startswith("received:")
        ]
        self.report["email"]["received_chain"] = received[:10]
        self.report["stages"]["2_headers"] = {"auth": auth, "received_count": len(received)}

    def stage_3_body(self) -> None:
        print("[*] Этап 3: Анализ тела письма")
        full_body = f"{self._body_text}\n{self._body_html}"
        urls = self._extract_urls(full_body)
        self.report["email"]["urls"] = urls

        if PHISHING_KW.search(full_body):
            self.log_warning("Обнаружены фишинговые ключевые слова в теле", "SUSPICIOUS")
        if PASSWORD_RE.search(full_body):
            self.log_warning("В теле указан пароль (возможен архив с payload)", "SUSPICIOUS")
            self.report["email"]["password_in_body"] = True

        sender_email = self.report["email"].get("sender_email", "")
        sender_domain = sender_email.split("@")[-1].lower() if "@" in sender_email else ""
        misaligned = []
        for url in urls:
            if any(part in url.lower() for part in TECHNICAL_URL_PARTS):
                continue
            host = urlparse(url).hostname or ""
            host = host.lower()
            if not host or host in PUBLIC_MAIL_DOMAINS:
                continue
            if host in ("telemost.yandex.ru", "zoom.us", "teams.microsoft.com", "meet.google.com"):
                continue
            if sender_domain and not same_registrable_domain(host, sender_domain):
                misaligned.append(url)
        if misaligned:
            self.log_warning(
                f"Ссылки на домены, не совпадающие с отправителем: {len(misaligned)}",
                "SUSPICIOUS",
            )
        self.report["email"]["misaligned_urls"] = misaligned
        self.report["email"]["body_preview"] = re.sub(r"\s+", " ", full_body).strip()[:2500]

        if self._body_text.strip():
            (self.extract_dir / "body_plain.txt").write_text(self._body_text, encoding="utf-8", errors="replace")
        if self._body_html.strip():
            (self.extract_dir / "body.html").write_text(self._body_html, encoding="utf-8", errors="replace")

        self.report["stages"]["3_body"] = {
            "url_count": len(urls),
            "misaligned_url_count": len(misaligned),
        }

    def stage_4_extract_attachments(self) -> None:
        print("[*] Этап 4: Извлечение вложений")
        # Уже извлечены при загрузке; дополнительно TNEF
        tnef_count = self._extract_tnef_if_present()
        self.report["stages"]["4_extract"] = {
            "attachment_count": len(self.attachments),
            "tnef_extracted": tnef_count,
            "extract_dir": str(self.extract_dir),
        }

    def stage_5_deep_attachments(self) -> None:
        print("[*] Этап 5: Глубокий анализ вложений")
        queue = list(self.attachments)
        processed: set[str] = set()

        while queue:
            att = queue.pop(0)
            if att.path in processed:
                continue
            processed.add(att.path)
            path = Path(att.path)
            if not path.exists():
                continue

            ext = path.suffix.lower()
            self._attachment_static_checks(att, path)
            if ext == ".pdf":
                att.analysis["pdf"] = self._analyze_pdf(path)
                att.indicators.extend(self._pdf_indicators(att.analysis["pdf"]))
            elif ext in OFFICE_EXT:
                data = att.raw_data
                if not data:
                    try:
                        data = path.read_bytes()
                    except OSError as exc:
                        self.log_warning(f"{att.name}: не удалось прочитать файл ({exc})", "SUSPICIOUS")
                        continue
                att.analysis["office"] = self._analyze_office(path, data)
                att.indicators.extend(att.analysis["office"].get("indicators", []))
                activation = att.analysis["office"].get("activation_on_open", {})
                mechanism = activation.get("mechanism", "")
                if mechanism and mechanism != "Не определено статически — нужна KATA":
                    self.log_warning(
                        f"{att.name}: при открытии — {mechanism}",
                        "MALICIOUS",
                    )
            elif ext == ".url":
                att.analysis["url_file"] = self._analyze_url_file(path)
                att.indicators.extend(att.analysis["url_file"].get("indicators", []))
            elif ext in ARCHIVE_EXT:
                if att.name.count(" -> ") >= MAX_ARCHIVE_DEPTH:
                    self.log_warning(f"{att.name}: превышена глубина вложенности архивов", "SUSPICIOUS")
                    continue
                nested = self._extract_archive(path, parent_name=att.name)
                queue.extend(nested)
                att.analysis["archive"] = {"nested_files": [n.name for n in nested]}

            for indicator in att.indicators:
                low = indicator.lower()
                if any(key in indicator for key in ("JavaScript", "OpenAction", "VBA", "ОПАСНОЕ", "YARA")):
                    self.log_warning(f"{att.name}: {indicator}", "MALICIOUS")
                elif any(
                    token in low
                    for token in (
                        "ddeauto", "remote template", "template injection",
                        "equation", "ole package", "ole10native", "внешний url",
                        "внешний ole", "unc в",
                    )
                ):
                    self.log_warning(f"{att.name}: {indicator}", "MALICIOUS")
                elif "dde" in low or "ole:" in low or "подозр" in low or "macro" in low:
                    self.log_warning(f"{att.name}: {indicator}", "SUSPICIOUS")

            if ext in SUSPICIOUS_EXT and ext != ".url":
                self.log_warning(f"Опасное расширение вложения: {att.name}", "MALICIOUS")
                att.indicators.append(f"Опасное расширение: {ext}")

        self.report["stages"]["5_deep"] = {"analyzed_files": len(processed)}

    def _attachment_static_checks(self, att: AttachmentRecord, path: Path) -> None:
        """Имя, тип по сигнатуре, контейнеры повышенного риска (HTML smuggling и др.)."""
        leaf_name = att.name.split(" -> ")[-1]
        try:
            data = att.raw_data if att.raw_data else path.read_bytes()
        except OSError:
            data = b""

        for finding in attachment_name_findings(leaf_name):
            att.indicators.append(finding)
            self.log_warning(f"{att.name}: {finding}", "SUSPICIOUS")

        mismatch = magic_extension_mismatch(leaf_name, data)
        if mismatch:
            att.indicators.append(mismatch)
            benign = magic_mismatch_is_benign_image(leaf_name, data)
            self.log_warning(f"{att.name}: {mismatch}", "INFO" if benign else "SUSPICIOUS")

        ext = path.suffix.lower()
        if ext in RISKY_CONTAINER_EXT:
            att.indicators.append(f"Тип вложения повышенного риска: {ext}")
            self.log_warning(f"{att.name}: тип вложения повышенного риска ({ext})", "SUSPICIOUS")
            if ext in {".html", ".htm", ".svg"}:
                for finding in html_smuggling_findings(data):
                    att.indicators.append(finding)
                    self.log_warning(f"{att.name}: {finding}", "MALICIOUS")

    def stage_6_yara(self) -> None:
        print("[*] Этап 6: YARA (Обнаружение угроз/YARA)")
        cache_info = build_yara_cache()
        hits: list[dict[str, Any]] = []
        if cache_info.get("compiled", 0) == 0:
            self.report["stages"]["6_yara"] = {
                "status": "skipped",
                "reason": cache_info.get("reason", "нет скомпилированных правил"),
                "cache": cache_info,
            }
            return
        try:
            for att in self.attachments:
                data = att.raw_data
                if not data:
                    try:
                        data = Path(att.path).read_bytes()
                    except OSError:
                        continue
                for match in scan_bytes_yara(data):
                    hit = {
                        "file": att.name,
                        "rule": match["rule"],
                        "source_file": match.get("source_file", ""),
                        "tags": match.get("tags", []),
                    }
                    hits.append(hit)
                    indicator = f"YARA: {match['rule']} ({match.get('source_file', '')})"
                    att.indicators.append(indicator)
                    self.log_warning(f"{att.name} — {indicator}", "MALICIOUS")
            self.report["stages"]["6_yara"] = {
                "status": "ok",
                "rules_compiled": cache_info.get("compiled"),
                "rules_failed": cache_info.get("failed", 0),
                "cache": cache_info.get("status"),
                "hits": hits,
            }
        except ImportError:
            self.report["stages"]["6_yara"] = {"status": "skipped", "reason": "yara-python не установлен"}
        except Exception as exc:
            self.report["stages"]["6_yara"] = {"status": "error", "error": str(exc)}

    def stage_7_nuclei(self) -> None:
        print("[*] Этап 7: Nuclei (40k-nuclei-templates, поднабор по URL)")
        attachment_payload = [
            {"analysis": att.analysis}
            for att in self.attachments
        ]
        urls = collect_urls_for_nuclei(
            self.report.get("email", {}).get("urls", []),
            attachment_payload,
        )
        nuclei_jsonl = self.case_dir / f"nuclei_{self.stem}.jsonl"
        nuclei_result = run_nuclei_on_urls(urls, output_jsonl=nuclei_jsonl)
        self.report["stages"]["7_nuclei"] = nuclei_result

        if nuclei_result.get("status") == "skipped":
            print(f"    [i] Nuclei: {nuclei_result.get('reason', 'пропущено')}")
            return
        if nuclei_result.get("status") != "ok":
            print(f"    [!] Nuclei: {nuclei_result.get('error', nuclei_result.get('status'))}")
            return

        for finding in nuclei_result.get("findings", []):
            info = finding.get("info", {})
            severity = str(info.get("severity", "info")).lower()
            template_id = finding.get("template-id") or finding.get("templateID") or info.get("name", "unknown")
            matched = finding.get("matched-at") or finding.get("host", "")
            msg = f"Nuclei [{severity}]: {template_id} @ {matched}"
            print(f"    [!] {msg}")
            if severity in ("high", "critical"):
                self.log_warning(msg, "MALICIOUS")
            elif severity in ("medium",):
                self.log_warning(msg, "SUSPICIOUS")

    def stage_8_sandbox_note(self) -> None:
        print("[*] Этап 8: Песочница (справка)")
        note = (
            "Динамический анализ не выполнялся. "
            "При вердикте SUSPICIOUS/MALICIOUS используйте KATA / ANY.RUN или VirusTotal в изолированной среде. "
            "Для .doc/.docx без макросов обязательна песочница: Remote Template, DDE и OLE не всегда видны в olevba."
        )
        self.report["stages"]["8_sandbox"] = {
            "performed": False,
            "recommendation": note if self.report["verdict"] != "CLEAN" else "Не требуется",
        }

    def stage_9_finalize(self) -> None:
        print("[*] Этап 9: Итоговый отчёт")
        self.report["attachments"] = [
            {
                "name": a.name,
                "path": a.path,
                "size": a.size,
                "sha256": a.sha256,
                "md5": a.md5,
                "ext": a.ext,
                "source": a.source,
                "indicators": a.indicators,
                "analysis": a.analysis,
            }
            for a in self.attachments
        ]
        self.report["stages"]["9_report"] = {
            "json": str(self.report_json),
            "txt": str(self.report_txt),
            "headers": str(self.headers_txt),
            "verdict": self.report["verdict"],
        }

    # ------------------------------------------------------------------ loaders

    def _load_msg(self) -> None:
        import extract_msg

        msg = extract_msg.Message(str(self.email_path))
        try:
            header_obj = msg.header
            if header_obj is None:
                self._header_text = ""
            elif hasattr(header_obj, "as_string"):
                self._header_text = header_obj.as_string()
            else:
                self._header_text = str(header_obj)

            self._body_text = self._decode_maybe(msg.body)
            self._body_html = self._decode_maybe(msg.htmlBody)

            _, sender_email = parseaddr(msg.sender or "")
            self.report["email"] = {
                "format": "msg",
                "subject": msg.subject or "",
                "sender": msg.sender or "",
                "sender_email": sender_email.lower(),
                "to": msg.to or "",
                "cc": msg.cc or "",
                "date": str(msg.date or ""),
                "message_id": msg.messageId or "",
                "reply_to": getattr(msg, "replyTo", "") or "",
            }

            for att in msg.attachments or []:
                name = att.longFilename or att.shortFilename or "unnamed"
                data = att.data or b""
                self._save_attachment(name, data, source="msg")
        finally:
            msg.close()

    def _load_eml(self) -> None:
        raw = self.email_path.read_bytes()
        with self.email_path.open("rb") as handle:
            message = email.message_from_binary_file(handle, policy=policy.default)

        self._header_text = str(message)
        self.report["email"] = {
            "format": "eml",
            "subject": str(message.get("Subject", "")),
            "sender": str(message.get("From", "")),
            "sender_email": parseaddr(str(message.get("From", "")))[1].lower(),
            "to": str(message.get("To", "")),
            "cc": str(message.get("Cc", "")),
            "date": str(message.get("Date", "")),
            "message_id": str(message.get("Message-ID", "")),
            "reply_to": str(message.get("Reply-To", "")),
        }

        for part in message.walk():
            if part.get_content_maintype() == "multipart":
                continue
            content_type = part.get_content_type()
            if content_type == "message/rfc822":
                nested_payload = part.get_payload()
                raw_nested = b""
                if isinstance(nested_payload, list) and nested_payload:
                    sub_msg = nested_payload[0]
                    raw_nested = sub_msg.as_bytes() if hasattr(sub_msg, "as_bytes") else str(sub_msg).encode("utf-8", errors="replace")
                elif hasattr(nested_payload, "as_bytes"):
                    raw_nested = nested_payload.as_bytes()
                if not raw_nested:
                    raw_nested = part.get_payload(decode=True) or b""
                if raw_nested:
                    nested_fn = part.get_filename() or part.get_param("name") or "nested_message.eml"
                    self._save_attachment(str(nested_fn), raw_nested, source="eml_rfc822")
                continue

            payload = part.get_payload(decode=True)
            if payload is None:
                if part.get_filename() or part.get_param("name"):
                    payload = b""
                else:
                    continue

            if content_type == "text/plain" and not part.get_filename():
                charset = part.get_content_charset() or "utf-8"
                try:
                    self._body_text += payload.decode(charset, errors="replace")
                except (LookupError, ValueError):
                    self._body_text += payload.decode("utf-8", errors="replace")
            elif content_type == "text/html" and not part.get_filename():
                charset = part.get_content_charset() or "utf-8"
                try:
                    self._body_html += payload.decode(charset, errors="replace")
                except (LookupError, ValueError):
                    self._body_html += payload.decode("utf-8", errors="replace")
            else:
                filename = part.get_filename() or part.get_param("name")
                if not filename and content_type not in ("text/plain", "text/html"):
                    ext = content_type.split("/")[-1] if "/" in content_type else "bin"
                    ext = "".join(c for c in ext if c.isalnum()) or "bin"
                    filename = f"attachment.{ext}"
                if filename:
                    self._save_attachment(str(filename), payload, source="eml")

    def _save_attachment(self, name: str, data: bytes, source: str) -> None:
        raw_name = Path(str(name).replace("\\", "/")).name
        # Sanitize Windows reserved characters while keeping Unicode/extensions intact
        safe_name = re.sub(r'[<>:"/\\|?*\x00-\x1f]', "_", raw_name).strip(" .")
        if not safe_name or safe_name in {".", ".."}:
            safe_name = "attachment.bin"
        path = unique_path(self.extract_dir, safe_name)
        path.write_bytes(data)
        record = AttachmentRecord(
            name=path.name,
            path=str(path),
            size=len(data),
            sha256=sha256_bytes(data),
            md5=md5_bytes(data),
            ext=path.suffix.lower(),
            source=source,
            raw_data=data,
        )
        self.attachments.append(record)
        print(f"    [+] Извлечено: {path.name} ({len(data)} bytes)")

    # ------------------------------------------------------------------ analysis helpers

    def _extract_auth(self, header_text: str) -> dict[str, str]:
        auth = {"spf": "", "dkim": "", "dmarc": ""}
        # RFC 5322: строки-продолжения (начинаются с пробела/табуляции) относятся к предыдущему заголовку
        unfolded = re.sub(r"\r?\n[ \t]+", " ", header_text)
        for line in unfolded.splitlines():
            low = line.lower()
            if not any(token in low for token in ("authentication-results", "received-spf", "x-feas-spf")):
                continue
            if "spf=pass" in low or "spf-result=pass" in low:
                auth["spf"] = "pass"
            elif "spf=fail" in low or "spf=softfail" in low:
                auth["spf"] = auth["spf"] or "fail/softfail"
            if "dkim=pass" in low:
                auth["dkim"] = "pass"
            elif "dkim=fail" in low or "dkim=none" in low:
                auth["dkim"] = auth["dkim"] or "fail/none"
            if "dmarc=pass" in low:
                auth["dmarc"] = "pass"
            elif "dmarc=fail" in low:
                auth["dmarc"] = auth["dmarc"] or "fail"
        return auth

    def _extract_urls(self, text: str) -> list[str]:
        urls = []
        for url in URL_RE.findall(text):
            url = url.rstrip(".,;:!?)]")
            if any(part in url for part in TECHNICAL_URL_PARTS):
                continue
            urls.append(url)
        return list(dict.fromkeys(urls))

    def _decode_maybe(self, value: Any) -> str:
        if value is None:
            return ""
        if isinstance(value, bytes):
            return value.decode("utf-8", errors="replace")
        return str(value)

    def _analyze_pdf(self, path: Path) -> dict[str, Any]:
        data = path.read_bytes()
        # Тела потоков (изображения, шрифты) бинарные: в них случайно встречаются /JS и т.п., поэтому
        # сырой текст сканируется без них; содержимое /ObjStm добавляется отдельно после разжатия.
        stripped = re.sub(rb"(stream\r?\n).*?(\r?\n?endstream)", rb"\1\2", data, flags=re.S)
        text = self._pdf_normalize_names(stripped.decode("latin1", errors="ignore"))
        # Объекты внутри /ObjStm сжаты и не видны при поиске по сырым байтам — разжимаем их
        corpus, objstm_count = text, 0
        for stream_match in re.finditer(rb"stream\r?\n(.*?)\r?\n?endstream", data, re.S):
            head = data[max(0, stream_match.start() - 600):stream_match.start()].decode("latin1", errors="ignore")
            head = self._pdf_normalize_names(head)
            dict_text = head[head.rfind(" obj"):] if " obj" in head else head
            if "/ObjStm" not in dict_text or "/FlateDecode" not in dict_text:
                continue
            try:
                inflated = zlib.decompressobj().decompress(stream_match.group(1), MAX_OBJSTM_BYTES)
            except zlib.error:
                continue
            objstm_count += 1
            corpus += "\n" + self._pdf_normalize_names(inflated.decode("latin1", errors="ignore"))
        marker_patterns = {
            "/JavaScript": r"/JavaScript(?=[\s()<>\[\]{}/%]|$)",
            "/JS": r"/JS(?=[\s()<>\[\]{}/%]|$)",
            "/Launch": r"/Launch(?=[\s()<>\[\]{}/%]|$)",
            "/EmbeddedFile": r"/EmbeddedFiles?(?=[\s()<>\[\]{}/%]|$)",
            "/URI": r"/URI(?=[\s()<>\[\]{}/%]|$)",
        }
        markers = {}
        for key, pattern in marker_patterns.items():
            count = len(re.findall(pattern, corpus))
            if count:
                markers[key] = count
        result = {
            "valid": data.startswith(b"%PDF"),
            "size": len(data),
            "markers": markers,
            "objstm_streams": objstm_count,
            "uris": re.findall(r"/URI\s*\(([^)]+)\)", corpus)[:30],
        }
        try:
            from pdfminer.pdfparser import PDFParser
            from pdfminer.pdfdocument import PDFDocument

            with path.open("rb") as handle:
                doc = PDFDocument(PDFParser(handle))
                catalog = doc.catalog
                if "OpenAction" in catalog or "AA" in catalog:
                    result["open_action"] = True
                if "Names" in catalog and "JavaScript" in str(catalog["Names"]):
                    result["javascript_names"] = True
        except Exception as exc:
            result["pdfminer_error"] = str(exc)
        return result

    @staticmethod
    def _pdf_normalize_names(text: str) -> str:
        """Раскодирует имена PDF с #XX (например /#4A#53 -> /JS), как это делает PDF-ридер."""
        def decode(match: "re.Match[str]") -> str:
            return re.sub(r"#([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), match.group(0))

        return re.sub(r"/[^\s()<>\[\]{}/%]+", decode, text)

    def _pdf_indicators(self, pdf_info: dict[str, Any]) -> list[str]:
        indicators = []
        markers = pdf_info.get("markers", {})
        if markers.get("/JavaScript") or markers.get("/JS"):
            indicators.append("PDF: обнаружен JavaScript")
        if markers.get("/Launch"):
            indicators.append("PDF: обнаружен /Launch")
        if pdf_info.get("open_action"):
            indicators.append("PDF: OpenAction/AA (автозапуск)")
        if markers.get("/EmbeddedFile"):
            indicators.append("PDF: встроенный файл")
        if pdf_info.get("javascript_names"):
            indicators.append("PDF: JavaScript в Names")
        return indicators

    def _infer_activation_mechanism(self, deep: dict[str, Any]) -> str:
        urls = deep.get("external_urls_whole_file", [])
        dde = deep.get("dde_links", [])
        oleobj = deep.get("oleobj_findings", [])
        has_macros = deep.get("tools", {}).get("olevba", {}).get("has_macros")

        if dde:
            return "DDE / DDEAUTO — поле Word (автозапуск при открытии/обновлении)"
        if urls and not has_macros:
            streams = deep.get("ole_streams", {}).get("stream_hits", {})
            stream_name = next(iter(streams), "")
            where = f"поток {stream_name}" if stream_name else "бинарник документа"
            return f"Remote Template Injection — внешний шаблон Word ({where}, часто UTF-16LE)"
        if oleobj:
            return "Внешний OLE / связь — загрузка при открытии документа"
        if urls and has_macros:
            return "VBA-макросы + внешние URL"
        if has_macros:
            return "VBA-макросы (AutoOpen / Document_Open)"
        return "Не определено статически — нужна KATA"

    def _analyze_office(self, path: Path, data: bytes) -> dict[str, Any]:
        deep = build_report(data, path.name)
        result: dict[str, Any] = {
            "has_macros": deep.get("tools", {}).get("olevba", {}).get("has_macros"),
            "document_threats": deep.get("document_threats", {}),
            "activation_on_open": {
                "mechanism": self._infer_activation_mechanism(deep),
                "candidates": deep.get("activation_candidates", []),
                "external_urls": deep.get("external_urls_whole_file", []),
                "stream_hits": deep.get("ole_streams", {}).get("stream_hits", {}),
                "dde_links": deep.get("dde_links", []),
                "oleobj_findings": deep.get("oleobj_findings", []),
                "interpretation": deep.get("interpretation", ""),
            },
            "indicators": [],
        }

        for indicator in deep.get("document_threats", {}).get("indicators", []):
            result["indicators"].append(indicator)
        for url in deep.get("external_urls_whole_file", []):
            result["indicators"].append(f"Office: внешний URL (триггер сети) — {url}")
        for link in deep.get("dde_links", []):
            result["indicators"].append(f"Office: DDE — {link}")
        for finding in deep.get("oleobj_findings", []):
            result["indicators"].append(f"Office: oleobj — {finding}")

        olevba = deep.get("tools", {}).get("olevba", {})
        if olevba.get("has_macros"):
            result["indicators"].append("Office: обнаружены VBA-макросы")
            for item in olevba.get("autoexec", []):
                result["indicators"].append(f"VBA: {item.get('keyword', '')} — {item.get('desc', '')}")

        for token in office_suspicious_tokens(data):
            result["indicators"].append(f"Office: найдена строка {token}")

        result["indicators"] = list(dict.fromkeys(result["indicators"]))
        return result

    def _analyze_url_file(self, path: Path) -> dict[str, Any]:
        text = path.read_text(encoding="utf-8", errors="replace")
        urls = re.findall(r"URL=(.+)", text, flags=re.I)
        indicators = []
        if urls:
            indicators.append(f".url указывает на: {urls[0].strip()}")
        return {"content": text.strip(), "target_urls": urls, "indicators": indicators}

    def _extract_archive(self, path: Path, parent_name: str) -> list[AttachmentRecord]:
        nested_dir = unique_path(self.extract_dir / "archives", Path(parent_name).stem)
        nested_dir.mkdir(parents=True, exist_ok=True)
        extracted: list[AttachmentRecord] = []

        if path.suffix.lower() == ".zip":
            try:
                with zipfile.ZipFile(path) as zf:
                    infos = zf.infolist()
                    total = sum(i.file_size for i in infos)
                    if total > MAX_ARCHIVE_UNPACKED_BYTES or len(infos) > MAX_ARCHIVE_FILES:
                        self.log_warning(
                            f"Архив {parent_name} превышает лимит распаковки "
                            f"({total} байт, {len(infos)} файлов) — возможный zip-bomb, не распакован",
                            "SUSPICIOUS",
                        )
                        return extracted

                    nested_dir_resolved = nested_dir.resolve()
                    for info in infos:
                        target = (nested_dir / info.filename).resolve()
                        if target != nested_dir_resolved and not str(target).startswith(str(nested_dir_resolved) + os.sep):
                            self.log_warning(
                                f"Обнаружена попытка Zip Slip в {parent_name}: {info.filename}",
                                "MALICIOUS",
                            )
                            return extracted
                    zf.extractall(nested_dir)
            except Exception as exc:
                self.log_warning(f"Не удалось распаковать ZIP {parent_name}: {exc}", "SUSPICIOUS")
                return extracted
        elif path.suffix.lower() in (".tar", ".gz", ".tgz") or path.name.lower().endswith((".tar.gz", ".tar.bz2", ".tar.xz")):
            import tarfile
            try:
                with tarfile.open(path, "r:*") as tf:
                    members = tf.getmembers()
                    total = sum(m.size for m in members if m.isfile())
                    if total > MAX_ARCHIVE_UNPACKED_BYTES or len(members) > MAX_ARCHIVE_FILES:
                        self.log_warning(
                            f"Архив {parent_name} превышает лимит распаковки "
                            f"({total} байт, {len(members)} файлов) — возможный tar-bomb, не распакован",
                            "SUSPICIOUS",
                        )
                        return extracted
                    nested_dir_resolved = nested_dir.resolve()
                    safe_members = []
                    for m in members:
                        if m.issym() or m.islnk() or m.isdev():
                            self.log_warning(f"Подозрительная ссылка/устройство в TAR {parent_name}: {m.name}", "SUSPICIOUS")
                            continue
                        target = (nested_dir / m.name).resolve()
                        if target != nested_dir_resolved and not str(target).startswith(str(nested_dir_resolved) + os.sep):
                            self.log_warning(
                                f"Обнаружена попытка Tar Slip в {parent_name}: {m.name}",
                                "MALICIOUS",
                            )
                            return extracted
                        safe_members.append(m)
                    for m in safe_members:
                        if m.isfile():
                            rel_safe = Path(m.name)
                            dest_file = (nested_dir / rel_safe).resolve()
                            dest_file.parent.mkdir(parents=True, exist_ok=True)
                            f_obj = tf.extractfile(m)
                            if f_obj is not None:
                                dest_file.write_bytes(f_obj.read())
            except Exception as exc:
                self.log_warning(f"Не удалось распаковать TAR/GZ {parent_name}: {exc}", "SUSPICIOUS")
                return extracted
        else:
            seven_zip = Path(r"C:\Program Files\7-Zip\7z.exe")
            cmd = [str(seven_zip), "x", str(path), f"-o{str(nested_dir)}", "-y"] if seven_zip.exists() else ["7z", "x", str(path), f"-o{str(nested_dir)}", "-y"]
            try:
                proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                if proc.returncode != 0:
                    self.log_warning(f"Не удалось распаковать архив {parent_name}", "SUSPICIOUS")
                    return extracted
            except Exception as exc:
                self.log_warning(f"Ошибка распаковки {parent_name}: {exc}", "SUSPICIOUS")
                return extracted

        for file_path in nested_dir.rglob("*"):
            if not file_path.is_file():
                continue
            data = file_path.read_bytes()
            rel = file_path.relative_to(nested_dir).as_posix()
            record = AttachmentRecord(
                name=f"{parent_name} -> {rel}",
                path=str(file_path),
                size=len(data),
                sha256=sha256_bytes(data),
                md5=md5_bytes(data),
                ext=file_path.suffix.lower(),
                source="archive",
                raw_data=data,
            )
            self.attachments.append(record)
            extracted.append(record)
            print(f"    [+] Из архива: {record.name}")
        return extracted

    def _extract_tnef_if_present(self) -> int:
        count = 0
        try:
            from tnefparse import TNEF
        except ImportError:
            return 0

        for att in list(self.attachments):
            if att.name.lower() != "winmail.dat":
                continue
            try:
                tnef = TNEF(Path(att.path).read_bytes())
                for attachment in tnef.attachments:
                    name = attachment.name
                    if isinstance(name, bytes):
                        name = name.decode("utf-8", errors="replace")
                    self._save_attachment(name, attachment.data, source="tnef")
                    count += 1
            except Exception as exc:
                self.log_warning(f"Ошибка разбора winmail.dat: {exc}", "SUSPICIOUS")
        return count

    def _write_text_report(self) -> None:
        lines = [
            f"ВЕРДИКТ: {self.report['verdict']}",
            f"Файл: {self.email_path.name}",
            f"SHA256: {self.report['meta']['email_sha256']}",
            f"Каталог вложений: {self.extract_dir}",
            "",
            "--- Письмо ---",
            f"Тема: {self.report['email'].get('subject', '')}",
            f"From: {self.report['email'].get('sender', '')}",
            f"To: {self.report['email'].get('to', '')}",
            f"Date: {self.report['email'].get('date', '')}",
            f"Auth: {self.report['email'].get('auth', {})}",
            "",
            "--- URL ---",
        ]
        for url in self.report["email"].get("urls", []):
            lines.append(f"  {url}")
        nuclei = self.report.get("stages", {}).get("7_nuclei", {})
        if nuclei.get("findings"):
            lines.extend(["", "--- Nuclei ---"])
            for f in nuclei["findings"][:20]:
                info = f.get("info", {})
                tid = f.get("template-id", info.get("name", ""))
                sev = info.get("severity", "")
                at = f.get("matched-at", f.get("host", ""))
                lines.append(f"  [{sev}] {tid} @ {at}")
        yara = self.report.get("stages", {}).get("6_yara", {})
        if yara.get("hits"):
            lines.extend(["", "--- YARA ---"])
            for h in yara["hits"][:20]:
                lines.append(f"  {h.get('file')}: {h.get('rule')} ({h.get('source_file', '')})")
        lines.extend(["", "--- Предупреждения ---"])
        for warning in self.report["warnings"]:
            lines.append(f"  [{warning['severity']}] {warning['message']}")
        lines.extend(["", "--- Вложения ---"])
        for att in self.attachments:
            lines.append(f"  {att.name} ({att.size} bytes)")
            lines.append(f"    SHA256: {att.sha256}")
            activation = att.analysis.get("office", {}).get("activation_on_open", {})
            if activation.get("mechanism"):
                lines.append(f"    >>> При открытии: {activation['mechanism']}")
                for url in activation.get("external_urls", [])[:5]:
                    lines.append(f"    >>> URL: {url}")
            for indicator in att.indicators:
                lines.append(f"    ! {indicator}")
        lines.extend(["", "--- Этапы ---"])
        for stage, data in self.report.get("stages", {}).items():
            lines.append(f"  {stage}: {data}")
        self.report_txt.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    import argparse
    parser = argparse.ArgumentParser(description="Автономный сквозной анализатор писем (.eml / .msg, этапы 0–9)")
    parser.add_argument("file", nargs="?", default=str(EMAIL_PATH), help="Путь к анализируемому письму (.eml / .msg)")
    parser.add_argument("-o", "--output", type=Path, help="Дополнительный путь для сохранения JSON-отчета")
    args = parser.parse_args()
    target = Path(args.file)
    try:
        analyzer = FullEmailAnalyzer(target)
        analyzer.run()
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(analyzer.report_json, args.output)
            print(f"[+] Копия JSON-отчета сохранена: {args.output}")
        return 0
    except Exception as exc:
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    raise SystemExit(main())