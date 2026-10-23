# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: checks_attachments.py
Назначение: Модуль триажа вложений и композитных атак (Staged Assembly).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import io
import re
import tarfile
import zipfile
import zlib
from pathlib import Path
from typing import List, Dict, Any, Tuple

from .scoring import Finding, Category, Severity
from .checks_quishing import QuishingChecker

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse",
    ".wsf", ".hta", ".dll", ".iso", ".img", ".lnk", ".jar", ".msi",
    ".com", ".cpl", ".pif", ".docm", ".xlsm", ".pptm", ".url",
    ".html", ".htm", ".svg", ".one", ".chm", ".xll", ".wsh"
}

DECOY_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf",
    ".jpg", ".jpeg", ".png", ".gif", ".zip", ".rar", ".7z", ".csv"
}

MAGIC_SIGNATURES = (
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

EXT_MAPPINGS = {
    "exe": {".exe", ".dll", ".scr", ".sys", ".cpl", ".ocx"},
    "pdf": {".pdf"},
    "png": {".png"},
    "jpg": {".jpg", ".jpeg"},
    "gif": {".gif"},
    "ole": {".doc", ".xls", ".ppt", ".msi", ".msg", ".dot", ".xlt", ".pps"},
    "zip": {
        ".zip", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".jar",
        ".odt", ".ods", ".apk", ".xlsb", ".epub"
    },
    "rar": {".rar"},
    "7z": {".7z"},
}

MAX_ARCHIVE_UNPACKED_BYTES = 100 * 1024 * 1024
MAX_ARCHIVE_FILES = 2000
MAX_OBJSTM_BYTES = 20 * 1024 * 1024


class AttachmentsChecker:
    def __init__(self):
        self.quishing_checker = QuishingChecker()

    def check_file(self, filename: str, data: bytes) -> List[Finding]:
        findings: List[Finding] = []
        ext = Path(filename).suffix.lower()

        # 1. Анализ имени файла (RTLO, двойное расширение)
        findings.extend(self._check_filename(filename))

        # 2. Анализ соответствия сигнатуры (magic bytes)
        findings.extend(self._check_magic(filename, data))

        # 3. Анализ опасного расширения
        if ext in SUSPICIOUS_EXTENSIONS and ext not in (".html", ".htm", ".svg", ".url"):
            findings.append(Finding(
                id="ATT_SUSPICIOUS_EXTENSION",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=50,
                title=f"Опасный исполняемый или скриптовый тип вложения: {ext}",
                evidence=f"Файл: {filename}",
                confidence=0.95
            ))

        # 4. Проверка ярлыков Windows (.lnk) и Shell Link структуры
        if ext == ".lnk" or (len(data) >= 76 and data[:4] == b"\x4c\x00\x00\x00"):
            findings.extend(self._check_lnk(filename, data))

        # 5. Проверка HTML smuggling
        if ext in (".html", ".htm", ".svg"):
            findings.extend(self._check_html_smuggling(filename, data))

        # 6. Проверка PDF структуры
        if ext == ".pdf":
            findings.extend(self._check_pdf(filename, data))

        # 7. Проверка Office документов (OOXML/OLE)
        if ext in (".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".docm", ".xlsm", ".rtf"):
            findings.extend(self._check_office(filename, data))

        # 8. Проверка архивов (ZIP, RAR, 7Z, TAR, GZ, ISO)
        if ext in (".zip", ".rar", ".7z", ".tar", ".gz", ".tgz", ".iso", ".img") or any(data.startswith(s) for s in (b"PK\x03\x04", b"Rar!", b"7z\xbc\xaf", b"\x1f\x8b")):
            findings.extend(self._check_archive(filename, data))

        # 9. Проверка изображений на оверлеи и Quishing (QR-коды)
        if ext in (".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp"):
            findings.extend(self._check_image_payload(filename, data))
            q_findings, _ = self.quishing_checker.scan_image(filename, data)
            findings.extend(q_findings)

        # 10. Проверка скриптов и текстовых файлов на Remcos/Matryoshka техники (Reversed PE, WMI env, MSBuild)
        if ext in (".js", ".jse", ".vbs", ".wsf", ".ps1", ".bat", ".cmd", ".txt", ".log", ".dat"):
            findings.extend(self._check_staged_script_or_text(filename, data))

        return findings


    def _check_filename(self, filename: str) -> List[Finding]:
        findings = []
        # RTLO / Bidi
        if any(ch in filename for ch in ("\u202e", "\u202d", "\u2066", "\u2067", "\u2068")):
            findings.append(Finding(
                id="ATT_NAME_RTLO",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=80,
                title="Использование управляющих символов RTLO (маскировка расширения файла)",
                evidence=f"Имя файла содержит скрытые Unicode символы: {filename}",
                confidence=0.99
            ))

        # Двойное расширение (например invoice.pdf.exe)
        suffixes = [s.lower() for s in Path(filename).suffixes]
        if len(suffixes) >= 2:
            last, prev = suffixes[-1], suffixes[-2]
            if last in SUSPICIOUS_EXTENSIONS and prev in DECOY_EXTENSIONS:
                findings.append(Finding(
                    id="ATT_DOUBLE_EXTENSION",
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    weight=75,
                    title=f"Двойное расширение файла для обмана пользователя ({prev}{last})",
                    evidence=f"Имя файла: {filename}",
                    confidence=0.98
                ))
        return findings

    def _check_magic(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        detected = next((kind for sig, kind in MAGIC_SIGNATURES if data.startswith(sig)), "")
        ext = Path(filename).suffix.lower()
        declared = next((kind for kind, exts in EXT_MAPPINGS.items() if ext in exts), "")

        if detected == "exe" and declared != "exe":
            findings.append(Finding(
                id="ATT_MAGIC_EXECUTABLE_MISMATCH",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=85,
                title=f"Исполняемый PE-файл (Windows MZ) замаскирован под расширение «{ext}»",
                evidence=f"Сигнатура: MZ, Заявленное расширение: {ext}",
                confidence=0.99
            ))
        elif detected and declared and detected != declared:
            # Доброкачественные подмены картинок (jpeg под png) помечаем как INFO
            is_benign_img = {detected, declared} <= {"png", "jpg", "gif"}
            findings.append(Finding(
                id="ATT_MAGIC_MISMATCH",
                category=Category.ATTACHMENT,
                severity=Severity.INFO if is_benign_img else Severity.MEDIUM,
                weight=5 if is_benign_img else 25,
                title=f"Сигнатура файла ({detected}) не соответствует заявленному расширению ({ext})",
                evidence=f"Файл: {filename}",
                confidence=0.9
            ))
        return findings

    def _check_html_smuggling(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        text = data.decode("utf-8", errors="ignore").lower()
        decoders = [t for t in ("atob(", "fromcharcode", "unescape(") if t in text]
        builders = [t for t in ("new blob", "createobjecturl", "mssaveblob", "mssaveoropenblob", ".download") if t in text]

        if decoders and builders:
            findings.append(Finding(
                id="ATT_HTML_SMUGGLING",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=80,
                title="Обнаружены признаки техники HTML Smuggling (скрытая сборка и скачивание payload)",
                evidence=f"Декодеры: {decoders}, Сборка/Blob: {builders}",
                confidence=0.95
            ))
        return findings

    def _check_pdf(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        if not data.startswith(b"%PDF"):
            return findings

        # Вырезаем бинарные потоки изображений перед текстовым анализом (защита от ложных детектов)
        stripped = re.sub(rb"(stream\r?\n).*?(\r?\n?endstream)", rb"\1\2", data, flags=re.S)
        corpus = self._normalize_pdf_names(stripped.decode("latin1", errors="ignore"))

        # Разжимаем потоки /ObjStm
        objstm_count = 0
        for sm in re.finditer(rb"stream\r?\n(.*?)\r?\n?endstream", data, re.S):
            head = data[max(0, sm.start() - 600):sm.start()].decode("latin1", errors="ignore")
            head = self._normalize_pdf_names(head)
            if "/ObjStm" in head and "/FlateDecode" in head:
                try:
                    inflated = zlib.decompressobj().decompress(sm.group(1), MAX_OBJSTM_BYTES)
                    objstm_count += 1
                    corpus += "\n" + self._normalize_pdf_names(inflated.decode("latin1", errors="ignore"))
                except Exception:
                    pass

        # Поиск ключевых слов PDF
        if re.search(r"/(?:JavaScript|JS)(?=[\s()<>/%\[\]{}]|$)", corpus):
            findings.append(Finding(
                id="ATT_PDF_JAVASCRIPT",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=75,
                title="В документе PDF обнаружен встроенный исполняемый скрипт (/JavaScript или /JS)",
                evidence=f"Файл: {filename}",
                confidence=0.98
            ))

        if re.search(r"/Launch(?=[\s()<>/%\[\]{}]|$)", corpus):
            findings.append(Finding(
                id="ATT_PDF_LAUNCH_ACTION",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=80,
                title="В документе PDF обнаружено действие запуска внешних процессов (/Launch)",
                evidence=f"Файл: {filename}",
                confidence=0.98
            ))

        if re.search(r"/OpenAction(?=[\s()<>/%\[\]{}]|$)", corpus):
            findings.append(Finding(
                id="ATT_PDF_OPEN_ACTION",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=40,
                title="В документе PDF настроено автоматическое действие при открытии (/OpenAction)",
                evidence=f"Файл: {filename}",
                confidence=0.9
            ))

        if re.search(r"/EmbeddedFiles?(?=[\s()<>/%\[\]{}]|$)", corpus):
            findings.append(Finding(
                id="ATT_PDF_EMBEDDED_FILE",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=50,
                title="В документ PDF встроен внешний файл (/EmbeddedFile)",
                evidence=f"Файл: {filename}",
                confidence=0.95
            ))

        return findings

    def _check_office(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        # Если OOXML (docx, xlsx, docm...)
        if zipfile.is_zipfile(io.BytesIO(data)):
            try:
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    namelist = zf.namelist()
                    # 1. Макросы
                    if any("vbaproject.bin" in name.lower() for name in namelist):
                        findings.append(Finding(
                            id="ATT_OFFICE_VBA_MACRO",
                            category=Category.ATTACHMENT,
                            severity=Severity.HIGH,
                            weight=50,
                            title="В документе Office обнаружен проект VBA-макросов (vbaProject.bin)",
                            evidence=f"Файл: {filename}",
                            confidence=0.98
                        ))

                    # 2. Внешние связи (Template Injection)
                    for name in namelist:
                        if name.endswith(".rels"):
                            rels_xml = zf.read(name).decode("utf-8", errors="ignore")
                            if 'TargetMode="External"' in rels_xml:
                                if "attachedTemplate" in rels_xml or "http://" in rels_xml or "https://" in rels_xml:
                                    findings.append(Finding(
                                        id="ATT_OFFICE_TEMPLATE_INJECTION",
                                        category=Category.ATTACHMENT,
                                        severity=Severity.CRITICAL,
                                        weight=80,
                                        title="Обнаружена техника Remote Template Injection (загрузка удаленного шаблона Word)",
                                        evidence=f"В файле связей {name}",
                                        confidence=0.95
                                    ))
                                if "oleObject" in rels_xml:
                                    findings.append(Finding(
                                        id="ATT_OFFICE_EXTERNAL_OLE",
                                        category=Category.ATTACHMENT,
                                        severity=Severity.CRITICAL,
                                        weight=80,
                                        title="Обнаружен внешний OLE-объект с загрузкой по сети",
                                        evidence=f"В файле {name}",
                                        confidence=0.95
                                    ))

                    # 3. Инструкции DDE и вызовы интерпретаторов
                    for name in namelist:
                        if name.endswith(".xml"):
                            xml_content = zf.read(name).decode("utf-8", errors="ignore")
                            if "ddeauto" in xml_content.lower() or "<w:instrtext" in xml_content.lower():
                                if any(t in xml_content.lower() for t in ("powershell", "cmd.exe", "mshta", "cscript")):
                                    findings.append(Finding(
                                        id="ATT_OFFICE_DDE_EXEC",
                                        category=Category.ATTACHMENT,
                                        severity=Severity.CRITICAL,
                                        weight=85,
                                        title="В документе обнаружено выполнение команд через поля DDE/инструкции Word",
                                        evidence=f"В файле {name}",
                                        confidence=0.98
                                    ))
            except Exception:
                pass
        return findings

    def _check_lnk(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        if len(data) < 76 or data[:4] != b"\x4c\x00\x00\x00":
            return findings

        data_lower = data.lower()
        evidence_reasons = []

        # Поиск вызовов системных утилит и LoLBins в теле LNK
        lolbins = [
            b"powershell", b"pwsh", b"cmd.exe", b"mshta", b"certutil", b"bitsadmin",
            b"cscript", b"wscript", b"regsvr32", b"rundll32", b"curl.exe", b"wget.exe"
        ]
        matched_lolbins = [lb.decode() for lb in lolbins if lb in data_lower]
        if matched_lolbins:
            evidence_reasons.append(f"вызов системных утилит: {', '.join(matched_lolbins)}")

        # Поиск подозрительных параметров и команд запуска
        suspicious_args = [
            b"-enc", b"-encodedcommand", b"-w hidden", b"-windowstyle hidden",
            b"downloadstring", b"invoke-webrequest", b"iex", b"http://", b"https://",
            b"frombase64string", b"/e:vbscript", b"/e:jscript"
        ]
        matched_args = [arg.decode() for arg in suspicious_args if arg in data_lower]
        if matched_args:
            evidence_reasons.append(f"команды/аргументы: {', '.join(matched_args[:4])}")

        if evidence_reasons:
            findings.append(Finding(
                id="ATT_LNK_MALICIOUS_COMMAND",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=90,
                title="В ярлыке Windows (.lnk) обнаружена скрытая команда запуска системных утилит (LoLBins)",
                evidence=f"Ярлык '{filename}': {'; '.join(evidence_reasons)}",
                confidence=0.99
            ))
        else:
            findings.append(Finding(
                id="ATT_LNK_GENERIC_SHORTCUT",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=50,
                title="Вложение является исполняемым ярлыком Windows (.lnk)",
                evidence=f"Файл: '{filename}'",
                confidence=0.95
            ))

        return findings

    def _check_archive(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        ext = Path(filename).suffix.lower()

        # 1. ZIP Архивы
        if ext == ".zip" or data.startswith(b"PK\x03\x04"):
            findings.extend(self._check_zip_archive(filename, data))

        # 2. TAR / GZ Архивы
        elif ext in (".tar", ".gz", ".tgz") or data.startswith(b"\x1f\x8b"):
            findings.extend(self._check_tar_archive(filename, data))

        # 3. RAR Архивы
        elif ext == ".rar" or data.startswith(b"Rar!"):
            findings.extend(self._check_rar_archive(filename, data))

        # 4. 7Z Архивы
        elif ext == ".7z" or data.startswith(b"7z\xbc\xaf\x27\x1c"):
            findings.append(Finding(
                id="ATT_ARCHIVE_7Z_DETECTED",
                category=Category.ATTACHMENT,
                severity=Severity.MEDIUM,
                weight=25,
                title="Вложение является архивом 7-Zip (.7z)",
                evidence=f"Файл: '{filename}' (сигнатура 7z)",
                confidence=0.95
            ))

        return findings

    def _check_zip_archive(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        try:
            with zipfile.ZipFile(io.BytesIO(data)) as zf:
                infos = zf.infolist()
                total_unpacked = sum(i.file_size for i in infos)
                if total_unpacked > MAX_ARCHIVE_UNPACKED_BYTES or len(infos) > MAX_ARCHIVE_FILES:
                    findings.append(Finding(
                        id="ATT_ARCHIVE_ZIP_BOMB",
                        category=Category.ATTACHMENT,
                        severity=Severity.HIGH,
                        weight=50,
                        title="Архив превышает лимит распаковки (признак Zip-Bomb)",
                        evidence=f"Размер в распакованном виде: {total_unpacked} байт, файлов: {len(infos)}",
                        confidence=0.9
                    ))

                # Проверка вложенных файлов на опасные расширения и Zip Slip (Path Traversal)
                for info in infos:
                    if ".." in info.filename or info.filename.startswith(("/", "\\")):
                        findings.append(Finding(
                            id="ATT_ARCHIVE_ZIP_SLIP",
                            category=Category.ATTACHMENT,
                            severity=Severity.CRITICAL,
                            weight=85,
                            title="В архиве обнаружен файл с относительным путем обхода каталогов (Zip Slip / Path Traversal)",
                            evidence=f"Файл в архиве: {info.filename}",
                            confidence=0.99
                        ))
                    sub_ext = Path(info.filename).suffix.lower()
                    if sub_ext in SUSPICIOUS_EXTENSIONS:
                        findings.append(Finding(
                            id="ATT_ARCHIVE_HIDDEN_PAYLOAD",
                            category=Category.ATTACHMENT,
                            severity=Severity.HIGH,
                            weight=60,
                            title=f"Внутри архива содержится исполняемый/скриптовый файл ({sub_ext})",
                            evidence=f"Файл в архиве: {info.filename}",
                            confidence=0.98
                        ))
        except Exception:
            pass
        return findings

    def _check_tar_archive(self, filename: str, data: bytes) -> List[Finding]:
        findings = []
        try:
            with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                members = tf.getmembers()
                total_unpacked = sum(m.size for m in members)
                if total_unpacked > MAX_ARCHIVE_UNPACKED_BYTES or len(members) > MAX_ARCHIVE_FILES:
                    findings.append(Finding(
                        id="ATT_ARCHIVE_TAR_BOMB",
                        category=Category.ATTACHMENT,
                        severity=Severity.HIGH,
                        weight=50,
                        title="TAR архив превышает лимиты распаковки (признак Tar-Bomb)",
                        evidence=f"Размер: {total_unpacked} байт, файлов: {len(members)}",
                        confidence=0.9
                    ))
                for m in members:
                    if ".." in m.name or m.name.startswith(("/", "\\")):
                        findings.append(Finding(
                            id="ATT_ARCHIVE_TAR_SLIP",
                            category=Category.ATTACHMENT,
                            severity=Severity.CRITICAL,
                            weight=85,
                            title="В TAR архиве обнаружен файл с относительным путем обхода каталогов (Tar Slip)",
                            evidence=f"Файл в архиве: {m.name}",
                            confidence=0.99
                        ))
                    sub_ext = Path(m.name).suffix.lower()
                    if sub_ext in SUSPICIOUS_EXTENSIONS:
                        findings.append(Finding(
                            id="ATT_ARCHIVE_HIDDEN_PAYLOAD",
                            category=Category.ATTACHMENT,
                            severity=Severity.HIGH,
                            weight=60,
                            title=f"Внутри TAR архива содержится исполняемый/скриптовый файл ({sub_ext})",
                            evidence=f"Файл в архиве: {m.name}",
                            confidence=0.98
                        ))
        except Exception:
            pass
        return findings

    def _check_rar_archive(self, filename: str, data: bytes) -> List[Finding]:
        # shortcut: byte-matching for RAR without unrar dependency, upgrade to header unpacker if FP rate > 1%
        findings = []
        data_low = data.lower()
        susp_in_rar = [ext.encode() for ext in SUSPICIOUS_EXTENSIONS if ext.encode() in data_low]
        if susp_in_rar:
            found_str = [e.decode(errors="ignore") for e in susp_in_rar[:4]]
            findings.append(Finding(
                id="ATT_ARCHIVE_HIDDEN_PAYLOAD",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=65,
                title="Внутри RAR архива обнаружены признаки исполняемых или скриптовых файлов",
                evidence=f"В архиве '{filename}' найдены маркеры расширений: {', '.join(found_str)}",
                confidence=0.92
            ))
        else:
            findings.append(Finding(
                id="ATT_ARCHIVE_RAR_DETECTED",
                category=Category.ATTACHMENT,
                severity=Severity.MEDIUM,
                weight=25,
                title="Вложение является архивом WinRAR (.rar)",
                evidence=f"Файл: '{filename}'",
                confidence=0.95
            ))
        return findings


    def _check_image_payload(self, filename: str, data: bytes) -> List[Finding]:
        """Проверка графических файлов на скрытые оверлеи (JPEG/PNG append) и маркеры полезной нагрузки Remcos-style."""
        findings = []
        ext = Path(filename).suffix.lower()

        trailing_data = b""
        if ext in (".jpg", ".jpeg"):
            eoi_idx = data.rfind(b"\xff\xd9")
            if eoi_idx != -1 and (eoi_idx + 2) < len(data):
                trailing_data = data[eoi_idx + 2:]
        elif ext == ".png":
            iend_idx = data.rfind(b"IEND")
            if iend_idx != -1 and (iend_idx + 8) < len(data):
                trailing_data = data[iend_idx + 8:]

        # Анализ оверлея
        if len(trailing_data) > 32:
            # Проверка специфических маркеров контейнеров лоадера Remcos («матрёшка»)
            has_remcos_markers = b"<<STT>>" in trailing_data or b"<<D>>" in trailing_data
            has_embedded_pe = b"MZ" in trailing_data[:16] or b"This program cannot be run in DOS mode" in trailing_data
            has_archive = any(sig in trailing_data[:32] for sig in (b"PK\x03\x04", b"7z\xbc\xaf", b"Rar!"))
            has_b64_pe = b"TVqQAAMAAAAEAAAA" in trailing_data or b"TVoAAA" in trailing_data
            has_script = any(kw in trailing_data.lower() for kw in (b"powershell", b"wscript", b"cmd.exe", b"<script"))

            if has_remcos_markers or has_embedded_pe or has_b64_pe or has_archive or has_script:
                evidence_desc = []
                if has_remcos_markers:
                    evidence_desc.append("маркеры полезной нагрузки <<STT>> / <<D>>")
                if has_embedded_pe:
                    evidence_desc.append("заголовок исполняемого файла MZ/PE")
                if has_b64_pe:
                    evidence_desc.append("Base64-представление исполняемого PE-файла")
                if has_archive:
                    evidence_desc.append("структура архива в оверлее")
                if has_script:
                    evidence_desc.append("скриптовые команды в оверлее")

                findings.append(Finding(
                    id="ATT_IMAGE_OVERLAY_PAYLOAD",
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    weight=90,
                    title="В оверлее изображения обнаружена вредоносная полезная нагрузка (Remcos Matryoshka / Image Append)",
                    evidence=f"Файл '{filename}': {len(trailing_data)} байт после маркера конца изображения. Найдено: {', '.join(evidence_desc)}",
                    confidence=0.98
                ))
            else:
                findings.append(Finding(
                    id="ATT_IMAGE_SUSPICIOUS_OVERLAY",
                    category=Category.ATTACHMENT,
                    severity=Severity.HIGH,
                    weight=45,
                    title="В графическом файле обнаружен подозрительный неструктурированный хвостовой оверлей",
                    evidence=f"Файл '{filename}': {len(trailing_data)} байт за пределами формата изображения",
                    confidence=0.85
                ))

        # Поиск внедренных сигнатур во всем теле изображения
        if b"<<STT>>" in data and b"<<D>>" in data:
            if not any(f.id == "ATT_IMAGE_OVERLAY_PAYLOAD" for f in findings):
                findings.append(Finding(
                    id="ATT_IMAGE_PAYLOAD_MARKERS",
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    weight=85,
                    title="В теле изображения найдены маркеры передачи полезной нагрузки (<<STT>>...<<D>>)",
                    evidence=f"Файл: '{filename}'",
                    confidence=0.95
                ))

        return findings

    def _check_staged_script_or_text(self, filename: str, data: bytes) -> List[Finding]:
        """Проверка скриптов и текстовых файлов на многослойные техники (Reversed PE, WMI env injection, LoLBins)."""
        findings = []
        data_lower = data.lower()

        # 1. Проверка на инвертированный PE-файл («задом наперёд»)
        # 'This program cannot be run in DOS mode' -> 'edoc SOD ni nur eb tonnac margorp sihT'
        if b"edoc sod ni nur eb tonnac margorp siht" in data_lower or b"edoc mod ni nur eb tonnac margorp siht" in data_lower:
            findings.append(Finding(
                id="ATT_REVERSED_PE_PAYLOAD",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=95,
                title="Обнаружен инвертированный исполняемый файл (Reversed PE, «задом наперёд» для обхода AV)",
                evidence=f"Файл '{filename}' содержит инвертированный заголовок DOS stub",
                confidence=0.99
            ))
        else:
            # Проверка разворота байтов (последние 2 байта становятся первыми MZ)
            stripped_data = data.strip()
            if stripped_data.endswith(b"ZM") or stripped_data.endswith(b"5A4D") or stripped_data.endswith(b"5a4d"):
                reversed_head = stripped_data[::-1][:64]
                if reversed_head.startswith(b"MZ") or reversed_head.startswith(b"4D5A") or reversed_head.startswith(b"4d5a"):
                    findings.append(Finding(
                        id="ATT_REVERSED_PE_PAYLOAD",
                        category=Category.ATTACHMENT,
                        severity=Severity.CRITICAL,
                        weight=95,
                        title="Обнаружена инвертированная сигнатура исполняемого файла (Reversed MZ Header)",
                        evidence=f"Файл '{filename}' содержит байты PE-файла в обратном порядке",
                        confidence=0.92
                    ))

        # 2. Проверка JS/VBS/WSH на скрытую передачу через переменные окружения и WMI
        has_env_store = b"environment(\"user\")" in data_lower or b"environment('user')" in data_lower or b"hkcu\\environment" in data_lower
        has_wmi_spawn = b"winmgmts:" in data_lower and (b"win32_process" in data_lower or b"win32process" in data_lower)
        if has_env_store and has_wmi_spawn:
            findings.append(Finding(
                id="ATT_STAGED_WMI_ENV_INJECTION",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=90,
                title="Обнаружена техника скрытой передачи payload через переменные окружения с запуском через WMI",
                evidence=f"Файл '{filename}' использует WScript.Shell.Environment и Win32_Process.Create для отвязки от родительского процесса",
                confidence=0.98
            ))

        # 3. Проверка на обфусцированный вызов PowerShell iex и компиляцию Add-Type для обхода Assembly.Load
        has_obf_iex = bool(re.search(rb"\[char\[\]\]\s*\(\s*105\s*,\s*101\s*,\s*120\s*\)\s*-\s*join", data_lower))
        has_inline_load = b"add-type" in data_lower and (b"appdomain" in data_lower or b"loadassembly" in data_lower)
        if has_obf_iex or has_inline_load:
            evidence_details = []
            if has_obf_iex:
                evidence_details.append("обфускация [char[]](105,101,120)-join'' (iex)")
            if has_inline_load:
                evidence_details.append("динамическая компиляция Add-Type + AppDomain.Load")
            findings.append(Finding(
                id="ATT_POWERSHELL_INLINE_INJECTION",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=75,
                title="Обнаружены техники обхода антивирусных логов PowerShell (Dynamic Assembly Load / IEX Obfuscation)",
                evidence=f"Файл '{filename}': {', '.join(evidence_details)}",
                confidence=0.95
            ))

        # 4. Проверка на целевую инъекцию в системные процессы LoLBins (.NET tools) и артефакты Remcos
        lolbins = [p for p in (b"msbuild", b"regasm", b"vbc", b"installutil", b"cvtres") if p in data_lower]
        remcos_markers = [m for m in (b"myprogram.homees", b"runss", b"remcos", b"breaking-security") if m in data_lower]
        if lolbins and remcos_markers:
            findings.append(Finding(
                id="ATT_REMCOS_MATRYOSHKA_CHAIN",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=95,
                title="Обнаружены прямые маркеры вредоносной цепочки Remcos RAT (LoLBins injection: MSBuild/RegAsm)",
                evidence=f"Файл '{filename}'. Процессы-контейнеры: {[p.decode() for p in lolbins]}, маркеры: {[m.decode() for m in remcos_markers]}",
                confidence=0.99
            ))

        return findings

    def check_attachments_cluster(self, attachments: List[Tuple[str, bytes]]) -> List[Finding]:
        """Анализ кластера вложений на предмет распределенной полезной нагрузки (Fragmented Payload / Multi-Document Staging)."""
        findings: List[Finding] = []
        if len(attachments) < 2:
            return findings

        filenames = [fn for fn, _ in attachments]
        filenames_stems = [Path(fn).stem.lower() for fn in filenames if len(Path(fn).stem) > 3]

        # 1. Поиск взаимных перекрестных ссылок (один документ ссылается на другой)
        for fn, data in attachments:
            data_lower = data.lower()
            for other_stem in filenames_stems:
                if other_stem != Path(fn).stem.lower() and other_stem.encode("utf-8") in data_lower:
                    findings.append(Finding(
                        id="ATT_CROSS_FILE_REFERENCE",
                        category=Category.ATTACHMENT,
                        severity=Severity.HIGH,
                        weight=55,
                        title="Обнаружена перекрестная ссылка на соседнее вложение (признак сборщика/Stager)",
                        evidence=f"В файле '{fn}' найдено упоминание имени другого вложения: '{other_stem}'",
                        confidence=0.9
                    ))

        # 2. Поиск команд конкатенации/сборки в текстах и скриптах документов
        concat_patterns = (
            rb"copy\s+/b\s+", rb"cat\s+.*?>", rb"certutil\s+-decode",
            rb"\[system\.io\.file\]::writeallbytes", rb"scripting\.filesystemobject",
            rb"adodb\.stream"
        )
        for fn, data in attachments:
            data_lower = data.lower()
            for pat in concat_patterns:
                if re.search(pat, data_lower):
                    findings.append(Finding(
                        id="ATT_ASSEMBLY_COMMANDS",
                        category=Category.ATTACHMENT,
                        severity=Severity.CRITICAL,
                        weight=80,
                        title="Обнаружены системные команды сборщика файлов / потокового вывода",
                        evidence=f"В файле '{fn}' обнаружен паттерн: {pat.decode(errors='ignore')}",
                        confidence=0.95
                    ))

        # 3. Проверка скрытых оверлеев (trailing data за пределами спецификации формата)
        for fn, data in attachments:
            ext = Path(fn).suffix.lower()
            if ext == ".pdf":
                eof_idx = data.rfind(b"%%EOF")
                if eof_idx != -1:
                    trailing = data[eof_idx + 5:].strip()
                    if len(trailing) > 64:
                        findings.append(Finding(
                            id="ATT_PDF_SUSPICIOUS_OVERLAY",
                            category=Category.ATTACHMENT,
                            severity=Severity.MEDIUM,
                            weight=35,
                            title="В PDF файле обнаружен неструктурированный хвостовой оверлей",
                            evidence=f"Файл '{fn}': {len(trailing)} байт после маркера %%EOF",
                            confidence=0.85
                        ))
            elif ext in (".zip", ".docx", ".xlsx", ".pptx"):
                eocd_idx = data.rfind(b"PK\x05\x06")
                if eocd_idx != -1 and len(data) >= eocd_idx + 22:
                    comment_len = int.from_bytes(data[eocd_idx + 20:eocd_idx + 22], "little")
                    expected_end = eocd_idx + 22 + comment_len
                    trailing_len = len(data) - expected_end
                    if trailing_len > 64:
                        findings.append(Finding(
                            id="ATT_ZIP_SUSPICIOUS_OVERLAY",
                            category=Category.ATTACHMENT,
                            severity=Severity.MEDIUM,
                            weight=35,
                            title="В архиве/OpenXML документе обнаружен подозрительный хвостовой оверлей",
                            evidence=f"Файл '{fn}': {trailing_len} байт после структуры ZIP",
                            confidence=0.85
                        ))
            elif ext in (".jpg", ".jpeg"):
                eoi_idx = data.rfind(b"\xff\xd9")
                if eoi_idx != -1 and (eoi_idx + 2) < len(data):
                    trailing = data[eoi_idx + 2:].strip()
                    if len(trailing) > 32:
                        findings.append(Finding(
                            id="ATT_IMAGE_SUSPICIOUS_OVERLAY",
                            category=Category.ATTACHMENT,
                            severity=Severity.HIGH,
                            weight=50,
                            title="В графическом файле кластера обнаружен подозрительный оверлей после маркера EOI",
                            evidence=f"Файл '{fn}': {len(trailing)} байт после маркера EOI (FF D9)",
                            confidence=0.9
                        ))
            elif ext == ".png":
                iend_idx = data.rfind(b"IEND")
                if iend_idx != -1 and (iend_idx + 8) < len(data):
                    trailing = data[iend_idx + 8:].strip()
                    if len(trailing) > 32:
                        findings.append(Finding(
                            id="ATT_IMAGE_SUSPICIOUS_OVERLAY",
                            category=Category.ATTACHMENT,
                            severity=Severity.HIGH,
                            weight=50,
                            title="В PNG-изображении кластера обнаружен оверлей после чанка IEND",
                            evidence=f"Файл '{fn}': {len(trailing)} байт после IEND",
                            confidence=0.9
                        ))

        # 4. Поиск внедренных исполняемых PE-сигнатур (MZ + PE\0\0) во всех не-EXE вложениях
        for fn, data in attachments:
            ext = Path(fn).suffix.lower()
            if ext not in (".exe", ".dll", ".sys"):
                if b"This program cannot be run in DOS mode" in data:
                    findings.append(Finding(
                        id="ATT_HIDDEN_PE_EXECUTABLE",
                        category=Category.ATTACHMENT,
                        severity=Severity.CRITICAL,
                        weight=90,
                        title="В неисполняемом документе обнаружена внедренная сигнатура PE/DOS",
                        evidence=f"Файл: {fn}",
                        confidence=0.99
                    ))

        # 5. Поиск инвертированных исполняемых файлов (Reversed PE, «задом наперёд»)
        for fn, data in attachments:
            data_l = data.lower()
            if b"edoc sod ni nur eb tonnac margorp siht" in data_l or b"edoc mod ni nur eb tonnac margorp siht" in data_l:
                findings.append(Finding(
                    id="ATT_REVERSED_PE_PAYLOAD",
                    category=Category.ATTACHMENT,
                    severity=Severity.CRITICAL,
                    weight=95,
                    title="В файле кластера обнаружен инвертированный исполняемый файл (Reversed PE, «задом наперёд»)",
                    evidence=f"Файл: '{fn}'",
                    confidence=0.99
                ))

        return findings

    @staticmethod
    def _normalize_pdf_names(text: str) -> str:
        def decode(match: re.Match[str]) -> str:
            return re.sub(r"#([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), match.group(0))
        return re.sub(r"/[^\s()<>/%\[\]{}]+", decode, text)

