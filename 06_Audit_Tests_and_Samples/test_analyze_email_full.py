# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: test_analyze_email_full.py
Назначение: Регрессионные тесты для сквозного конвейера анализа писем.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import io
import sys
import zipfile
import zlib
from pathlib import Path

import pytest

CORE_ENGINES = Path(__file__).resolve().parents[1] / "01_Core_Engines"
SCRIPTS = Path(__file__).resolve().parents[1] / "Scripts"
for p in (CORE_ENGINES, SCRIPTS):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

import analyze_email_full as m  # noqa: E402


def make_analyzer(tmp_path: Path, sender_email: str = "user@partner-org.org") -> m.FullEmailAnalyzer:
    eml = tmp_path / "case.eml"
    eml.write_bytes(b"From: x\r\n\r\nbody")
    analyzer = m.FullEmailAnalyzer(eml)
    analyzer.extract_dir.mkdir(parents=True, exist_ok=True)
    analyzer.report["email"] = {"sender": sender_email, "sender_email": sender_email}
    return analyzer


def warnings_text(analyzer: m.FullEmailAnalyzer) -> str:
    return " | ".join(w["message"] for w in analyzer.report["warnings"])


# ---------------------------------------------------------------- D3: auth
def test_d3_folded_authentication_results(tmp_path):
    analyzer = make_analyzer(tmp_path)
    hdr = (
        "From: a@b.c\n"
        "Authentication-Results: smx1.hoster.by;\n"
        "\tspf=pass (x) smtp.mailfrom=a@b.c;\n"
        "\tdkim=pass header.i=@b.c;\n"
        "\tdmarc=pass header.from=b.c;\n"
        "Subject: x\n"
    )
    assert analyzer._extract_auth(hdr) == {"spf": "pass", "dkim": "pass", "dmarc": "pass"}


def test_d3_folded_fail_detected(tmp_path):
    analyzer = make_analyzer(tmp_path)
    hdr = "Authentication-Results: mx;\n\tspf=fail smtp.mailfrom=a@b.c;\n\tdkim=none;\n"
    auth = analyzer._extract_auth(hdr)
    assert auth["spf"] == "fail/softfail"
    assert auth["dkim"] == "fail/none"


# ---------------------------------------------------------------- D2: no auth
def test_d2_missing_auth_is_recorded_but_does_not_change_verdict(tmp_path):
    analyzer = make_analyzer(tmp_path)
    analyzer._header_text = "From: a@b.c\nSubject: x\n"
    analyzer.stage_2_headers()
    assert any(
        "SPF/DKIM/DMARC" in w["message"] and w["severity"] == "INFO"
        for w in analyzer.report["warnings"]
    )
    # ~40% чистых писем без части auth -> сигнал слабый, вердикт не меняется
    assert analyzer.report["verdict"] == "CLEAN"


# ---------------------------------------------------------------- D1: domain alignment
@pytest.mark.parametrize(
    "url",
    [
        "https://partner-org.org.evil.com/login",
        "https://evil-partner-org.org/login",
        "https://notpartner-org.org/login",
    ],
)
def test_d1_lookalike_hosts_are_misaligned(tmp_path, url):
    analyzer = make_analyzer(tmp_path, "user@partner-org.org")
    analyzer._body_text = f"Перейдите: {url}"
    analyzer.stage_3_body()
    assert analyzer.report["email"]["misaligned_urls"] == [url]


@pytest.mark.parametrize(
    "url",
    ["https://partner-org.org/x", "https://www.partner-org.org/x", "https://mail.partner-org.org/x"],
)
def test_d1_own_domain_and_subdomains_are_aligned(tmp_path, url):
    analyzer = make_analyzer(tmp_path, "user@partner-org.org")
    analyzer._body_text = f"Ссылка: {url}"
    analyzer.stage_3_body()
    assert analyzer.report["email"]["misaligned_urls"] == []


def test_d1_registrable_domain_helper():
    f = m.same_registrable_domain
    assert f("www.partner-org.org", "partner-org.org")
    assert f("a.b.com.by", "x.b.com.by")
    assert not f("partner-org.org.evil.com", "partner-org.org")
    assert not f("evil-partner-org.org", "partner-org.org")
    assert not f("a.co.uk", "b.co.uk")


# ---------------------------------------------------------------- D4/D5: PDF
def _pdf_with_objstm(inner: bytes) -> bytes:
    body = zlib.compress(b"6 0 " + inner)
    return (
        b"%PDF-1.7\n"
        b"1 0 obj\n<< /Type /Catalog >>\nendobj\n"
        b"5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length "
        + str(len(body)).encode()
        + b" >>\nstream\n"
        + body
        + b"\nendstream\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
    )


def test_d4_javascript_inside_objstm_is_found(tmp_path):
    pdf = tmp_path / "a.pdf"
    pdf.write_bytes(_pdf_with_objstm(b"<< /S /JavaScript /JS (app.alert(1)) >>"))
    analyzer = make_analyzer(tmp_path)
    info = analyzer._analyze_pdf(pdf)
    assert "PDF: обнаружен JavaScript" in analyzer._pdf_indicators(info)
    assert info.get("objstm_streams", 0) >= 1


def test_d5_obfuscated_name_is_normalised(tmp_path):
    pdf = tmp_path / "b.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /S /Launch /#4A#53 (x) /J#53 (y) >>\nendobj\n%%EOF\n"
    )
    analyzer = make_analyzer(tmp_path)
    info = analyzer._analyze_pdf(pdf)
    inds = analyzer._pdf_indicators(info)
    assert "PDF: обнаружен JavaScript" in inds
    assert "PDF: обнаружен /Launch" in inds


def test_d5_font_name_and_json_are_not_false_positives(tmp_path):
    pdf = tmp_path / "c.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /BaseFont /AAAAAA+SegoeUI /JSONData (x) /Author (y) >>\nendobj\n%%EOF\n"
    )
    analyzer = make_analyzer(tmp_path)
    info = analyzer._analyze_pdf(pdf)
    assert analyzer._pdf_indicators(info) == []


# ---------------------------------------------------------------- D6: names / types
def test_d6_rtlo_and_double_extension():
    f = m.attachment_name_findings
    assert f("invoice\u202egpj.exe")
    assert f("act.pdf.exe")
    assert not f("План УМО 26-27.docx")
    assert not f("report.final.pdf")


def test_d6_magic_vs_extension_mismatch():
    f = m.magic_extension_mismatch
    assert f("doc.pdf", b"MZ\x90\x00")
    assert f("img.png", b"%PDF-1.7")
    assert not f("a.pdf", b"%PDF-1.4")
    assert not f("a.docx", b"PK\x03\x04rest")


def test_d6_html_smuggling_detected():
    smug = b"<html><script>var b=atob('TVqQ');var u=new Blob([b]);a.download='x.exe'</script></html>"
    assert m.html_smuggling_findings(smug)
    assert not m.html_smuggling_findings(b"<html><body><p>Hello</p></body></html>")


def test_d6_new_extensions_flagged():
    for ext in (".html", ".htm", ".svg", ".one", ".chm", ".xll", ".wsh"):
        assert ext in m.RISKY_CONTAINER_EXT


# ---------------------------------------------------------------- D10: archive limits
def test_d10_zip_bomb_is_refused(tmp_path):
    z = tmp_path / "bomb.zip"
    with zipfile.ZipFile(z, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("a.bin", b"\x00" * (m.MAX_ARCHIVE_UNPACKED_BYTES + 1))
    analyzer = make_analyzer(tmp_path)
    out = analyzer._extract_archive(z, "bomb.zip")
    assert out == []
    assert "bomb" in warnings_text(analyzer).lower() or "лимит" in warnings_text(analyzer).lower()


# ---------------------------------------------------------------- D13: OOXML strings
def test_d13_strings_found_inside_compressed_ooxml():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("word/document.xml", "<w:t>cmd /c powershell -enc AAAA</w:t>" * 5)
    found = m.office_suspicious_tokens(buf.getvalue())
    assert "powershell" in [t.lower() for t in found]
    assert m.office_suspicious_tokens(b"hello") == []


# ---------------------------------------------------------------- регрессия по реальному ложному срабатыванию
def test_pdf_binary_stream_with_random_js_bytes_is_not_flagged(tmp_path):
    """Реальный случай: /JS в случайных байтах изображения сканированного PDF давал MALICIOUS."""
    body = b"\x00\x01garbage /JS \x02 more /JS\n/JavaScript \x03"
    pdf = tmp_path / "scan.pdf"
    pdf.write_bytes(
        b"%PDF-1.4\n1 0 obj\n<< /Type /XObject /Subtype /Image /Filter /DCTDecode /Length "
        + str(len(body)).encode()
        + b" >>\nstream\n"
        + body
        + b"\nendstream\nendobj\n%%EOF\n"
    )
    analyzer = make_analyzer(tmp_path)
    info = analyzer._analyze_pdf(pdf)
    assert analyzer._pdf_indicators(info) == []


def test_magic_image_mismatch_is_benign_but_exe_is_not():
    assert m.magic_mismatch_is_benign_image("a.png", b"\xff\xd8\xff\xe0")
    assert not m.magic_mismatch_is_benign_image("a.png", b"MZ\x90\x00")
    assert not m.magic_mismatch_is_benign_image("a.pdf", b"\x89PNG")
