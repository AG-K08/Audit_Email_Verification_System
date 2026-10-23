# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: test_advanced_phish.py
Назначение: Автотесты для новых эшелонов детекции фишинга (Quishing, Shorteners, IP-URLs, LNK, Tar, Received Hops).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import io
import struct
import sys
import tarfile
import zlib
from pathlib import Path
try:
    from PIL import Image, ImageDraw
except ImportError:
    Image = None
    ImageDraw = None
import pytest

CORE_ENGINES = Path(__file__).resolve().parents[1] / "01_Core_Engines"
if str(CORE_ENGINES) not in sys.path:
    sys.path.insert(0, str(CORE_ENGINES))

from phish_engine import (
    PhishingEngine, HeadersChecker, BodyChecker, AttachmentsChecker,
    QuishingChecker, Severity, Category, Finding
)


def _build_qr_finder_png_bytes() -> bytes:
    """Создает тестовое PNG 140x140 с 3 метками позиционирования QR (с Pillow или через stdlib zlib/struct)."""
    if Image is not None and ImageDraw is not None:
        img = Image.new("RGB", (140, 140), "white")
        draw = ImageDraw.Draw(img)

        def draw_finder(x, y):
            draw.rectangle([x, y, x + 14, y + 14], fill="black")
            draw.rectangle([x + 2, y + 2, x + 12, y + 12], fill="white")
            draw.rectangle([x + 4, y + 4, x + 10, y + 10], fill="black")

        draw_finder(10, 10)
        draw_finder(110, 10)
        draw_finder(10, 110)

        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()

    w, h = 140, 140
    grid = [[255] * w for _ in range(h)]

    def draw_rect(x0, y0, x1, y1, val):
        for yy in range(y0, y1 + 1):
            for xx in range(x0, x1 + 1):
                grid[yy][xx] = val

    for fx, fy in ((10, 10), (110, 10), (10, 110)):
        draw_rect(fx, fy, fx + 14, fy + 14, 0)
        draw_rect(fx + 2, fy + 2, fx + 12, fy + 12, 255)
        draw_rect(fx + 4, fy + 4, fx + 10, fy + 10, 0)

    raw_rows = b"".join(b"\x00" + bytes(row) for row in grid)

    def png_chunk(ctype: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(ctype + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + ctype + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", w, h, 8, 0, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + png_chunk(b"IHDR", ihdr)
        + png_chunk(b"IDAT", zlib.compress(raw_rows))
        + png_chunk(b"IEND", b"")
    )


def test_quishing_finder_pattern_detection():
    """Тест автономного выявления маркеров позиционирования QR-кода (Quishing)."""
    checker = QuishingChecker()
    png_data = _build_qr_finder_png_bytes()

    findings, urls = checker.scan_image("qr_login.png", png_data)
    ids = [f.id for f in findings]
    assert any(i in ids for i in ("ATT_QUISHING_DETECTED", "ATT_QUISHING_SUSPECTED"))


def test_body_url_shortener():
    """Тест выявления сокращателей ссылок (bit.ly, clck.ru)."""
    checker = BodyChecker()
    body = "Подтвердите доступ по ссылке: https://bit.ly/secure-login-392"
    findings = checker.check(body, "", "admin@company.com")
    ids = [f.id for f in findings]
    assert "BODY_URL_SHORTENER" in ids


def test_body_ip_url():
    """Тест выявления ссылок с прямыми IP-адресами вместо домена."""
    checker = BodyChecker()
    body = "Вход в панель: http://185.220.101.5/auth/index.php"
    findings = checker.check(body, "", "support@bank.ru")
    ids = [f.id for f in findings]
    assert "BODY_IP_URL" in ids


def test_body_risky_tld():
    """Тест выявления доменов верхнего уровня с высоким уровнем спама/фишинга (.top, .xyz)."""
    checker = BodyChecker()
    body = "Ваш отчет: https://corporate-portal-login.top/view"
    findings = checker.check(body, "", "info@corp.ru")
    ids = [f.id for f in findings]
    assert "BODY_RISKY_TLD" in ids


def test_body_open_redirect():
    """Тест выявления параметров открытого перенаправления (Open Redirect)."""
    checker = BodyChecker()
    html = '<a href="https://google.com/url?q=https://phishing-site.ru/steal">Нажмите здесь</a>'
    findings = checker.check("", html, "service@google.com")
    ids = [f.id for f in findings]
    assert "BODY_OPEN_REDIRECT" in ids


def test_body_expanded_social_engineering():
    """Тест расширенной базы паттернов социальной инженерии (HR, MFA, дедлайны)."""
    checker = BodyChecker()
    # 1. Жесткий дедлайн
    f1 = checker.check("Срочно примите меры в течение 24 часов иначе ящик будет удален", "", "it@corp.ru")
    assert any("дедлайн" in f.title.lower() for f in f1)

    # 2. ИТ/ИБ уведомление
    f2 = checker.check("Срочно требуется настройка MFA и обновление почтового сервера", "", "security@corp.ru")
    assert any("ит/иб" in f.title.lower() for f in f2)

    # 3. Прямой запрос пароля
    f3 = checker.check("Пришлите свой пароль для подтверждения учетной записи", "", "support@corp.ru")
    assert any(f.id == "BODY_PHISH_KEYWORDS" and f.severity == Severity.CRITICAL for f in f3)


def test_headers_received_dynamic_ip():
    """Тест трассировки Received и выявления отправки с динамических/бытовых пулов провайдера."""
    checker = HeadersChecker()
    raw_headers = (
        "From: Boss <boss@enterprise-corp.com>\n"
        "To: employee@enterprise-corp.com\n"
        "Subject: Urgent payment\n"
        "Received: from mx.enterprise-corp.com by mail.enterprise-corp.com with ESMTP; Thu, 22 Oct 2026 10:00:00 +0300\n"
        "Received: from [178.120.45.10] (helo=dsl-pool-dynamic.broadband.telecom.by) by mx.enterprise-corp.com; Thu, 22 Oct 2026 09:59:00 +0300\n"
    )
    findings = checker.check({"From": "Boss <boss@enterprise-corp.com>", "Subject": "Urgent"}, raw_headers)
    ids = [f.id for f in findings]
    assert "HDR_RECEIVED_DYNAMIC_IP" in ids


def test_lnk_shortcut_malicious_command():
    """Тест анализа ярлыка Windows (.lnk) со скрытым вызовом PowerShell."""
    checker = AttachmentsChecker()
    # Заголовок LNK: HeaderSize=0x4C (76) + CLSID
    header = b"\x4c\x00\x00\x00\x01\x14\x02\x00\x00\x00\x00\x00\xc0\x00\x00\x00\x00\x00\x00\x46"
    padding = b"\x00" * 56
    # Тело с командой запуска
    command = b"powershell.exe -w hidden -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp..."
    lnk_data = header + padding + command

    findings = checker.check_file("Document.pdf.lnk", lnk_data)
    ids = [f.id for f in findings]
    assert "ATT_LNK_MALICIOUS_COMMAND" in ids


def test_tar_archive_hidden_payload():
    """Тест безопасного анализа оглавления TAR архива с исполняемым файлом."""
    checker = AttachmentsChecker()
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tf:
        info = tarfile.TarInfo(name="invoice.pdf.exe")
        info.size = 10
        tf.addfile(info, io.BytesIO(b"MZ\x00\x00\x00\x00\x00\x00\x00\x00"))

    tar_bytes = buf.getvalue()
    findings = checker.check_file("archive.tar", tar_bytes)
    ids = [f.id for f in findings]
    assert "ATT_ARCHIVE_HIDDEN_PAYLOAD" in ids


def test_cloud_phishing_and_credential_harvesting():
    """Тест выявления фишинга на облачных ресурсах (web.core.windows.net) с перехватом email (Credential Harvesting)."""
    checker = BodyChecker()
    body_text = (
        "Абнаўленне паштовага сервера\n"
        "Паўторна актываваць электронную пошту: https://rollercost.z13.web.core.windows.net/ebul.html#mts@enterprise-corp.com\n"
    )
    findings = checker.check(body_text, "", "mts@enterprise-corp.com")
    ids = [f.id for f in findings]
    assert "BODY_CREDENTIAL_HARVEST_URL" in ids
    
    crit_finding = [f for f in findings if f.id == "BODY_CREDENTIAL_HARVEST_URL"][0]
    assert crit_finding.severity == Severity.CRITICAL
    assert crit_finding.weight >= 80


def test_belarusian_phishing_social_engineering():
    """Тест эвристик социальной инженерии на белорусском языке."""
    checker = BodyChecker()
    body = "Апошняе папярэджанне: ваш рахунак хутка будзе адключана, неўзабаве патрэбна пацвердзіць пароль"
    findings = checker.check(body, "", "admin@enterprise-corp.com")
    ids = [f.id for f in findings]
    assert "BODY_PHISH_KEYWORDS" in ids
    assert any("парол" in f.title.lower() or "блокировк" in f.title.lower() or "дедлайн" in f.title.lower() for f in findings)

