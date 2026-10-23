# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: checks_body.py
Назначение: Модуль семантического анализа тела письма и гиперссылок.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from urllib.parse import urlparse, unquote, parse_qs
from typing import List, Dict, Any, Tuple

from .scoring import Finding, Category, Severity
from .checks_headers import get_registrable_domain, PUBLIC_MAIL_DOMAINS

URL_REGEX = re.compile(r"https?://[^\s<>\"')\]]+", re.I)
IP_HOST_RE = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")

TECHNICAL_DOMAINS = {
    "schemas.microsoft.com", "openxmlformats.org", "w3.org", "purl.org",
    "xmlsoap.org", "schema.org", "schemas.openxmlformats.org",
    "telemost.yandex.ru", "zoom.us", "teams.microsoft.com", "meet.google.com"
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "clck.ru", "t.co", "is.gd", "cutt.ly", "rb.gy",
    "ow.ly", "rebrandly.com", "shorturl.at", "soo.gd", "s.id", "tiny.cc",
    "goo.gl", "lnkd.in", "surli.cc", "vk.cc"
}

RISKY_TLDS = {
    ".top", ".xyz", ".buzz", ".click", ".club", ".tk", ".ml", ".ga",
    ".cf", ".gq", ".work", ".icu", ".sbs", ".cfd", ".fit", ".rest",
    ".monster", ".quest", ".hair", ".beauty", ".skin"
}

OPEN_REDIRECT_PARAMS = {
    "url", "redirect", "redirect_uri", "goto", "dest", "destination",
    "target", "link", "r", "u", "return", "next", "to", "q", "redir", "out", "ref", "site", "src"
}

CLOUD_PHISHING_HOSTS = {
    "web.core.windows.net", "blob.core.windows.net", "azureedge.net",
    "firebaseapp.com", "web.app", "workers.dev", "pages.dev",
    "glitch.me", "ipfs.io", "fleek.co", "ngrok.io", "loca.lt",
    "github.io", "gitlab.io", "supabase.co", "appspot.com",
    "s3.amazonaws.com", "storage.googleapis.com", "surge.sh",
    "render.com", "vercel.app", "netlify.app", "pantheonsite.io"
}

PHISH_PATTERNS = [
    (r"(срочн.*парол|обновите?\s+пароль|update\s+your\s+password|change\s+password|пацвердзіць\s+пароль)", "Требование срочной смены пароля", 35, Severity.HIGH),
    (r"(подтвердите\s+уч[её]тн|verify\s+your\s+account|подтвердите\s+доступ)", "Запрос подтверждения учетной записи", 30, Severity.MEDIUM),
    (r"(приостановлен.*почт|отключени.*почт|заблокирован|mailbox\s+full|ящик\s+переполнен|дэактываван|будзе\s+адключан|папярэджанн.*адключан)", "Угроза блокировки ящика или сервиса", 35, Severity.HIGH),
    (r"(акт\s+сверки|сч[её]т\s+на\s+оплату|задолженност|постановление|судебн.*пристав)", "Манипуляция финансовой или правовой тематикой", 15, Severity.LOW),
    (r"(парол[ья]?\s*[:：]\s*\S+|password\s*[:：]\s*\S+)", "В теле письма указан пароль (признак зашифрованного payload)", 25, Severity.MEDIUM),
    # Новые расширенные паттерны социальной инженерии
    (r"(в\s+течени[еи]\s+24\s+час|до\s+конца\s+дня|немедленно|срочно\s+примите|будет\s+заблокирован\s+навсегда|within\s+24\s+hours|immediate\s+action|апошняе\s+папярэджанне|неўзабаве)", "Манипуляция жестким дедлайном и искусственной срочностью", 25, Severity.HIGH),
    (r"(подтвердите\s+перевод|подозрительн.*транзакц|карта\s+заблокирован|разблокировк.*сч[её]т|оплата\s+штрафа|возврат\s+налог|компенсаци|выплат[аы]\s+денег)", "Банковские и финансовые манипуляции", 30, Severity.HIGH),
    (r"(истека[ею]т?\s+срок\s+действия\s+сертификат|обновлени.*почтов.*сервер|абнаўленне\s+паштовага\s+сервера|настройк.*mfa|двухфакторн.*аутентифик|смена\s+vpn|vdi\s+доступ|security\s+awareness|обязательный\s+опрос)", "Поддельное уведомление корпоративных ИТ/ИБ служб", 35, Severity.HIGH),
    (r"(паўторна\s+актывава|актываваць\s+сваю\s+паштовую\s+скрыню|пацвердзіць\s+пароль)", "Белорусскоязычный фишинг: призыв повторной активации ящика и подтверждения пароля", 45, Severity.HIGH),
    (r"(график\s+отпусков|индексаци.*зарплат|преми[ия]\s+по\s+итогам|уведомлени.*об\s+увольнении|сокращени.*штат|новый\s+трудовой\s+договор)", "Целевая атака через кадровую и HR-тематику", 20, Severity.MEDIUM),
    (r"(пришлите\s+(свой\s+)?пароль|отправьте\s+логин\s+и\s+пароль|send\s+your\s+credentials|send\s+password)", "Прямой запрос учетных данных пользователя", 50, Severity.CRITICAL),
]



class AdvancedHTMLParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links: List[Tuple[str, str]] = []  # (href, text)
        self.images: List[Dict[str, str]] = []
        self.forms: List[Dict[str, str]] = []
        self.hidden_text_blocks: List[str] = []
        self.suspicious_schemes: List[str] = []
        
        self._current_tag: str | None = None
        self._current_href: str | None = None
        self._current_link_text: List[str] = []
        self._in_hidden_block: bool = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        self._current_tag = tag
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        style = attr_dict.get("style", "").lower().replace(" ", "")

        # Проверка скрытых элементов (исключая служебные теги style, script, head, meta)
        if tag not in ("style", "script", "head", "meta", "title"):
            if "display:none" in style or "visibility:hidden" in style or "font-size:0" in style:
                self._in_hidden_block = True

        if tag == "a":
            href = attr_dict.get("href", "").strip()
            self._current_href = href
            self._current_link_text = []
            
            # Опасные схемы
            low_href = href.lower()
            if low_href.startswith(("javascript:", "vbscript:", "data:text/html")):
                self.suspicious_schemes.append(href)

        elif tag == "img":
            src = attr_dict.get("src", "").strip()
            width = attr_dict.get("width", "")
            height = attr_dict.get("height", "")
            self.images.append({
                "src": src,
                "width": width,
                "height": height,
                "is_pixel": (width in ("0", "1") and height in ("0", "1")) or ("display:none" in style)
            })

        elif tag == "form":
            self.forms.append({
                "action": attr_dict.get("action", ""),
                "method": attr_dict.get("method", "get")
            })

    def handle_endtag(self, tag: str):
        if tag == "a" and self._current_href is not None:
            visible_text = "".join(self._current_link_text).strip()
            self.links.append((self._current_href, visible_text))
            self._current_href = None
            self._current_link_text = []

        if tag in ("div", "span", "p", "td", "font", "section", "article") and self._in_hidden_block:
            self._in_hidden_block = False

    def handle_data(self, data: str):
        if self._current_tag in ("style", "script", "head", "title"):
            return
        if self._current_href is not None:
            self._current_link_text.append(data)
        if self._in_hidden_block and data.strip():
            self.hidden_text_blocks.append(data.strip())



class BodyChecker:
    def __init__(self):
        pass

    def check(self, body_text: str, body_html: str, sender_email: str) -> List[Finding]:
        findings: List[Finding] = []
        clean_sender = sender_email
        if "<" in clean_sender and ">" in clean_sender:
            m = re.search(r"<([^>]+)>", clean_sender)
            if m:
                clean_sender = m.group(1)
        sender_domain = clean_sender.split("@")[-1].lower().strip(">. ") if "@" in clean_sender else ""
        reg_sender_domain = get_registrable_domain(sender_domain) if sender_domain else ""

        full_content = f"{body_text}\n{body_html}"

        # 1. Анализ социальной инженерии по паттернам
        for pattern, desc, weight, sev in PHISH_PATTERNS:
            matches = re.findall(pattern, full_content, re.IGNORECASE)
            if matches:
                findings.append(Finding(
                    id="BODY_PHISH_KEYWORDS",
                    category=Category.BODY,
                    severity=sev,
                    weight=weight,
                    title=f"Признак социальной инженерии: {desc}",
                    evidence=f"Найдено: '{matches[0]}'",
                    confidence=0.85
                ))

        # 2. HTML-анализ (если есть HTML)
        if body_html:
            parser = AdvancedHTMLParser()
            try:
                parser.feed(body_html)
            except Exception:
                pass

            # Опасные URI-схемы
            for scheme in parser.suspicious_schemes:
                findings.append(Finding(
                    id="BODY_DANGEROUS_URI",
                    category=Category.BODY,
                    severity=Severity.CRITICAL,
                    weight=80,
                    title="В теле письма обнаружена опасная интерактивная URI-схема (JavaScript/Data)",
                    evidence=f"Ссылка: {scheme[:120]}",
                    confidence=0.99
                ))

            # Скрытые блоки текста (обход спам-фильтров)
            if parser.hidden_text_blocks:
                findings.append(Finding(
                    id="BODY_HIDDEN_TEXT",
                    category=Category.BODY,
                    severity=Severity.HIGH,
                    weight=30,
                    title="Обнаружен скрытый текст (display:none/visibility:hidden)",
                    evidence=f"Фрагмент: '{parser.hidden_text_blocks[0][:100]}'",
                    confidence=0.9
                ))

            # Трекинг-пиксели (Web Beacons)
            tracking_beacons = [img["src"] for img in parser.images if img["is_pixel"] and img["src"].startswith("http")]
            if tracking_beacons:
                findings.append(Finding(
                    id="BODY_TRACKING_BEACON",
                    category=Category.BODY,
                    severity=Severity.LOW,
                    weight=10,
                    title="Обнаружен скрытый веб-маяк (отслеживание открытия письма / Canary Token)",
                    evidence=f"URL маяка: {tracking_beacons[0][:120]}",
                    confidence=0.85
                ))

            # Интерактивные формы ввода данных
            if parser.forms:
                findings.append(Finding(
                    id="BODY_EMBEDDED_FORM",
                    category=Category.BODY,
                    severity=Severity.HIGH,
                    weight=45,
                    title="В тело письма встроена интерактивная HTML-форма для отправки данных",
                    evidence=f"Action: {parser.forms[0].get('action', '')}",
                    confidence=0.95
                ))

            # Расхождение видимого текста ссылки и реального href (Mismatched Anchor)
            for href, visible in parser.links:
                if not href.startswith("http"):
                    continue
                # Если в видимом тексте содержится адрес URL
                vis_match = re.search(r"https?://([^\s/]+)", visible, re.I)
                if vis_match:
                    vis_host = vis_match.group(1).lower()
                    href_host = urlparse(href).hostname or ""
                    href_host = href_host.lower()
                    
                    reg_vis = get_registrable_domain(vis_host)
                    reg_href = get_registrable_domain(href_host)

                    if reg_vis and reg_href and reg_vis != reg_href:
                        findings.append(Finding(
                            id="BODY_MISMATCHED_LINK",
                            category=Category.BODY,
                            severity=Severity.CRITICAL,
                            weight=75,
                            title="Критическое несоответствие ссылки: видимый URL отличается от целевого адреса",
                            evidence=f"Текст показывает: «{vis_host}», но переход ведёт на «{href_host}» ({href[:90]})",
                            confidence=0.98
                        ))

        # 3. Анализ всех URL на привязку к домену отправителя, сокращатели, IP и опасные TLD
        extracted_urls = list(set(URL_REGEX.findall(full_content)))
        misaligned_urls = []
        shortener_urls = []
        ip_urls = []
        risky_tld_urls = []
        open_redirect_urls = []
        cred_harvest_urls = []
        cloud_phish_urls = []

        for url in extracted_urls:
            url_clean = url.rstrip(".,;:!?)]")
            parsed = urlparse(url_clean)
            host = parsed.hostname or ""
            host = host.lower()
            if not host:
                continue

            # Проверка IP адреса в URL
            if IP_HOST_RE.match(host):
                ip_urls.append(url_clean)

            # Проверка сокращателей ссылок
            if host in URL_SHORTENERS or any(host.endswith("." + s) for s in URL_SHORTENERS):
                shortener_urls.append(url_clean)

            # Проверка опасных / абузоустойчивых TLD
            if any(host.endswith(tld) for tld in RISKY_TLDS):
                risky_tld_urls.append(url_clean)

            # Проверка Open Redirects
            if parsed.query:
                qs = parse_qs(parsed.query)
                for param, vals in qs.items():
                    for val in vals:
                        if val.lower().startswith(("http://", "https://")):
                            open_redirect_urls.append(f"{url_clean} -> {val}")
                            break
                        elif param.lower() in OPEN_REDIRECT_PARAMS and "http" in val.lower():
                            open_redirect_urls.append(f"{url_clean} -> {val}")
                            break

            # Проверка облачных хостингов и перехвата учетных данных (Credential Harvesting)
            is_cloud = host in CLOUD_PHISHING_HOSTS or any(host.endswith("." + cph) for cph in CLOUD_PHISHING_HOSTS)
            has_cred_marker = "@" in url_clean or any(k in url_clean.lower() for k in ("email=", "mail=", "user=", "login=", "account="))

            if is_cloud:
                if has_cred_marker:
                    cred_harvest_urls.append(url_clean)
                else:
                    cloud_phish_urls.append(url_clean)
            elif has_cred_marker and reg_sender_domain:
                reg_host = get_registrable_domain(host)
                if reg_host and reg_host != reg_sender_domain and reg_host not in PUBLIC_MAIL_DOMAINS:
                    cred_harvest_urls.append(url_clean)

            if host in PUBLIC_MAIL_DOMAINS or any(td in host for td in TECHNICAL_DOMAINS):
                continue
            
            reg_host = get_registrable_domain(host)
            if reg_sender_domain and reg_host and reg_host != reg_sender_domain:
                misaligned_urls.append(url_clean)

        if cred_harvest_urls:
            findings.append(Finding(
                id="BODY_CREDENTIAL_HARVEST_URL",
                category=Category.BODY,
                severity=Severity.CRITICAL,
                weight=85,
                title="Критический фишинг: ссылка сбора учетных данных (Credential Harvesting)",
                evidence=f"Передача идентификатора/email жертвы на внешний или облачный ресурс: {', '.join(cred_harvest_urls[:2])}",
                confidence=0.99
            ))

        if cloud_phish_urls:
            findings.append(Finding(
                id="BODY_CLOUD_PHISHING_HOST",
                category=Category.BODY,
                severity=Severity.HIGH,
                weight=45,
                title="Ссылка ведет на публичный облачный хостинг / CDN (частый вектор фишинга)",
                evidence=f"Облачный хостинг: {', '.join(cloud_phish_urls[:3])}",
                confidence=0.90
            ))

        if shortener_urls:
            findings.append(Finding(
                id="BODY_URL_SHORTENER",
                category=Category.BODY,
                severity=Severity.HIGH,
                weight=35,
                title=f"Использование сервисов сокращения ссылок ({len(shortener_urls)} шт.)",
                evidence=f"Скрывают реальный целевой адрес: {', '.join(shortener_urls[:3])}",
                confidence=0.95
            ))

        if ip_urls:
            findings.append(Finding(
                id="BODY_IP_URL",
                category=Category.BODY,
                severity=Severity.HIGH,
                weight=45,
                title=f"Использование прямого IP-адреса вместо доменного имени ({len(ip_urls)} шт.)",
                evidence=f"Примеры: {', '.join(ip_urls[:3])}",
                confidence=0.98
            ))

        if risky_tld_urls:
            findings.append(Finding(
                id="BODY_RISKY_TLD",
                category=Category.BODY,
                severity=Severity.MEDIUM,
                weight=25,
                title=f"Ссылки ведут на доменные зоны повышенного риска ({len(risky_tld_urls)} шт.)",
                evidence=f"Примеры: {', '.join(risky_tld_urls[:3])}",
                confidence=0.9
            ))

        if open_redirect_urls:
            findings.append(Finding(
                id="BODY_OPEN_REDIRECT",
                category=Category.BODY,
                severity=Severity.HIGH,
                weight=40,
                title="Обнаружена эксплуатация открытого перенаправления (Open Redirect)",
                evidence=f"Ссылка: {open_redirect_urls[0][:120]}",
                confidence=0.95
            ))

        if misaligned_urls:
            findings.append(Finding(
                id="BODY_MISALIGNED_URLS",
                category=Category.BODY,
                severity=Severity.MEDIUM,
                weight=15,
                title=f"Ссылки на сторонние домены, не связанные с доменом отправителя ({len(misaligned_urls)} шт.)",
                evidence=f"Примеры: {', '.join(misaligned_urls[:3])}",
                confidence=0.8
            ))

        return findings

