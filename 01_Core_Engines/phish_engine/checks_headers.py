# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: checks_headers.py
Назначение: Модуль криминалистического анализа заголовков и аутентификации.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import re
from email.utils import parseaddr
from typing import List, Dict, Any, Tuple
from pathlib import Path

from .scoring import Finding, Category, Severity

# Публичные почтовые провайдеры
PUBLIC_MAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "mail.ru", "yandex.ru", "yandex.by", "rambler.ru",
    "outlook.com", "hotmail.com", "live.com", "bk.ru", "inbox.ru", "list.ru",
    "protonmail.com", "proton.me", "icloud.com", "gmx.com", "zoho.com"
}

# Двухуровневые публичные суффиксы
TWO_LEVEL_SUFFIXES = {
    "com.by", "gov.by", "org.by", "net.by", "mil.by",
    "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.ru", "org.ru", "net.ru", "com.ua", "com.cn", "com.br",
    "co.jp", "com.au", "co.in", "com.tr", "com.kz",
}

# Типичные омоглифы (кириллица, визуально неотличимая от латиницы)
CYRILLIC_HOMOGLYPHS = {
    'а': 'a', 'с': 'c', 'е': 'e', 'о': 'o', 'р': 'p', 'х': 'x', 'у': 'y',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w'
}


def get_registrable_domain(host: str) -> str:
    labels = [p for p in host.lower().strip(".").split(".") if p]
    if len(labels) <= 2:
        return ".".join(labels)
    if ".".join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def detect_mixed_scripts(text: str) -> bool:
    """Выявляет опасное смешение символов латиницы и похожей кириллицы в одном слове/домене."""
    has_cyr = bool(re.search(r'[а-яёА-ЯЁ]', text))
    has_lat = bool(re.search(r'[a-zA-Z]', text))
    return has_cyr and has_lat


def levenshtein_distance(s1: str, s2: str) -> int:
    """Расчет расстояния Левенштейна для поиска опечаток в доменах (typosquatting)."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    prev = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        curr = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = prev[j + 1] + 1
            deletions = curr[j] + 1
            substitutions = prev[j] + (c1 != c2)
            curr.append(min(insertions, deletions, substitutions))
        prev = curr
    return prev[-1]


class HeadersChecker:
    def __init__(self, protected_domains: List[str] | None = None):
        self.protected_domains = [d.lower() for d in (protected_domains or ["enterprise-corp.com", "partner-org.org", "vendor-group.net"])]

    def check(self, msg_headers: Dict[str, Any], raw_header_text: str) -> List[Finding]:
        findings: List[Finding] = []
        unfolded = re.sub(r"\r?\n[ \t]+", " ", raw_header_text)

        sender_raw = msg_headers.get("Nested-From") or msg_headers.get("From", "")
        reply_to_raw = msg_headers.get("Nested-Reply-To") or msg_headers.get("Reply-To", "")
        return_path_raw = msg_headers.get("Nested-Return-Path") or msg_headers.get("Return-Path", "")
        subject = msg_headers.get("Subject", "")

        disp_from, addr_from = parseaddr(sender_raw)
        _, addr_reply_to = parseaddr(reply_to_raw)
        _, addr_return_path = parseaddr(return_path_raw)

        domain_from = addr_from.split("@")[-1].lower() if "@" in addr_from else ""
        reg_domain_from = get_registrable_domain(domain_from) if domain_from else ""

        # 1. Проверка наличия аутентификации
        has_auth_header = any(
            h in unfolded.lower() 
            for h in ("authentication-results:", "received-spf:", "arc-authentication-results:")
        )
        if not has_auth_header:
            findings.append(Finding(
                id="HDR_AUTH_MISSING",
                category=Category.HEADERS,
                severity=Severity.INFO,
                weight=5,
                title="Заголовки аутентификации (SPF/DKIM/DMARC) отсутствуют",
                evidence="Почтовый сервер не записал Authentication-Results",
                confidence=0.9
            ))

        # 2. Парсинг статусов SPF, DKIM, DMARC
        auth_data = self._extract_auth_statuses(unfolded)
        
        # SPF
        spf_status = auth_data.get("spf", "").lower()
        if "fail" in spf_status:
            findings.append(Finding(
                id="HDR_SPF_FAIL",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                weight=35,
                title=f"SPF аутентификация не пройдена: {spf_status}",
                evidence=f"SPF status: {spf_status}",
                confidence=0.95
            ))

        # DKIM
        dkim_status = auth_data.get("dkim", "").lower()
        if dkim_status in ("fail", "none"):
            findings.append(Finding(
                id="HDR_DKIM_FAIL",
                category=Category.HEADERS,
                severity=Severity.MEDIUM,
                weight=20,
                title=f"DKIM аутентификация отсутствует или не прошла валидацию: {dkim_status}",
                evidence=f"DKIM status: {dkim_status}",
                confidence=0.9
            ))

        # DMARC
        dmarc_status = auth_data.get("dmarc", "").lower()
        if "fail" in dmarc_status:
            findings.append(Finding(
                id="HDR_DMARC_FAIL",
                category=Category.HEADERS,
                severity=Severity.HIGH,
                weight=35,
                title=f"DMARC проверка завершилась с ошибкой: {dmarc_status}",
                evidence=f"DMARC status: {dmarc_status}",
                confidence=0.95
            ))

        # 3. Выравнивание (Alignment) From vs Return-Path
        if addr_return_path and domain_from:
            domain_rp = addr_return_path.split("@")[-1].lower() if "@" in addr_return_path else ""
            if domain_rp and get_registrable_domain(domain_rp) != reg_domain_from:
                findings.append(Finding(
                    id="HDR_MISALIGNED_RETURN_PATH",
                    category=Category.HEADERS,
                    severity=Severity.MEDIUM,
                    weight=15,
                    title="Return-Path не совпадает с доменом отправителя From",
                    evidence=f"From: {domain_from} vs Return-Path: {domain_rp}",
                    confidence=0.85
                ))

        # 4. Выравнивание From vs Reply-To
        if addr_reply_to and domain_from:
            domain_rt = addr_reply_to.split("@")[-1].lower() if "@" in addr_reply_to else ""
            if domain_rt and get_registrable_domain(domain_rt) != reg_domain_from:
                findings.append(Finding(
                    id="HDR_MISALIGNED_REPLY_TO",
                    category=Category.HEADERS,
                    severity=Severity.HIGH,
                    weight=25,
                    title="Адрес ответа Reply-To перенаправляет на сторонний домен",
                    evidence=f"From: {addr_from} -> Reply-To: {addr_reply_to}",
                    confidence=0.9
                ))

        # 5. Display Name Spoofing
        if disp_from and domain_from in PUBLIC_MAIL_DOMAINS:
            brand_keywords = ("администрация", "security", "безопасность", "поддержка", "банк", "it-отдел", "техподдержка", "бухгалтерия")
            if any(k in disp_from.lower() for k in brand_keywords) or any(p in disp_from.lower() for p in self.protected_domains):
                findings.append(Finding(
                    id="HDR_DISPLAY_NAME_SPOOF",
                    category=Category.HEADERS,
                    severity=Severity.HIGH,
                    weight=40,
                    title="Подмена имени отправителя (Display Name Spoofing с публичного ящика)",
                    evidence=f"Имя: «{disp_from}» отправлено с публичного почтового сервиса {addr_from}",
                    confidence=0.95
                ))

        # 6. Проверка домена отправителя на омоглифы и IDN/Punycode
        if domain_from:
            if domain_from.startswith("xn--"):
                findings.append(Finding(
                    id="HDR_IDN_PUNYCODE",
                    category=Category.HEADERS,
                    severity=Severity.MEDIUM,
                    weight=20,
                    title="Домен отправителя использует интернационализированный Punycode (xn--)",
                    evidence=f"Домен: {domain_from}",
                    confidence=0.9
                ))
            if detect_mixed_scripts(domain_from):
                findings.append(Finding(
                    id="HDR_HOMOGLYPH_DOMAIN",
                    category=Category.HEADERS,
                    severity=Severity.CRITICAL,
                    weight=75,
                    title="Спуфинг домена: обнаружено смешение символов латиницы и кириллицы (омоглифы)",
                    evidence=f"Домен: {domain_from}",
                    confidence=0.98
                ))

            # Поиск Typosquatting относительно защищаемых доменов
            for prot in self.protected_domains:
                if domain_from != prot and reg_domain_from != get_registrable_domain(prot):
                    dist = levenshtein_distance(domain_from, prot)
                    if 1 <= dist <= 2 and abs(len(domain_from) - len(prot)) <= 2:
                        findings.append(Finding(
                            id="HDR_TYPOSQUATTING",
                            category=Category.HEADERS,
                            severity=Severity.CRITICAL,
                            weight=70,
                            title=f"Возможный спуфинг домена организации (Typosquatting к {prot})",
                            evidence=f"Домен отправителя «{domain_from}» отличается от «{prot}» на {dist} симв.",
                            confidence=0.92
                        ))

        # 7. Форензик цепочки Received (трассировка транзитных узлов и originating IP)
        findings.extend(self._check_received_hops(unfolded))

        # 8. Анализ Message-ID и почтового клиента X-Mailer
        findings.extend(self._check_message_id_and_mailer(msg_headers, domain_from, reg_domain_from))

        return findings

    def _check_received_hops(self, unfolded_text: str) -> List[Finding]:
        findings: List[Finding] = []
        received_lines = []
        for line in unfolded_text.splitlines():
            if line.lower().startswith("received:"):
                received_lines.append(line[9:].strip())

        if not received_lines:
            return findings

        # Поиск внешнего IP отправителя (последний по списку / первый хронологически)
        ip_regex = re.compile(r"\[([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})\]")
        originating_ip = None

        # Идем снизу вверх (от самого раннего релея к последнему)
        for hop in reversed(received_lines):
            ips = ip_regex.findall(hop)
            for ip in ips:
                # Фильтр частных и локальных сетей
                parts = [int(p) for p in ip.split(".")]
                if parts[0] == 10 or parts[0] == 127:
                    continue
                if parts[0] == 172 and 16 <= parts[1] <= 31:
                    continue
                if parts[0] == 192 and parts[1] == 168:
                    continue
                originating_ip = ip
                break
            if originating_ip:
                # Проверка подозрительных PTR / FQDN в строке hop
                hop_low = hop.lower()
                dynamic_markers = ("dynamic", "broadband", "dialup", "pool", "dhcp", "user.ono", "cable")
                if any(m in hop_low for m in dynamic_markers):
                    findings.append(Finding(
                        id="HDR_RECEIVED_DYNAMIC_IP",
                        category=Category.HEADERS,
                        severity=Severity.HIGH,
                        weight=35,
                        title="Отправка письма напрямую с динамического пула IP (ботнет / нелегитимный релей)",
                        evidence=f"Узел Received указывает на бытовой пул провайдера: {originating_ip} ({hop[:120]})",
                        confidence=0.9
                    ))
                break

        return findings

    def _check_message_id_and_mailer(self, headers: Dict[str, Any], domain_from: str, reg_domain_from: str) -> List[Finding]:
        findings: List[Finding] = []
        msg_id = headers.get("Message-ID", headers.get("Message-Id", "")).strip()

        # 1. Проверка Message-ID
        if not msg_id:
            findings.append(Finding(
                id="HDR_MISSING_MESSAGE_ID",
                category=Category.HEADERS,
                severity=Severity.LOW,
                weight=10,
                title="Отсутствует обязательный заголовок Message-ID",
                evidence="Письмо отправлено без стандартного идентификатора RFC 5322",
                confidence=0.8
            ))
        else:
            if "@" not in msg_id:
                findings.append(Finding(
                    id="HDR_MALFORMED_MESSAGE_ID",
                    category=Category.HEADERS,
                    severity=Severity.MEDIUM,
                    weight=20,
                    title="Некорректный синтаксис Message-ID (отсутствует разделитель @)",
                    evidence=f"Message-ID: {msg_id}",
                    confidence=0.9
                ))
            else:
                id_domain = msg_id.split("@")[-1].rstrip(">").strip().lower()
                reg_id_domain = get_registrable_domain(id_domain) if id_domain else ""
                # Если домен в Message-ID полностью сторонний и не является почтовым сервером / From
                if reg_domain_from and reg_id_domain and reg_domain_from != reg_id_domain:
                    # Исключаем крупные валидные почтовые платформы
                    known_relays = ("google.com", "protection.outlook.com", "mail.ru", "yandex.net", "yahoodns.net", "hoster.by")
                    if not any(kr in id_domain for kr in known_relays):
                        findings.append(Finding(
                            id="HDR_MISALIGNED_MESSAGE_ID",
                            category=Category.HEADERS,
                            severity=Severity.LOW,
                            weight=10,
                            title="Домен в Message-ID не совпадает с доменом отправителя From",
                            evidence=f"From: {domain_from} vs Message-ID: {id_domain}",
                            confidence=0.8
                        ))

        # 2. Проверка X-Mailer / User-Agent
        x_mailer = headers.get("X-Mailer", headers.get("User-Agent", "")).strip()
        if x_mailer:
            suspicious_mailers = ("phpmailer", "massmail", "directmail", "python", "curl", "wget", "smtp-send", "auto-generated")
            x_low = x_mailer.lower()
            if any(sm in x_low for sm in suspicious_mailers):
                findings.append(Finding(
                    id="HDR_SUSPICIOUS_X_MAILER",
                    category=Category.HEADERS,
                    severity=Severity.HIGH,
                    weight=30,
                    title="Использование автоматизированного спам/фишинг инструмента в X-Mailer",
                    evidence=f"X-Mailer: {x_mailer}",
                    confidence=0.95
                ))

        return findings

    def _extract_auth_statuses(self, unfolded_text: str) -> Dict[str, str]:
        auth = {"spf": "", "dkim": "", "dmarc": ""}
        clean_text = re.sub(r"\r?\n[ \t]+", " ", unfolded_text)
        for line in clean_text.splitlines():
            low = line.lower().strip()
            if not any(k in low for k in ("authentication-results:", "received-spf:", "x-feas-spf:", "arc-authentication-results:", "x-feas-dkim:")):
                continue
            if "spf=pass" in low or "spf-result=pass" in low:
                auth["spf"] = "pass"
            elif "spf=fail" in low or "spf=softfail" in low:
                auth["spf"] = auth["spf"] or "fail"
            if "dkim=pass" in low:
                auth["dkim"] = "pass"
            elif "dkim=fail" in low or "invalid signature" in low or "dkim=none" in low:
                auth["dkim"] = auth["dkim"] or "fail"
            if "dmarc=pass" in low:
                auth["dmarc"] = "pass"
            elif "dmarc=fail" in low or "action=reject" in low or "action=quarantine" in low:
                auth["dmarc"] = auth["dmarc"] or "fail"
        return auth

