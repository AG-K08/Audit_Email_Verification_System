# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: engine.py
Назначение: Единый фасад аналитического движка (PhishingEngine).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import email
from email import policy
from email.parser import BytesParser
from pathlib import Path
from typing import Dict, Any, List, Tuple

from .scoring import ThreatScorer, ScoreResult, Finding
from .checks_headers import HeadersChecker
from .checks_body import BodyChecker
from .checks_attachments import AttachmentsChecker
from .checks_quishing import QuishingChecker


class PhishingEngine:
    def __init__(self, protected_domains: List[str] | None = None):
        self.headers_checker = HeadersChecker(protected_domains)
        self.body_checker = BodyChecker()
        self.attachments_checker = AttachmentsChecker()
        self.quishing_checker = QuishingChecker()
        self.scorer = ThreatScorer()

    def analyze_email_file(self, email_path: Path) -> ScoreResult:
        if isinstance(email_path, str):
            email_path = Path(email_path)
        raw_bytes = email_path.read_bytes()
        is_msg = email_path.suffix.lower() == ".msg" or raw_bytes.startswith(b"\xd0\xcf\x11\xe0")

        extra_uninspected: List[str] = []
        if is_msg:
            headers_dict, raw_header_text, body_text, body_html, attachments, used_fallback = self._load_msg_bytes(raw_bytes, email_path)
            if used_fallback:
                extra_uninspected.append("Формат Microsoft Outlook (.msg) обработан в резервном режиме; для полного извлечения вложений рекомендуется установить extract_msg")
        else:
            headers_dict, raw_header_text, body_text, body_html, attachments = self._load_eml_bytes(raw_bytes)

        return self.analyze_parsed_data(headers_dict, raw_header_text, body_text, body_html, attachments, extra_uninspected)

    def analyze_file(self, email_path: Path | str) -> ScoreResult:
        """Alias for analyze_email_file supporting str or Path."""
        return self.analyze_email_file(Path(email_path) if isinstance(email_path, str) else email_path)


    def analyze_parsed_data(
        self,
        headers_dict: Dict[str, Any],
        raw_header_text: str,
        body_text: str,
        body_html: str,
        attachments: List[Tuple[str, bytes]],
        extra_uninspected: List[str] | None = None
    ) -> ScoreResult:
        sender_email = headers_dict.get("From", "")

        # Запуск проверок
        all_findings: List[Finding] = []
        all_findings.extend(self.headers_checker.check(headers_dict, raw_header_text))
        all_findings.extend(self.body_checker.check(body_text, body_html, sender_email))

        # Проверка вложений
        quishing_urls: List[str] = []
        for fn, data in attachments:
            all_findings.extend(self.attachments_checker.check_file(fn, data))
            ext = Path(fn).suffix.lower()
            if ext in (".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp"):
                _, q_urls = self.quishing_checker.scan_image(fn, data)
                quishing_urls.extend(q_urls)

        # Если в QR-кодах найдены целевые ссылки, дополнительно проверяем их через BodyChecker
        if quishing_urls:
            quishing_body = "\n".join(quishing_urls)
            all_findings.extend(self.body_checker.check(quishing_body, "", sender_email))

        if len(attachments) > 1:
            all_findings.extend(self.attachments_checker.check_attachments_cluster(attachments))

        # Формирование перечня того, что не исследовалось статически
        uninspected = [
            "Динамический анализ в изолированной песочнице (KATA / ANY.RUN) не выполнялся",
            "Репутационная проверка внешних URL и доменов через VirusTotal / WHOIS отключена в офлайн-режиме",
            "Поведенческий профиль отправителя по локальной базе исторических писем не сопоставлялся"
        ]
        if extra_uninspected:
            uninspected.extend(extra_uninspected)

        return self.scorer.calculate(all_findings, uninspected)

    def _load_eml_bytes(self, raw_bytes: bytes) -> Tuple[Dict[str, Any], str, str, str, List[Tuple[str, bytes]]]:
        msg = BytesParser(policy=policy.default).parsebytes(raw_bytes)
        return self._extract_msg_parts(msg)

    def _extract_msg_parts(self, msg: Any) -> Tuple[Dict[str, Any], str, str, str, List[Tuple[str, bytes]]]:
        headers_dict = {k: str(v) for k, v in msg.items()}
        raw_header_text = str(msg)

        body_text = ""
        body_html = ""
        attachments: List[Tuple[str, bytes]] = []

        if msg.is_multipart():
            for part in msg.walk():
                ctype = part.get_content_type()
                cdisp = str(part.get_content_disposition())
                fn = part.get_filename()

                # Рекурсивный разбор вложенных писем (Fwd: контейнеры message/rfc822)
                if ctype == "message/rfc822":
                    import base64
                    payload = part.get_payload()
                    sub_msg = None
                    if isinstance(payload, list) and payload:
                        first_item = payload[0]
                        if hasattr(first_item, "walk"):
                            if len(first_item.keys()) == 0 and isinstance(first_item.get_payload(), str):
                                try:
                                    raw_b64 = base64.b64decode(first_item.get_payload())
                                    sub_msg = BytesParser(policy=policy.default).parsebytes(raw_b64)
                                except Exception:
                                    sub_msg = first_item
                            else:
                                sub_msg = first_item
                        elif isinstance(first_item, (bytes, bytearray)):
                            sub_msg = BytesParser(policy=policy.default).parsebytes(bytes(first_item))
                    elif hasattr(payload, "walk"):
                        sub_msg = payload
                    if sub_msg is None:
                        raw_sub = part.get_payload(decode=True)
                        if isinstance(raw_sub, bytes) and raw_sub:
                            try:
                                sub_msg = BytesParser(policy=policy.default).parsebytes(raw_sub)
                            except Exception:
                                sub_msg = None

                    if sub_msg:
                        sub_h, sub_raw, sub_bt, sub_bh, sub_att = self._extract_msg_parts(sub_msg)
                        raw_header_text += "\n--- Nested message/rfc822 ---\n" + sub_raw
                        body_text += "\n" + sub_bt
                        body_html += "\n" + sub_bh
                        attachments.extend(sub_att)
                        if sub_h.get("From"):
                            headers_dict["Nested-From"] = sub_h.get("From")
                        if sub_h.get("Return-Path"):
                            headers_dict["Nested-Return-Path"] = sub_h.get("Return-Path")
                    continue

                payload = part.get_payload(decode=True)
                if fn and payload is not None:
                    attachments.append((fn, payload))
                elif ctype == "text/plain" and "attachment" not in cdisp and payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_text += payload.decode(charset, errors="replace")
                    except (LookupError, ValueError):
                        body_text += payload.decode("utf-8", errors="replace")
                elif ctype == "text/html" and "attachment" not in cdisp and payload:
                    charset = part.get_content_charset() or "utf-8"
                    try:
                        body_html += payload.decode(charset, errors="replace")
                    except (LookupError, ValueError):
                        body_html += payload.decode("utf-8", errors="replace")
        else:
            payload = msg.get_payload(decode=True)
            charset = msg.get_content_charset() or "utf-8"
            if payload:
                try:
                    decoded_text = payload.decode(charset, errors="replace")
                except (LookupError, ValueError):
                    decoded_text = payload.decode("utf-8", errors="replace")
            else:
                decoded_text = ""
            if msg.get_content_type() == "text/html":
                body_html = decoded_text
            else:
                body_text = decoded_text

        return headers_dict, raw_header_text, body_text, body_html, attachments


    def _load_msg_bytes(self, raw_bytes: bytes, file_path: Path) -> Tuple[Dict[str, Any], str, str, str, List[Tuple[str, bytes]], bool]:
        try:
            import extract_msg
            msg = extract_msg.Message(str(file_path))
            try:
                headers_dict = {
                    "From": str(msg.sender or ""),
                    "To": str(msg.to or ""),
                    "Subject": str(msg.subject or ""),
                    "Date": str(msg.date or ""),
                    "Message-ID": str(msg.messageId or "")
                }
                raw_header_text = str(msg.header or "")
                body_text = str(msg.body or "")
                body_html = str(msg.htmlBody or "")

                attachments: List[Tuple[str, bytes]] = []
                for att in msg.attachments or []:
                    fn = att.longFilename or att.shortFilename or "attachment.bin"
                    data = att.data or b""
                    attachments.append((fn, data))

                return headers_dict, raw_header_text, body_text, body_html, attachments, False
            finally:
                msg.close()
        except Exception:
            # Fallback: эвристический разбор строк из OLE бинарника
            headers_dict = {"From": "outlook_user@msg"}
            raw_header_text = raw_bytes[:4096].decode("latin-1", errors="ignore")
            body_text = raw_bytes.decode("utf-8", errors="ignore")
            return headers_dict, raw_header_text, body_text, "", [], True
