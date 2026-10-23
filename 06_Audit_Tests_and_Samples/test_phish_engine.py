# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: test_phish_engine.py
Назначение: Модульные тесты для аналитического движка phish_engine.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import sys
from pathlib import Path
import pytest

CORE_ENGINES = Path(__file__).resolve().parents[1] / "01_Core_Engines"
SCRIPTS = Path(__file__).resolve().parents[1] / "Scripts"
for p in (CORE_ENGINES, SCRIPTS):
    if p.exists() and str(p) not in sys.path:
        sys.path.insert(0, str(p))

from phish_engine import (
    PhishingEngine, HeadersChecker, BodyChecker, AttachmentsChecker,
    ThreatScorer, Severity, Category, Finding
)


def test_scorer_thresholds():
    scorer = ThreatScorer(clean_threshold=30, malicious_threshold=70)
    
    # Clean
    res_clean = scorer.calculate([Finding("TEST_1", Category.HEADERS, Severity.INFO, 5, "Test info")])
    assert res_clean.verdict == "CLEAN"
    assert res_clean.total_score == 5

    # Suspicious
    res_susp = scorer.calculate([
        Finding("TEST_2", Category.BODY, Severity.MEDIUM, 35, "Suspicious anchor")
    ])
    assert res_susp.verdict == "SUSPICIOUS"

    # Malicious
    res_mal = scorer.calculate([
        Finding("TEST_3", Category.ATTACHMENT, Severity.CRITICAL, 80, "Payload execution")
    ])
    assert res_mal.verdict == "MALICIOUS"
    assert res_mal.total_score >= 80


def test_headers_checker_typosquatting():
    checker = HeadersChecker(protected_domains=["enterprise-corp.com"])
    findings = checker.check(
        {"From": "Security <admin@enterprise-corpp.com>", "Subject": "Alert"},
        "From: Security <admin@enterprise-corpp.com>\nSubject: Alert\n"
    )
    ids = [f.id for f in findings]
    assert "HDR_TYPOSQUATTING" in ids


def test_headers_checker_homoglyph():
    checker = HeadersChecker()
    # 'p' кириллическое (U+0440) вместо латинского 'p'
    spoofed = "admin@enter\u0440rise-corp.com"
    findings = checker.check(
        {"From": f"Admin <{spoofed}>", "Subject": "Update"},
        f"From: Admin <{spoofed}>\nSubject: Update\n"
    )
    ids = [f.id for f in findings]
    assert "HDR_HOMOGLYPH_DOMAIN" in ids


def test_body_mismatched_anchor():
    checker = BodyChecker()
    html = '<p>Войдите в банк: <a href="https://evil-phish.ru/login">https://sberbank.ru/login</a></p>'
    findings = checker.check("", html, "info@sberbank.ru")
    ids = [f.id for f in findings]
    assert "BODY_MISMATCHED_LINK" in ids


def test_attachments_html_smuggling():
    checker = AttachmentsChecker()
    payload = b'<html><script>var x = atob("TVqQ"); var b = new Blob([x]); var a = document.createElement("a"); a.download = "update.exe";</script></html>'
    findings = checker.check_file("invoice.html", payload)
    ids = [f.id for f in findings]
    assert "ATT_HTML_SMUGGLING" in ids


def test_engine_real_emails_execution():
    engine = PhishingEngine(protected_domains=["enterprise-corp.com", "partner-org.org", "vendor-group.net"])
    
    # 1. Верификация на эталонном тестовом образце test.eml
    sample_eml = Path(__file__).resolve().parent / "test.eml"
    assert sample_eml.exists(), "Эталонный файл test.eml должен присутствовать в каталоге тестов"
    res_sample = engine.analyze_email_file(sample_eml)
    assert res_sample.verdict in ("CLEAN", "SUSPICIOUS", "MALICIOUS")
    assert any("песочниц" in u.lower() for u in res_sample.uninspected)

    # 2. Опциональная проверка внешних архивных кейсов (при их наличии)
    email_root = Path(__file__).resolve().parents[2] / "Email"
    if email_root.is_dir() and (email_root / "02.10.2026").is_dir():
        case1_files = list((email_root / "02.10.2026").glob("*.eml"))
        if case1_files:
            res_case1 = engine.analyze_email_file(case1_files[0])
            assert res_case1.verdict in ("CLEAN", "SUSPICIOUS")

    if (email_root / "05.10.2026").is_dir():
        case2_files = list((email_root / "05.10.2026").glob("*.eml"))
        if case2_files:
            res_case2 = engine.analyze_email_file(case2_files[0])
            assert res_case2.verdict == "CLEAN"
            assert res_case2.total_score <= 30
