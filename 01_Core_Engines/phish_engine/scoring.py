# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: scoring.py
Назначение: Модель оценки рисков, скоринга и классификации вердиктов.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, List, Dict


class Severity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class Category(str, Enum):
    HEADERS = "headers"
    BODY = "body"
    ATTACHMENT = "attachment"
    REPUTATION = "reputation"
    BEHAVIOR = "behavior"


@dataclass
class Finding:
    id: str
    category: Category
    severity: Severity
    weight: int
    title: str
    evidence: str = ""
    confidence: float = 1.0
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category.value,
            "severity": self.severity.value,
            "weight": self.weight,
            "title": self.title,
            "evidence": self.evidence,
            "confidence": self.confidence,
            "tags": self.tags,
        }


@dataclass
class ScoreResult:
    total_score: int
    verdict: str  # CLEAN, SUSPICIOUS, MALICIOUS
    confidence: float
    findings: List[Finding] = field(default_factory=list)
    uninspected: List[str] = field(default_factory=list)
    summary: str = ""
    recommendation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "total_score": self.total_score,
            "verdict": self.verdict,
            "confidence": self.confidence,
            "findings_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "uninspected": self.uninspected,
            "summary": self.summary,
            "recommendation": self.recommendation,
        }


class ThreatScorer:
    """Оценивает угрозы по сумме баллов на основе методологии (0-30 CLEAN, 31-70 SUSPICIOUS, >70 MALICIOUS)."""

    def __init__(self, clean_threshold: int = 30, malicious_threshold: int = 70):
        self.clean_threshold = clean_threshold
        self.malicious_threshold = malicious_threshold

    def calculate(
        self,
        findings: List[Finding],
        uninspected: List[str] | None = None,
    ) -> ScoreResult:
        if uninspected is None:
            uninspected = []

        # Базовая сумма баллов с учетом весов и уверенности
        raw_score = sum(int(f.weight * f.confidence) for f in findings)
        
        # Если есть хотя бы одна находка уровня CRITICAL с высокой уверенностью,
        # скоринг автоматически поднимается в зону MALICIOUS
        has_critical = any(f.severity == Severity.CRITICAL and f.confidence >= 0.8 for f in findings)
        if has_critical and raw_score < self.malicious_threshold + 1:
            raw_score = self.malicious_threshold + 10

        # Ограничиваем шкалой 0..100
        total_score = max(0, min(100, raw_score))

        # Определение вердикта
        if total_score <= self.clean_threshold:
            verdict = "CLEAN"
            recommendation = (
                "Письмо и вложения не содержат выявленных статических угроз. "
                "При необходимости отправки конфиденциальных данных убедитесь в аутентичности отправителя."
            )
        elif total_score <= self.malicious_threshold:
            verdict = "SUSPICIOUS"
            recommendation = (
                "Обнаружены подозрительные маркеры (несоответствие доменов, специфические структуры файлов). "
                "Рекомендуется дополнительная проверка через песочницу (KATA / ANY.RUN) и подтверждение по альтернативному каналу."
            )
        else:
            verdict = "MALICIOUS"
            recommendation = (
                "Высокий риск вредоносной активности (эксплойты, обфускация, запуск процессов, фишинговые связки). "
                "Блокировать доставку сообщения, изолировать хост при открытии вложения, уведомить SOC."
            )

        # Расчет общей уверенности: падает, если много критически важных непроверенных зон
        penalty = len(uninspected) * 0.08
        overall_confidence = max(0.2, min(1.0, 1.0 - penalty))

        summary = f"Скоринг риска: {total_score}/100 ({verdict}), обнаружено находок: {len(findings)}"

        return ScoreResult(
            total_score=total_score,
            verdict=verdict,
            confidence=round(overall_confidence, 2),
            findings=findings,
            uninspected=uninspected,
            summary=summary,
            recommendation=recommendation,
        )
