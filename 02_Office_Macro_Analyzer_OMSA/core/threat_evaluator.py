# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: threat_evaluator.py
Назначение: Оценка весов индикаторов компрометации и расчет скоринга.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
from .models import ThreatIndicator, ThreatLevel, THREAT_WEIGHTS

SCORE_CRITICAL_THRESHOLD = 150
SCORE_HIGH_THRESHOLD = 80
SCORE_MEDIUM_THRESHOLD = 30
SCORE_LOW_THRESHOLD = 5


def deduplicate_indicators(
    indicators: list[ThreatIndicator],
) -> list[ThreatIndicator]:
    best_by_id: dict[str, ThreatIndicator] = {}
    for indicator in indicators:
        existing = best_by_id.get(indicator.indicator_id)
        if existing is None or indicator.weight > existing.weight:
            best_by_id[indicator.indicator_id] = indicator
    return list(best_by_id.values())


def calculate_total_weight(indicators: list[ThreatIndicator]) -> int:
    return sum(i.weight for i in indicators)


def get_threat_level_by_score(score: int) -> str:
    if score >= SCORE_CRITICAL_THRESHOLD:
        return "КРИТИЧЕСКИЙ"
    if score >= SCORE_HIGH_THRESHOLD:
        return "ВЫСОКИЙ"
    if score >= SCORE_MEDIUM_THRESHOLD:
        return "СРЕДНИЙ"
    if score >= SCORE_LOW_THRESHOLD:
        return "НИЗКИЙ"
    return "ЧИСТО"


LEVEL_SORT_ORDER = {
    ThreatLevel.CRITICAL: 0,
    ThreatLevel.HIGH: 1,
    ThreatLevel.MEDIUM: 2,
    ThreatLevel.LOW: 3,
    ThreatLevel.INFO: 4,
}


def get_top_indicators(
    indicators: list[ThreatIndicator],
    count: int,
) -> list[ThreatIndicator]:
    return sorted(
        indicators,
        key=lambda i: (
            -i.weight,
            LEVEL_SORT_ORDER.get(i.level, 99),
            i.indicator_id,
        ),
    )[:count]