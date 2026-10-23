# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: models.py
Назначение: Модели данных, индикаторы угроз и перечисления уровней риска.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
from enum import Enum
from typing import Any
from pydantic import BaseModel, Field


class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


THREAT_WEIGHTS: dict[ThreatLevel, int] = {
    ThreatLevel.CRITICAL: 100,
    ThreatLevel.HIGH: 50,
    ThreatLevel.MEDIUM: 20,
    ThreatLevel.LOW: 5,
    ThreatLevel.INFO: 0,
}


class ThreatIndicator(BaseModel):
    indicator_id: str
    level: ThreatLevel
    weight: int = 0
    description: str
    evidence: str = ""
    location: str = ""

    def model_post_init(self, __context: Any) -> None:
        if self.weight == 0:
            self.weight = THREAT_WEIGHTS[self.level]


class BlockResult(BaseModel):
    block_name: str
    success: bool
    execution_time_ms: int = 0
    error_message: str | None = None
    threat_indicators: list[ThreatIndicator] = Field(default_factory=list)
    raw_findings: dict[str, Any] = Field(default_factory=dict)