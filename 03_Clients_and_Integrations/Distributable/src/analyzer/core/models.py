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
from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field

class ThreatLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

class ThreatIndicator(BaseModel):
    indicator_id: str  # Format: BLOCK_NAME.SHORT_CODE
    level: ThreatLevel
    weight: int
    description: str
    evidence: str
    location: str

class BlockResult(BaseModel):
    block_name: str
    success: bool
    execution_time_ms: int
    error_message: Optional[str] = None
    threat_indicators: List[ThreatIndicator] = []
    raw_findings: Dict[str, Any] = {}



