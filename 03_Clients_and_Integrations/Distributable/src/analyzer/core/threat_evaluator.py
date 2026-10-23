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
import logging
from typing import List, Dict, Any, Tuple
from core.models import ThreatLevel, ThreatIndicator, BlockResult
from core.config import THREAT_WEIGHTS, TOTAL_THRESHOLD_CRITICAL, TOTAL_THRESHOLD_HIGH, TOTAL_THRESHOLD_MEDIUM, TOTAL_THRESHOLD_LOW

logger = logging.getLogger("EVALUATOR")

def evaluate_threats(all_indicators: List[ThreatIndicator]) -> Tuple[ThreatLevel, int, List[ThreatIndicator]]:
    # Дедупликация индикаторов по indicator_id (согласно п.5 ТЗ)
    # Сохраняем только экземпляр с максимальным весом
    dedup_map: Dict[str, ThreatIndicator] = {}
    
    for indicator in all_indicators:
        if indicator.indicator_id not in dedup_map or indicator.weight > dedup_map[indicator.indicator_id].weight:
            dedup_map[indicator.indicator_id] = indicator
            
    # Итоговый список дедуплицированных индикаторов
    unique_indicators = list(dedup_map.values())
    
    # Расчёт суммарного веса
    total_weight = sum([ind.weight for ind in unique_indicators])
    
    # Оценка уровня угрозы
    final_level = ThreatLevel.INFO
    if total_weight >= TOTAL_THRESHOLD_CRITICAL:
        final_level = ThreatLevel.CRITICAL
    elif total_weight >= TOTAL_THRESHOLD_HIGH:
        final_level = ThreatLevel.HIGH
    elif total_weight >= TOTAL_THRESHOLD_MEDIUM:
        final_level = ThreatLevel.MEDIUM
    elif total_weight >= TOTAL_THRESHOLD_LOW:
        final_level = ThreatLevel.LOW
        
    # Сортировка индикаторов по весу и уровню
    sorted_indicators = sorted(
        unique_indicators, 
        key=lambda x: (x.weight, x.level.value), 
        reverse=True
    )
    
    return final_level, total_weight, sorted_indicators



