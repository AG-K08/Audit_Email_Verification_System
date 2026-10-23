# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block3_pcode.py
Назначение: Блок 3: Дизассемблирование P-code и выявление VBA Stomping.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import subprocess
import logging
import time
import re
from typing import List, Dict, Any, Set
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK3")

def parse_pcodedmp(vba_project_path: str) -> List[Dict[str, Any]]:
    # Запуск pcodedmp CLI (ТЗ п.8)
    try:
        cmd = ["pcodedmp", "-v", vba_project_path]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if proc.returncode != 0:
            return []
            
        # Упрощенный парсинг вывода pcodedmp (поиск имен функций/процедур)
        # В реальной реализации здесь должен быть более сложный парсер
        # Для ТЗ 1.0 сделаем поиск по паттернам "[Sub" или "[Function"
        p_functions = []
        for line in proc.stdout.splitlines():
            m = re.search(r'\[(Sub|Function)\]\s+([\w\d_]+)', line, re.IGNORECASE)
            if m:
                p_functions.append({"type": m.group(1), "name": m.group(2).lower()})
        return p_functions
    except Exception as e:
        logger.error(f"pcodedmp error: {str(e)}")
        return []

def run_block3(vba_project_path: str, source_functions: List[str]) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK3", success=False, execution_time_ms=0)
    
    try:
        p_funcs_raw = parse_pcodedmp(vba_project_path)
        p_func_names = {f["name"].lower() for f in p_funcs_raw}
        source_func_names = {f.lower() for f in source_functions}
        
        inds = []
        
        # 1. Функции в p-code, отсутствующие в исходнике (HIGH)
        only_pcode = p_func_names - source_func_names
        for f in only_pcode:
             inds.append(ThreatIndicator(
                indicator_id="BLOCK3.VBA_STOMPING_ADDITIONAL_FUNC",
                level=ThreatLevel.HIGH,
                weight=50,
                description=f"Function '{f}' found in P-code but missing in VBA source",
                evidence=f"P-code function: {f}",
                location="P-CODE"
            ))
            
        # 2. Функции в исходнике, отсутствующие в p-code (MEDIUM)
        only_source = source_func_names - p_func_names
        for f in only_source:
             inds.append(ThreatIndicator(
                indicator_id="BLOCK3.VBA_STOMPING_MISSING_PCODE",
                level=ThreatLevel.MEDIUM,
                weight=20,
                description=f"Function '{f}' in source is not compiled to P-code (Dead Code?)",
                evidence=f"Source function: {f}",
                location="VBA_SOURCE"
            ))

        result.success = True
        result.threat_indicators = inds
        result.raw_findings = {
            "p_code_functions": list(p_func_names),
            "source_functions": list(source_func_names),
            "vba_stomping_confirmed": len(only_pcode) > 0 or len(only_source) > 0
        }

    except Exception as e:
        result.error_message = f"Error in Block 3: {str(e)}"
        logger.exception("Error in run_block3")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



