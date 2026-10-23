# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block6_ioc.py
Назначение: Блок 6: Извлечение сетевых и файловых индикаторов компрометации (IoC).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import re
import logging
import time
import requests
import os
from typing import List, Dict, Any, Set
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK6")

# Регулярные выражения (ТЗ п.4.6)
IOC_REGEX = {
    "URL": r'https?://[^\s"\'<>]+',
    "FTP": r'ftp://[^\s"\'<>]+',
    "UNC": r'\\\\[^\\s"\'<>]+',
    "IPV4": r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
    "IPV6": r'(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}',
    "FS_PATH_WIN": r'[A-Za-z]:\\[^"\'\n]+',
    "FS_PATH_UNIX": r'/[a-z/]+',
    "REGISTRY": r'HKEY_[A-Z_]+\\[^\s"\'<>]+'
}

def extract_from_text(text: str) -> Dict[str, Set[str]]:
    results = {k: set() for k in IOC_REGEX.keys()}
    for k, pattern in IOC_REGEX.items():
        matches = re.findall(pattern, text)
        for m in matches:
             results[k].add(m)
    return results

def check_vt(ioc_type: str, value: str, api_key: str) -> Dict[str, Any]:
    # Mocking VT check (ТЗ п.4.6 - оффлайн по дефолту)
    if not api_key:
        return {}
    # Real logic would be here with requests and ratelimiting
    return {"status": "NOT_CHECKED", "reason": "OFFLINE_MODE"}

def run_block6(vba_code: str, decoded_strings: List[str], offline_mode: bool = True, vt_api_key: str = None) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK6", success=False, execution_time_ms=0)
    
    try:
        inds = []
        combined_text = vba_code + "\n" + "\n".join(decoded_strings)
        iocs = extract_from_text(combined_text)
        
        # Превращение IoC в индикаторы
        for ioc_type, values in iocs.items():
            for val in values:
                level = ThreatLevel.MEDIUM
                weight = 20
                if ioc_type in ["URL", "UNC"]:
                    level = ThreatLevel.HIGH
                    weight = 50
                
                inds.append(ThreatIndicator(
                        indicator_id=f"BLOCK6.IOC_{ioc_type}",
                        level=level,
                        weight=weight,
                        description=f"{ioc_type} indicator of compromise found",
                        evidence=val,
                        location="VBA_OR_DECODED"
                    ))
                    
        # Внешние запросы (только если не в оффлайне)
        if not offline_mode and vt_api_key:
            # Логика VT запросов здесь
             pass
            
        result.success = True
        result.threat_indicators = inds
        result.raw_findings = {
            "iocs": {k: list(v) for k, v in iocs.items()},
            "iocs_count": sum(len(v) for v in iocs.values())
        }

    except Exception as e:
        result.error_message = f"Error in Block 6: {str(e)}"
        logger.exception("Error in run_block6")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



