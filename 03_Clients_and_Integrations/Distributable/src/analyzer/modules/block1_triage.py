# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block1_triage.py
Назначение: Блок 1: Сигнатурный триаж и экспресс-анализ подозрительных потоков.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import logging
import time
from typing import Dict, Any, List
try:
    from oletools.olevba import VBA_Parser, TYPE_XLM, TYPE_VBA
    from oletools.mraptor import MacroRaptor
    OLETOOLS_AVAILABLE = True
except ImportError:
    VBA_Parser = None
    MacroRaptor = None
    TYPE_XLM = "XLM"
    TYPE_VBA = "VBA"
    OLETOOLS_AVAILABLE = False
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK1")

def run_block1(filepath: str) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK1", success=False, execution_time_ms=0)
    
    vba_parser = None
    try:
        if not OLETOOLS_AVAILABLE or VBA_Parser is None:
            result.success = True
            result.raw_findings = {
                "vba_stomping": False,
                "xlm_macros": [],
                "modules_count": 0,
                "mraptor_status": "SKIPPED_NO_OLETOOLS",
                "has_macros": False,
                "vba_code": "",
                "decoded_strings": []
            }
            return result
        # 1. OLEVBA анализ через Python API
        vba_parser = VBA_Parser(filepath)
        vba_results = list(vba_parser.analyze_macros())
        
        # Сбор индикаторов от olevba
        indicators = []
        decoded_strings = []
        vba_stomping_detected = False
        
        for kw_type, keyword, description in vba_results:
            level = ThreatLevel.INFO
            weight = 0
            
            # Маппинг уровней olevba в OMSA
            if kw_type == 'AutoExec':
                level = ThreatLevel.MEDIUM
                weight = 20
            elif kw_type == 'Suspicious':
                level = ThreatLevel.HIGH
                weight = 50
            elif kw_type == 'IOC':
                level = ThreatLevel.HIGH
                weight = 50
            
            indicators.append(ThreatIndicator(
                indicator_id=f"BLOCK1.OLEVBA_{kw_type.upper()}",
                level=level,
                weight=weight,
                description=description,
                evidence=keyword,
                location="MACRO"
            ))
            
            if "Stomping" in description or "P-code" in description:
                vba_stomping_detected = True
        
        # 2. MRAPTOR анализ
        mraptor = MacroRaptor(vba_parser.vba_code if vba_parser.vba_code else "")
        mraptor_result = mraptor.analyze()
        
        if mraptor_result == "SUSPICIOUS":
             indicators.append(ThreatIndicator(
                indicator_id="BLOCK1.MRAPTOR_SUSPICIOUS",
                level=ThreatLevel.INFO, # Как указано в ТЗ п.4.1 (INFO-сигнал)
                weight=0,
                description="MRaptor flagged this file as suspicious",
                evidence="MRaptor: SUSPICIOUS",
                location="CORE"
            ))
        
        # 3. XLM Check
        xlm_macros = []
        for module in vba_parser.vba_modules:
            if module.type == TYPE_XLM:
                xlm_macros.append(module.modname)
                # Поиск CALL/EXEC/REGISTER/RUN в XLM (ТЗ п.4.1)
                for line in vba_parser.vba_code.upper().splitlines():
                    if any(cmd in line for cmd in ["CALL", "EXEC", "REGISTER", "RUN"]):
                        indicators.append(ThreatIndicator(
                            indicator_id="BLOCK1.XLM_HIGH_RISK",
                            level=ThreatLevel.HIGH,
                            weight=50,
                            description=f"Dangerous XLM function found in {module.modname}",
                            evidence=line.strip(),
                            location=module.modname
                        ))

        # 4. Сохранение результатов
        result.success = True
        result.raw_findings = {
            "vba_stomping": vba_stomping_detected,
            "xlm_macros": xlm_macros,
            "modules_count": len(vba_parser.vba_modules),
            "mraptor_status": mraptor_result,
            "has_macros": vba_parser.detect_macros(),
            "vba_code": vba_parser.vba_code if vba_parser.vba_code else "",
            "decoded_strings": [kw for kw_t, kw, desc in vba_results if kw_t == 'Suspicious']
        }
        result.threat_indicators = indicators
        
    except Exception as e:
        result.error_message = f"Error in Block 1: {str(e)}"
        logger.exception("Error in run_block1")
        
    finally:
        if vba_parser is not None:
            try:
                vba_parser.close()
            except Exception:
                pass
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



