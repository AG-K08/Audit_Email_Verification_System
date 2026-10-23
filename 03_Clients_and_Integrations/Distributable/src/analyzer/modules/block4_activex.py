# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block4_activex.py
Назначение: Блок 4: Анализ элементов управления ActiveX и внедренных форм.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import json
import logging
import time
try:
    import olefile
except ImportError:
    olefile = None
from typing import List, Dict, Any
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK4")

def load_clsid_db() -> Dict[str, Any]:
    db_path = os.path.join(os.path.dirname(__file__), "..", "core", "clsid_db.json")
    try:
        with open(db_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def parse_activex_bin(bin_path: str, clsid_db: Dict[str, Any]) -> List[Dict[str, Any]]:
    # Парсинг активных объектов из OLE-контейнеров (activeX*.bin)
    results = []
    if olefile is None or not olefile.isOleFile(bin_path):
        return []
        
    ole = None
    try:
        ole = olefile.OleFileIO(bin_path)
        # Попытка найти CLSID в \x01CompObj или других потоках
        # В OpenXML для ActiveX CLSID хранится в ассоциированных XML файлах, 
        # но информация может быть и в .bin (через OLE2 структуру).
        if ole.exists("\x01CompObj"):
            data = ole.openstream("\x01CompObj").read()
            # Простой поиск CLSID по паттерну в байтах
            import re
            m = re.findall(rb'\{[0-9A-Fa-f-]+\}', data)
            for raw_clsid in m:
                clsid_str = raw_clsid.decode('ascii', errors='ignore').upper()
                if clsid_str in clsid_db:
                    info = clsid_db[clsid_str]
                    results.append({"clsid": clsid_str, "name": info["name"], "sev": info["severity"], "desc": info["description"]})
    except Exception as e:
        logger.error(f"Error parsing ActiveX bin {bin_path}: {str(e)}")
    finally:
        if ole is not None:
            try:
                ole.close()
            except Exception:
                pass
        
    return results

def run_block4(extracted_dir: str) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK4", success=False, execution_time_ms=0)
    
    try:
        clsid_db = load_clsid_db()
        activex_path = os.path.join(extracted_dir, "word", "activeX")
        if not os.path.exists(activex_path):
            # Попробуем для Excel
            activex_path = os.path.join(extracted_dir, "xl", "activeX")
        
        findings = []
        inds = []
        
        if os.path.exists(activex_path):
            for f in os.listdir(activex_path):
                if f.endswith(".bin"):
                    path = os.path.join(activex_path, f)
                    fnd = parse_activex_bin(path, clsid_db)
                    for find in fnd:
                        inds.append(ThreatIndicator(
                            indicator_id=f"BLOCK4.ACTIVEX_{find['name']}",
                            level=ThreatLevel(find["sev"]),
                            weight=50 if find["sev"] == "CRITICAL" else 20,
                            description=find["desc"],
                            evidence=f"CLSID: {find['clsid']}",
                            location=f"ActiveX bin: {f}"
                        ))
                    findings.extend(fnd)

        result.success = True
        result.threat_indicators = inds
        result.raw_findings = {"activex_count": len(findings), "identified_clsids": findings}

    except Exception as e:
        result.error_message = f"Error in Block 4: {str(e)}"
        logger.exception("Error in run_block4")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



