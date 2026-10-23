# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block2_vba_source.py
Назначение: Блок 2: Декомпиляция и статический анализ исходного кода VBA.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import re
import math
import logging
import time
import base64
from typing import List, Dict, Any, Tuple
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK2")

# Сигнатурные категории (ТЗ п.4.2)
SIGNATURES = {
    "EXECUTION": [r"Shell", r"WScript\.Shell", r"CreateObject", r"GetObject", r"CallByName", r"Application\.Run", r"MacroOptions", r"ExecuteExcel4Macro"],
    "FILESYSTEM": [r"Open.*For\s+(Input|Output|Append|Binary|Random)", r"FileSystemObject", r"Kill", r"FileCopy", r"MkDir", r"CreateTextFile", r"OpenTextFile"],
    "NETWORK": [r"URLDownloadToFile", r"URLDownloadToCacheFile", r"XMLHTTP", r"WinHttpRequest", r"InternetOpen", r"InternetOpenUrl", r"Winsock", r"ADODB\.Stream"],
    "REGISTRY": [r"RegRead", r"RegWrite", r"RegDelete", r"HKEY_", r"WScript\.RegWrite", r"RegOpenKey", r"RegSetValue"],
    "PROCESS": [r"CreateProcessW", r"CreateProcess", r"ShellExecuteEx", r"ShellExecute", r"Win32_Process", r"WMI"],
    "SELF_MOD": [r"VBProject", r"AddFromString", r"AddFromFile", r"CodeModule", r"VBComponents", r"Application\.VBE", r"InsertLines", r"DeleteLines", r"ReplaceLine", r"Application\.OnTime"],
    "UTILS": [r"powershell", r"cmd\.exe", r"mshta\.exe", r"regsvr32\.exe", r"certutil\.exe", r"wscript\.exe", r"cscript\.exe", r"rundll32\.exe", r"bitsadmin"]
}

def calculate_shannon_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(chr(x))) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def decode_base64_and_search(code: str) -> List[Tuple[str, str]]:
    results = []
    # Поиск Base64-строк (>40 симв, ТЗ п.4.2)
    b64_regex = r'[A-Za-z0-9+/]{40,}={0,2}'
    matches = re.finditer(b64_regex, code)
    for match in matches:
        b64_str = match.group()
        try:
            decoded = base64.b64decode(b64_str).decode('ascii', errors='ignore')
            if any(kw in decoded.lower() for kw in ["http", "powershell", "cmd", ".exe"]):
                results.append((b64_str, decoded))
        except:
            continue
    return results

def run_block2(vba_code: str, entropy_threshold: float = 5.5) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK2", success=False, execution_time_ms=0)
    
    if not vba_code:
        result.success = True
        return result

    try:
        inds = []
        # 1. Поиск по категориям (case-insensitive)
        for cat, patterns in SIGNATURES.items():
            for p in patterns:
                matches = re.finditer(p, vba_code, re.IGNORECASE)
                for m in matches:
                    line = vba_code[max(0, m.start()-20) : min(len(vba_code), m.end()+20)].strip()
                    
                    # Маппинг уровней по ТЗ
                    level = ThreatLevel.MEDIUM
                    weight = 20
                    if cat in ["NETWORK", "SELF_MOD"]:
                        level = ThreatLevel.CRITICAL
                        weight = 100
                    elif cat in ["EXECUTION", "PROCESS", "REGISTRY"]:
                        level = ThreatLevel.HIGH
                        weight = 50
                    elif cat == "UTILS":
                        level = ThreatLevel.CRITICAL if "powershell" in p.lower() else ThreatLevel.HIGH
                        weight = 100 if level == ThreatLevel.CRITICAL else 50

                    clean_p = p.replace('\\', '')
                    inds.append(ThreatIndicator(
                        indicator_id=f"BLOCK2.{cat}_{clean_p}",
                        level=level,
                        weight=weight,
                        description=f"Suspicious {cat} pattern found: {p}",
                        evidence=line,
                        location="VBA_SOURCE"
                    ))

        # 2. Обфускация (Chr конкатенация)
        chr_matches = re.findall(r'ChrW?\(\d+\)', vba_code, re.IGNORECASE)
        if len(chr_matches) >= 3:
             inds.append(ThreatIndicator(
                        indicator_id="BLOCK2.OBF_CHR_CONCAT",
                        level=ThreatLevel.HIGH,
                        weight=50,
                        description="VBA Obfuscation: many Chr() or ChrW() calls",
                        evidence=", ".join(chr_matches[:5]),
                        location="VBA_SOURCE"
                    ))

        # 3. Энтропия
        entropy = calculate_shannon_entropy(vba_code)
        if entropy > entropy_threshold:
             inds.append(ThreatIndicator(
                        indicator_id="BLOCK2.HIGH_ENTROPY",
                        level=ThreatLevel.LOW,
                        weight=5,
                        description=f"High entropy detected in VBA code ({entropy:.2f} bits)",
                        evidence=f"Entropy: {entropy:.2f}",
                        location="VBA_SOURCE"
                    ))

        # 4. Base64
        b64_finds = decode_base64_and_search(vba_code)
        for orig, dec in b64_finds:
             inds.append(ThreatIndicator(
                        indicator_id="BLOCK2.B64_MALICIOUS",
                        level=ThreatLevel.CRITICAL,
                        weight=100,
                        description="Base64 decoded to suspicious content",
                        evidence=dec[:100],
                        location="VBA_SOURCE"
                    ))

        result.success = True
        result.threat_indicators = inds
        result.raw_findings = {"entropy": entropy, "b64_decoded": [d for o,d in b64_finds]}

    except Exception as e:
        result.error_message = f"Error in Block 2: {str(e)}"
        logger.exception("Error in run_block2")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



