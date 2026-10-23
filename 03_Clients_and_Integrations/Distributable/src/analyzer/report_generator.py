# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: report_generator.py
Назначение: Генератор структурированных отчетов OMSA (JSON, TXT, Markdown).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import json
import os
from typing import List, Dict, Any
from core.models import ThreatLevel, ThreatIndicator, BlockResult

def generate_text_report(filepath: str, final_level: ThreatLevel, total_weight: int, indicators: List[ThreatIndicator], context: Dict[str, BlockResult], output_dir: str):
    report_file = os.path.join(output_dir, "report.txt")
    
    with open(report_file, "w", encoding='utf-8') as f:
        f.write("=== OFFICE MACRO SECURITY ANALYZER V1.0 ===\n")
        f.write(f"File: {os.path.basename(filepath)}\n")
        f.write(f"Final Threat Level: {final_level.value}\n")
        f.write(f"Total Threat Score: {total_weight}\n")
        f.write("-" * 40 + "\n\n")
        
        f.write("1. THREAT INDICATORS (TOP):\n")
        for ind in indicators[:10]: # Top 10
            f.write(f"[{ind.level.value}] ({ind.weight}) {ind.indicator_id}\n")
            f.write(f"   Desc: {ind.description}\n")
            f.write(f"   Evidence: {ind.evidence[:100]}...\n")
            f.write(f"   Loc: {ind.location}\n")
            f.write("-" * 20 + "\n")
            
        f.write("\n2. IOC SUMMARY:\n")
        # Извлекаем IoC из Блока 6
        if "BLOCK6" in context:
             iocs = context["BLOCK6"].raw_findings.get("iocs", {})
             for k, v in iocs.items():
                 if v:
                     f.write(f"- {k}: {', '.join(v[:10])}\n")
        
        f.write("\n3. BLOCK EXECUTION LOGS:\n")
        for b_name, b_res in context.items():
            f.write(f"- [{b_name}] Success: {b_res.success}, Time: {b_res.execution_time_ms}ms\n")
            if not b_res.success:
                f.write(f"   Error: {b_res.error_message}\n")
                
    return report_file

def save_json_results(context: Dict[str, BlockResult], output_dir: str):
    for b_name, b_res in context.items():
        json_file = os.path.join(output_dir, f"{b_name.lower()}.json")
        with open(json_file, "w", encoding='utf-8') as f:
            json.dump(b_res.dict(), f, indent=4, ensure_ascii=False)



