# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: office_analyzer.py
Назначение: Главная точка входа подсистемы Office Macro Security Analyzer (OMSA).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import argparse
import logging
import json
import time
from typing import Dict, List, Any

# Core
from core.logger import setup_logger
from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.config import *
from core.threat_evaluator import evaluate_threats

# Modules
from modules.block0_extraction import run_block0
from modules.block1_triage import run_block1
from modules.block2_vba_source import run_block2
from modules.block3_pcode import run_block3
from modules.block4_activex import run_block4
from modules.block5_metadata import run_block5
from modules.block6_ioc import run_block6

# Report
from report_generator import generate_text_report, save_json_results

def main():
    parser = argparse.ArgumentParser(description="Office Macro Security Analyzer v1.0 (Static Only)")
    parser.add_argument("file", nargs="?", help="Path to the Office file for analysis")
    parser.add_argument("--file", dest="file_opt", help="Path to the Office file for analysis (flag alias)")
    parser.add_argument("-o", "--output", "--output-dir", dest="output", help="Output directory for reports", default="./results")
    parser.add_argument("--offline", help="Disable external calls (VT)", action="store_true", default=OFFLINE_MODE)
    parser.add_argument("--vt-key", help="VirusTotal API Key", default=os.environ.get("OMSA_VT_API_KEY", ""))
    args = parser.parse_args()
    if not args.file and getattr(args, "file_opt", None):
        args.file = args.file_opt
    if not args.file:
        parser.error("the following arguments are required: file (or --file)")

    # 1. Setup output and logger
    timestamp = int(time.time())
    file_basename = os.path.basename(args.file).replace(" ", "_")
    output_dir = os.path.join(args.output, f"{file_basename}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    logger = setup_logger(output_dir, "ORCHESTRATOR")
    
    logger.info(f"Starting analysis of {args.file}")
    context: Dict[str, BlockResult] = {}
    all_threats = []
    
    try:
        # BLOCK 0 - Extraction
        logger.info("Executing Block 0: Extraction...")
        context["BLOCK0"] = run_block0(args.file, output_dir, MAX_FILE_SIZE_MB, MAX_EXTRACTED_SIZE_MB)
        if not context["BLOCK0"].success:
            logger.error(f"Block 0 failed: {context['BLOCK0'].error_message}")
            return
        all_threats.extend(context["BLOCK0"].threat_indicators)
        
        # BLOCK 1 - Triage
        logger.info("Executing Block 1: Triage (olevba/mraptor)...")
        context["BLOCK1"] = run_block1(args.file)
        all_threats.extend(context["BLOCK1"].threat_indicators)
        
        # BLOCK 2 - Source Code (VBA)
        vba_code = context["BLOCK1"].raw_findings.get("vba_code", "")
        # Извлекаем все декодированные строки из olevba (если есть)
        decoded_strings = context["BLOCK1"].raw_findings.get("decoded_strings", [])
        
        logger.info(f"Executing Block 2: Source Code Analysis ({len(vba_code)} symbols)...")
        context["BLOCK2"] = run_block2(vba_code, ENTROPY_THRESHOLD)
        all_threats.extend(context["BLOCK2"].threat_indicators)
        
        # BLOCK 3 - P-code (VBA Stomping)
        if context["BLOCK1"].raw_findings.get("vba_stomping"):
            logger.info("Executing Block 3: P-code Analysis (VBA Stomping Detected)...")
            vba_project_path = context["BLOCK0"].raw_findings.get("vba_project_bin")
            source_funcs = context["BLOCK2"].raw_findings.get("functions", [])
            if vba_project_path and os.path.exists(vba_project_path):
                context["BLOCK3"] = run_block3(vba_project_path, source_funcs)
                all_threats.extend(context["BLOCK3"].threat_indicators)
            else:
                logger.warning("vbaProject.bin not found for Block 3 analysis")
        
        # BLOCK 4 - ActiveX
        logger.info("Executing Block 4: ActiveX Analysis...")
        context["BLOCK4"] = run_block4(context["BLOCK0"].raw_findings.get("temp_dir", ""))
        all_threats.extend(context["BLOCK4"].threat_indicators)
        
        # BLOCK 5 - Metadata
        logger.info("Executing Block 5: Metadata Analysis...")
        context["BLOCK5"] = run_block5(context["BLOCK0"].raw_findings.get("temp_dir", ""))
        all_threats.extend(context["BLOCK5"].threat_indicators)
        
        # BLOCK 6 - IoC
        logger.info("Executing Block 6: IoC Extraction...")
        decoded = context["BLOCK2"].raw_findings.get("b64_decoded", [])
        context["BLOCK6"] = run_block6(vba_code, decoded, args.offline, args.vt_key)
        all_threats.extend(context["BLOCK6"].threat_indicators)
        
        # FINAL EVALUATION
        final_level, total_score, sorted_inds = evaluate_threats(all_threats)
        logger.info(f"Analysis complete. Final Level: {final_level.value}. Score: {total_score}")
        
        # REPORTS
        save_json_results(context, output_dir)
        report_path = generate_text_report(args.file, final_level, total_score, sorted_inds, context, output_dir)
        logger.info(f"Detailed report saved to: {report_path}")
        
        # Cleanup (Optional)
        if CLEANUP_TEMP:
            import shutil
            temp_dir = context["BLOCK0"].raw_findings.get("temp_dir", "")
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)
            
    except Exception as e:
        logger.exception(f"Fatal error in Orchestrator: {str(e)}")
    
if __name__ == "__main__":
    main()



