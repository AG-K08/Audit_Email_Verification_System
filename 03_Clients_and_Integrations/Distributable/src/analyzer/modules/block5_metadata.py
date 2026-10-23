# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block5_metadata.py
Назначение: Блок 5: Криминалистический анализ метаданных и временных меток.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import xml.etree.ElementTree as ET
import logging
import time
from datetime import datetime
from typing import Dict, Any
from core.models import BlockResult, ThreatIndicator, ThreatLevel

logger = logging.getLogger("BLOCK5")

def parse_xml_props(xml_path: str) -> Dict[str, str]:
    props = {}
    if not os.path.exists(xml_path):
        return props
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        # Пространства имен для OpenXML
        namespaces = {
            'cp': 'http://schemas.openxmlformats.org/package/2006/metadata/core-properties',
            'dc': 'http://purl.org/dc/elements/1.1/',
            'dcterms': 'http://purl.org/dc/terms/',
            'vt': 'http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes'
        }
        for prop in root:
            name = prop.tag.split('}')[-1]
            props[name] = prop.text
    except Exception as e:
        logger.error(f"Error parsing XML props {xml_path}: {str(e)}")
    return props

def run_block5(extracted_dir: str) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK5", success=False, execution_time_ms=0)
    
    try:
        core_xml = os.path.join(extracted_dir, "docProps", "core.xml")
        app_xml = os.path.join(extracted_dir, "docProps", "app.xml")
        
        core_props = parse_xml_props(core_xml)
        app_props = parse_xml_props(app_xml)
        
        inds = []
        
        # 1. Template Injection check (п.4.5 ТЗ)
        template = core_props.get("template", "")
        if "http://" in template.lower() or "https://" in template.lower() or template.startswith("\\\\"):
             inds.append(ThreatIndicator(
                indicator_id="BLOCK5.EXTERNAL_TEMPLATE_INJECTION",
                level=ThreatLevel.HIGH,
                weight=50,
                description="Template points to an external URL or UNC path (Template Injection)",
                evidence=template,
                location="docProps/core.xml"
            ))

        # 2. Date anomalies
        created_str = core_props.get("created", "")
        modified_str = core_props.get("modified", "")
        
        if created_str and modified_str:
            try:
                # 2026-03-18T10:04:00Z
                fmt = "%Y-%m-%dT%H:%M:%SZ"
                dt_created = datetime.strptime(created_str, fmt) if created_str else None
                dt_modified = datetime.strptime(modified_str, fmt) if modified_str else None
                
                if dt_created and datetime.now() < dt_created:
                    inds.append(ThreatIndicator(
                        indicator_id="BLOCK5.FUTURE_CREATION_DATE",
                        level=ThreatLevel.LOW,
                        weight=5,
                        description="Creation date is in the future",
                        evidence=created_str,
                        location="docProps/core.xml"
                    ))
            except:
                pass

        # 3. Revision check
        revision = core_props.get("revision", "0")
        try:
            if int(revision) == 1:
                # В ТЗ: Revision = 1 при объеме кода > 200 строк -> признак автогенерации (MEDIUM)
                # Это проверка для Блока 6 или при наличии контекста. Здесь просто фиксируем INFO.
                 inds.append(ThreatIndicator(
                        indicator_id="BLOCK5.REVISION_ONE",
                        level=ThreatLevel.INFO,
                        weight=0,
                        description="First revision of the document detected",
                        evidence=f"Revision: {revision}",
                        location="docProps/core.xml"
                    ))
        except:
             pass

        result.success = True
        result.threat_indicators = inds
        result.raw_findings = {
            "core": core_props,
            "app": app_props,
            "revision": revision,
            "template": template
        }

    except Exception as e:
        result.error_message = f"Error in Block 5: {str(e)}"
        logger.exception("Error in run_block5")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



