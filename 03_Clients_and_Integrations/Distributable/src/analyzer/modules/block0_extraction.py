# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block0_extraction.py
Назначение: Блок 0: Распаковка контейнеров и извлечение макросов.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import zipfile
import hashlib
import time
import logging
try:
    import olefile
except ImportError:
    olefile = None
from typing import List, Tuple, Dict
from core.models import BlockResult, ThreatIndicator, ThreatLevel

# Настройка локального логгера
logger = logging.getLogger("BLOCK0")

def get_hashes(filepath: str) -> Dict[str, str]:
    hashes = {}
    with open(filepath, 'rb') as f:
        data = f.read()
        hashes['md5'] = hashlib.md5(data).hexdigest()
        hashes['sha1'] = hashlib.sha1(data).hexdigest()
        hashes['sha256'] = hashlib.sha256(data).hexdigest()
    return hashes

def check_file_format(filepath: str) -> str:
    # Определение формата по magic bytes без внешних библиотек
    with open(filepath, 'rb') as f:
        magic = f.read(8)
        
    if magic.startswith(b'\xD0\xCF\x11\xE0'):
        return "OLE2"
    elif magic.startswith(b'\x50\x4B\x03\x04'):
        return "ZIP/OpenXML"
    else:
        return "UNKNOWN"

def safe_extract_zip(zip_path: str, extract_to: str, max_size_mb: int) -> List[str]:
    # Защита от Zip Slip и Zip Bomb
    extracted_files = []
    total_size = 0
    max_bytes = max_size_mb * 1024 * 1024
    
    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.infolist():
            # Zip Slip check
            filename = member.filename
            if ".." in filename or filename.startswith("/") or filename.startswith("\\") or ":" in filename:
                raise ValueError(f"Zip Slip detected in member: {filename}")
            
            # Zip Bomb check
            total_size += member.file_size
            if total_size > max_bytes:
                raise ValueError("Potential Zip Bomb: total extracted size exceeds limit")
                
            # Извлекаем только если безопасно
            zf.extract(member, extract_to)
            extracted_files.append(os.path.join(extract_to, filename))
            
    return extracted_files

def extract_ole_streams(filepath: str, extract_to: str) -> List[str]:
    # Извлечение OLE потоков
    extracted_files = []
    if olefile is None or not olefile.isOleFile(filepath):
        return []
        
    ole = olefile.OleFileIO(filepath)
    ole_storage_dir = os.path.join(extract_to, "ole_streams")
    os.makedirs(ole_storage_dir, exist_ok=True)
    
    for stream in ole.listdir():
        stream_name = "_".join(stream)
        data = ole.openstream(stream).read()
        output_path = os.path.join(ole_storage_dir, stream_name)
        with open(output_path, 'wb') as f:
            f.write(data)
        extracted_files.append(output_path)
    
    ole.close()
    return extracted_files

def run_block0(filepath: str, output_dir: str, max_file_size_mb: int, max_extracted_size_mb: int) -> BlockResult:
    start_time = int(time.time() * 1000)
    result = BlockResult(block_name="BLOCK0", success=False, execution_time_ms=0)
    
    try:
        # 1. Проверка существования и размера
        if not os.path.exists(filepath):
            result.error_message = f"File not found: {filepath}"
            return result
            
        file_size_mb = os.path.getsize(filepath) / (1024 * 1024)
        if file_size_mb > max_file_size_mb:
            result.error_message = f"File too large: {file_size_mb:.2f} MB"
            result.threat_indicators.append(ThreatIndicator(
                indicator_id="BLOCK0.SIZE_LIMIT",
                level=ThreatLevel.CRITICAL,
                weight=100,
                description=f"File size exceeds limit ({max_file_size_mb} MB)",
                evidence=f"{file_size_mb:.2f} MB",
                location=filepath
            ))
            return result
        
        # 2. Формат и хеши
        fmt = check_file_format(filepath)
        hashes = get_hashes(filepath)
        
        # 3. Извлечение
        temp_extract_dir = os.path.join(output_dir, "extracted")
        os.makedirs(temp_extract_dir, exist_ok=True)
        
        extracted_paths = []
        if fmt == "ZIP/OpenXML":
            extracted_paths = safe_extract_zip(filepath, temp_extract_dir, max_extracted_size_mb)
        elif fmt == "OLE2":
            extracted_paths = extract_ole_streams(filepath, temp_extract_dir)
            
        # 4. Результаты
        result.success = True
        result.raw_findings = {
            "format": fmt,
            "hashes": hashes,
            "file_size_mb": file_size_mb,
            "extracted_files_count": len(extracted_paths),
            "temp_dir": temp_extract_dir
        }
        
        # Поиск vbaProject.bin для следующих блоков
        for p in extracted_paths:
            if "vbaProject.bin" in p:
                result.raw_findings["vba_project_bin"] = p
                break
                
    except Exception as e:
        result.error_message = f"Critical error in Block 0: {str(e)}"
        logger.exception("Error in run_block0")
        
    finally:
        result.execution_time_ms = int(time.time() * 1000) - start_time
        
    return result



