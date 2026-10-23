# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: analyze_attachments.py
Назначение: Пакетный статический скрининг вложений (PDF, Office, архивы) на признаки атак.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""

import os
import sys

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import email
from email import policy
from email.parser import BytesParser
import hashlib
import re
import zipfile
import io
import shutil
from pathlib import Path

# Динамическое определение рабочих директорий
PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CASES_DIR = PROJECT_ROOT / "06_Audit_Tests_and_Samples"
DEFAULT_REPORTS_DIR = PROJECT_ROOT / "Reports"
CASES_DIR = str(DEFAULT_CASES_DIR)
REPORTS_DIR = str(DEFAULT_REPORTS_DIR)
os.makedirs(REPORTS_DIR, exist_ok=True)
OUTPUT_FILE = os.path.join(REPORTS_DIR, "attachment_analysis_report.md")

SUSPICIOUS_EXTENSIONS = {
    '.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.pif', '.hta', '.cpl', '.msc', '.msi', '.ps1', '.wsf', '.jar'
}

DANGEROUS_ARCHIVE_EXTENSIONS = SUSPICIOUS_EXTENSIONS

def get_hashes(content):
    h_md5 = hashlib.md5(content).hexdigest()
    h_sha256 = hashlib.sha256(content).hexdigest()
    return h_md5, h_sha256

def check_pdf(content):
    findings = []
    content_str = content.decode('latin-1', errors='ignore') # PDF is mostly binary but keywords are ASCII
    
    keywords = {
        '/JavaScript': "Contains JavaScript",
        '/JS': "Contains JavaScript",
        '/OpenAction': "Auto-open action",
        '/Launch': "Executes command",
        '/URI': "External Link"
    }
    
    for kw, desc in keywords.items():
        if kw in content_str:
            findings.append(desc)
            
    return findings

def check_office_xml(content):
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            file_list = z.namelist()
            if 'xl/vbaProject.bin' in file_list or 'word/vbaProject.bin' in file_list:
                findings.append("Contains VBA Macros")
    except:
        pass # Not a valid zip or encrypted
    return findings

def check_zip(content):
    findings = []
    try:
        with zipfile.ZipFile(io.BytesIO(content)) as z:
            infos = z.infolist()
            total_size = sum(f.file_size for f in infos)
            if total_size > 100 * 1024 * 1024 or len(infos) > 2000:
                findings.append(f"Zip bomb risk (uncompressed size: {total_size} bytes, files: {len(infos)})")
            for file_info in infos:
                fn = file_info.filename
                if ".." in fn or fn.startswith(("/", "\\")):
                    findings.append(f"Zip Slip / Path Traversal detected: {fn}")
                ext = os.path.splitext(fn)[1].lower()
                if ext in DANGEROUS_ARCHIVE_EXTENSIONS:
                    findings.append(f"Contains executable: {fn}")
    except Exception:
        pass # encrypted or creating read error
    return findings

def analyze_attachment(filename, content):
    verdict = "Clean"
    details = []
    ext = os.path.splitext(filename)[1].lower()

    # Double extension check
    if re.search(r'\.[a-z0-9]{2,4}\.(exe|scr|vbs|js)$', filename.lower()):
        verdict = "Malicious"
        details.append("Double extension detected")

    # Extension check
    if ext in SUSPICIOUS_EXTENSIONS:
        verdict = "Malicious"
        details.append(f"Dangerous extension: {ext}")

    # Content checks based on extension
    if ext == '.pdf':
        pdf_findings = check_pdf(content)
        if pdf_findings:
            verdict = "Suspicious"
            details.extend(pdf_findings)
            
    elif ext in ['.docx', '.xlsx', '.pptx', '.docm', '.xlsm', '.pptm']:
        office_findings = check_office_xml(content)
        if office_findings:
            verdict = "Suspicious"
            details.extend(office_findings)
            
    elif ext == '.zip':
        zip_findings = check_zip(content)
        if zip_findings:
            verdict = "Suspicious"
            details.extend(zip_findings)

    return verdict, ", ".join(details)

def process_eml(file_path):
    results = []
    try:
        with open(file_path, 'rb') as f:
            msg = BytesParser(policy=policy.default).parse(f)
        
        for part in msg.iter_attachments():
            filename = part.get_filename()
            if filename:
                content = part.get_content()
                if isinstance(content, str):
                    content = content.encode('utf-8')
                
                md5, sha256 = get_hashes(content)
                verdict, details = analyze_attachment(filename, content)
                
                if verdict != "Clean":
                    results.append({
                        "file": os.path.basename(file_path),
                        "attachment": filename,
                        "verdict": verdict,
                        "details": details,
                        "md5": md5
                    })
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        
    return results

def main():
    target_path = sys.argv[1] if len(sys.argv) > 1 else CASES_DIR
    target_p = Path(target_path)
    
    reports_dir = Path(REPORTS_DIR)
    reports_dir.mkdir(parents=True, exist_ok=True)
        
    all_suspicious_attachments = []
    
    if target_p.is_file():
        files = [target_p]
        scan_dir_repr = str(target_p.parent)
    elif target_p.is_dir():
        files = [f for f in target_p.glob("*.eml")]
        scan_dir_repr = str(target_p)
    else:
        print(f"[!] Указанный путь не найден: {target_path}")
        return

    total_files = len(files)
    print(f"Scanning target: {scan_dir_repr} ({total_files} .eml files)...")
    
    for i, file_p in enumerate(files):
        if i % 100 == 0 and i > 0:
            print(f"Processed {i}/{total_files} files...")
            
        findings = process_eml(str(file_p))
        all_suspicious_attachments.extend(findings)

    # Generate Report
    with open(OUTPUT_FILE, 'w', encoding='utf-8') as f:
        f.write("# Attachment Security Analysis Report\n\n")
        f.write(f"Total Emails Scanned: {total_files}\n")
        f.write(f"Suspicious Attachments Found: {len(all_suspicious_attachments)}\n\n")
        
        f.write("| Source Email | Attachment | Verdict | Details | MD5 |\n")
        f.write("|---|---|---|---|---|\n")
        
        for item in all_suspicious_attachments:
            # Escape pipes in names
            email_name = item['file'].replace('|', 'I')
            att_name = item['attachment'].replace('|', 'I')
            f.write(f"| {email_name} | {att_name} | **{item['verdict']}** | {item['details']} | {item['md5']} |\n")
            
    print(f"\nAnalysis complete. Report saved to: {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
