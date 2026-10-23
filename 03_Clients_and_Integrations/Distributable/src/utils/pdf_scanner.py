# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: pdf_scanner.py
Назначение: Глубокий анализ внутренней структуры PDF-документов.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
import subprocess
import tempfile
try:
    import extract_msg
except ImportError:
    extract_msg = None
import email
from email import policy
import shutil
from datetime import datetime

# ==========================================
# CONFIGURATION
# ==========================================
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[4]
TOOLS_DIR = str(PROJECT_ROOT / "Tools")

# Tool Paths
PDFID_PATH = os.path.join(TOOLS_DIR, "PDF", "pdfid.py")
if not os.path.exists(PDFID_PATH):
     PDFID_PATH = os.path.join(TOOLS_DIR, "pdfid-master", "pdfid", "pdfid.py")

PDFPARSER_PATH = os.path.join(TOOLS_DIR, "PDF", "pdf-parser.py")

PEEPDF_PATH = os.path.join(TOOLS_DIR, "peepdf-master", "peepdf.py")

# Target Directory
TARGET_DIR = str(PROJECT_ROOT / "06_Audit_Tests_and_Samples")

# Output Directory
REPORT_DIR = str(PROJECT_ROOT / "Reports" / "PDF_Deep_Scan")
EXTRACTED_DIR = str(PROJECT_ROOT / "Reports" / "Extracted_PDFs")

# ==========================================
# FUNCTIONS
# ==========================================

def print_banner():
    print("="*60)
    print("      PDF DEEP INSPECTOR TOOL (PDFiD + PDF-Parser + peepdf)")
    print("      With Email Attachment Extraction Support")
    print("="*60)

def ensure_dir(directory):
    if not os.path.exists(directory):
        os.makedirs(directory)

def _safe_pdf_filename(raw_fn: str) -> str:
    base_fn = os.path.basename(str(raw_fn).replace("\\", "/"))
    clean_fn = "".join(c for c in base_fn if c.isalnum() or c in (" ", ".", "_", "-")).strip(" .")
    if not clean_fn.lower().endswith(".pdf"):
        clean_fn += ".pdf"
    return clean_fn

def extract_attachments_from_msg(file_path, output_dir):
    extracted = []
    if extract_msg is None:
        return extracted
    msg = None
    try:
        output_dir_resolved = os.path.abspath(output_dir)
        msg = extract_msg.Message(file_path)
        for attachment in msg.attachments:
            raw_fn = attachment.getFilename() if hasattr(attachment, "getFilename") else getattr(attachment, "longFilename", None)
            if raw_fn and str(raw_fn).lower().endswith(".pdf") and getattr(attachment, "data", None):
                safe_fn = _safe_pdf_filename(raw_fn)
                save_path = os.path.abspath(os.path.join(output_dir_resolved, f"{os.path.basename(file_path)}_{safe_fn}"))
                if not (save_path == output_dir_resolved or save_path.startswith(output_dir_resolved + os.sep)):
                    continue
                with open(save_path, "wb") as f:
                    f.write(attachment.data)
                extracted.append(save_path)
    except Exception as e:
        print(f"[!] Error extracting from MSG {file_path}: {e}")
    finally:
        if msg is not None and hasattr(msg, "close"):
            try:
                msg.close()
            except Exception:
                pass
    return extracted

def extract_attachments_from_eml(file_path, output_dir):
    extracted = []
    try:
        output_dir_resolved = os.path.abspath(output_dir)
        with open(file_path, "rb") as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
            
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            if part.get('Content-Disposition') is None and not part.get_filename():
                continue
                
            filename = part.get_filename()
            if filename and str(filename).lower().endswith(".pdf"):
                safe_fn = _safe_pdf_filename(filename)
                save_path = os.path.abspath(os.path.join(output_dir_resolved, f"{os.path.basename(file_path)}_{safe_fn}"))
                if not (save_path == output_dir_resolved or save_path.startswith(output_dir_resolved + os.sep)):
                    continue
                payload = part.get_payload(decode=True)
                if payload:
                    with open(save_path, "wb") as f:
                        f.write(payload)
                    extracted.append(save_path)
    except Exception as e:
        print(f"[!] Error extracting from EML {file_path}: {e}")
    return extracted

def find_an_process_files(directory, extraction_dir):
    pdf_files = []
    
    # If target is a file, check its extension directly
    if os.path.isfile(directory):
        ext = directory.lower().split('.')[-1]
        if ext == 'pdf':
            pdf_files.append(directory)
        elif ext == 'msg':
            print(f"[*] Extracting PDFs from MSG: {os.path.basename(directory)}")
            pdfs = extract_attachments_from_msg(directory, extraction_dir)
            pdf_files.extend(pdfs)
        elif ext == 'eml':
            print(f"[*] Extracting PDFs from EML: {os.path.basename(directory)}")
            pdfs = extract_attachments_from_eml(directory, extraction_dir)
            pdf_files.extend(pdfs)
        return pdf_files
    
    # 1. Find existing PDFs
    for root, dirs, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            ext = file.lower().split('.')[-1]
            
            if ext == 'pdf':
                pdf_files.append(file_path)
            
            elif ext == 'msg':
                print(f"[*] Extracting PDFs from MSG: {file}")
                pdfs = extract_attachments_from_msg(file_path, extraction_dir)
                pdf_files.extend(pdfs)
            
            elif ext == 'eml':
                print(f"[*] Extracting PDFs from EML: {file}")
                pdfs = extract_attachments_from_eml(file_path, extraction_dir)
                pdf_files.extend(pdfs)
                
    return pdf_files

def run_tool(cmd, tool_name):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = result.stdout + "\n" + result.stderr
        return output
    except subprocess.TimeoutExpired:
        return f"[-] Timeout running {tool_name}"
    except Exception as e:
        return f"[-] Error running {tool_name}: {e}"

def main():
    print_banner()
    
    target = TARGET_DIR
    if len(sys.argv) > 1:
        target = sys.argv[1]

    if not os.path.exists(target):
        print(f"[!] Target directory not found: {target}")
        return

    ensure_dir(REPORT_DIR)
    ensure_dir(EXTRACTED_DIR)
    
    print(f"[*] Scanning directory: {target}")
    pdfs = find_an_process_files(target, EXTRACTED_DIR)
    print(f"[+] Found {len(pdfs)} PDF files to analyze (including extracted attachments).")
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_file = os.path.join(REPORT_DIR, f"PDF_SCAN_REPORT_{timestamp}.txt")
    
    with open(report_file, "w", encoding="utf-8") as f:
        f.write(f"PDF SCAN REPORT - {timestamp}\n")
        f.write(f"Source: {target}\n")
        f.write("="*60 + "\n\n")
        
        for pdf_path in pdfs:
            fname = os.path.basename(pdf_path)
            print(f"\n>>> Analyzing: {fname}")
            f.write(f"\n>>> FILE: {fname}\n")
            f.write(f"    Path: {pdf_path}\n")
            f.write("-" * 40 + "\n")
            
            # 1. PDFiD
            if os.path.exists(PDFID_PATH):
                f.write("[ TOOL: PDFiD ]\n")
                f.write(run_tool(["python", PDFID_PATH, pdf_path], "PDFiD"))
                f.write("\n" + "." * 40 + "\n")

            # 2. PDF-Parser (Search for JS)
            if os.path.exists(PDFPARSER_PATH):
                f.write("[ TOOL: PDF-Parser (JS Search) ]\n")
                f.write(run_tool(["python", PDFPARSER_PATH, "--search", "javascript", pdf_path], "PDF-Parser"))
                f.write("\n" + "." * 40 + "\n")

            # 3. peepdf
            if os.path.exists(PEEPDF_PATH):
                f.write("[ TOOL: peepdf ]\n")
                f.write(run_tool(["python", PEEPDF_PATH, "-fl", pdf_path], "peepdf"))
                f.write("\n" + "=" * 60 + "\n")
            
    print(f"\n[+] Analysis Complete. Report saved to:\n    {report_file}")
    # Optional: Cleanup extracted files
    # shutil.rmtree(EXTRACTED_DIR) 

if __name__ == "__main__":
    main()



