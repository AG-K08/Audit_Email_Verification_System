# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: parse_eml_detailed.py
Назначение: Детальный синтаксический разбор структуры MIME/RFC822.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
import email
from email import policy
from email.header import decode_header
import hashlib
import re
import math

from pathlib import Path

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EML = PROJECT_ROOT / "06_Audit_Tests_and_Samples" / "test.eml"

def decode_mime(text):
    if not text: return ""
    try:
        dh = decode_header(text)
        decoded = []
        for part, encoding in dh:
            if isinstance(part, bytes):
                decoded.append(part.decode(encoding or 'utf-8', errors='ignore'))
            else:
                decoded.append(str(part))
        return "".join(decoded)
    except Exception as e:
        return str(text)

def calculate_hashes(data):
    md5_hash = hashlib.md5(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()
    return md5_hash, sha256_hash

def calculate_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for i in range(256):
        p_x = float(data.count(i))/len(data)
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def main():
    eml_path = sys.argv[1] if len(sys.argv) > 1 else str(DEFAULT_EML)
    out_dir = sys.argv[2] if len(sys.argv) > 2 else str(Path(eml_path).parent / f"Extracted_{Path(eml_path).stem}")
    os.makedirs(out_dir, exist_ok=True)

    print(f"[*] Reading EML: {eml_path}")
    if not os.path.exists(eml_path):
        print(f"[!] File not found: {eml_path}")
        sys.exit(1)
        
    with open(eml_path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)
        
    print("\n" + "="*40)
    print("EMAIL HEADERS")
    print("="*40)
    print(f"Subject:     {decode_mime(msg['Subject'])}")
    print(f"From:        {msg['From']}")
    print(f"To:          {msg['To']}")
    print(f"Date:        {msg['Date']}")
    print(f"Reply-To:    {msg['Reply-To']}")
    print(f"Return-Path: {msg['Return-Path']}")
    print(f"Message-ID:  {msg['Message-ID']}")
    
    auth_results = msg.get_all("Authentication-Results", [])
    print(f"\nAuthentication-Results:")
    for auth in auth_results:
        print(f"  {auth}")
        
    print("\nReceived Headers:")
    received = msg.get_all("Received", [])
    for rec in received:
        print(f"  {rec.strip()}")
        
    # Body and Links
    body_text = ""
    body_html = ""
    for part in msg.walk():
        if part.get_content_type() == "text/plain":
            payload = part.get_payload(decode=True)
            if payload:
                body_text += payload.decode(errors='ignore')
        elif part.get_content_type() == "text/html":
            payload = part.get_payload(decode=True)
            if payload:
                body_html += payload.decode(errors='ignore')
                
    print("\n" + "="*40)
    print("EMAIL BODY SNIPPETS")
    print("="*40)
    if body_text:
        print("--- PLAIN TEXT ---")
        print(body_text[:1000] + ("\n...[TRUNCATED]" if len(body_text) > 1000 else ""))
    if body_html:
        print("\n--- HTML CONTENT ---")
        print(body_html[:1000] + ("\n...[TRUNCATED]" if len(body_html) > 1000 else ""))
        
    # Extract links from both body text and html
    all_body = body_text + "\n" + body_html
    links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', all_body)
    unique_links = sorted(list(set(links)))
    
    print("\n" + "="*40)
    print("DETECTED LINKS")
    print("="*40)
    if unique_links:
        for link in unique_links:
            print(f"- {link}")
    else:
        print("No links found.")
        
    # Attachments
    print("\n" + "="*40)
    print("ATTACHMENTS ANALYSIS")
    print("="*40)
    attachments_found = False
    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        if part.get('Content-Disposition') is None and not part.get_filename():
            continue
            
        filename = part.get_filename()
        if filename:
            attachments_found = True
            filename = decode_mime(filename)
            # Sanitize filename (защита от Path Traversal)
            base_fn = os.path.basename(filename.replace("\\", "/"))
            clean_fn = "".join([c for c in base_fn if c.isalnum() or c in (" ", ".", "_", "-")]).strip()
            if not clean_fn or clean_fn.startswith("."):
                clean_fn = "attachment.bin"
            filename = clean_fn
                
            payload = part.get_payload(decode=True)
            if payload:
                size = len(payload)
                md5, sha256 = calculate_hashes(payload)
                entropy = calculate_entropy(payload)
                
                # Check magic bytes
                magic = payload[:4]
                magic_hex = magic.hex()
                magic_desc = "Unknown"
                if magic.startswith(b"PK\x03\x04"):
                    magic_desc = "ZIP / Office OpenXML (docx/xlsx/xlsm/...)"
                elif magic.startswith(b"\xD0\xCF\x11\xE0"):
                    magic_desc = "OLE2 / MS Office Binary (doc/xls/...)"
                elif magic.startswith(b"%PDF"):
                    magic_desc = "PDF Document"
                elif magic.startswith(b"MZ"):
                    magic_desc = "PE Executable (exe/dll/...)"
                elif magic.startswith(b"\x7FELF"):
                    magic_desc = "ELF Linux Executable"
                    
                print(f"\nAttachment: {filename}")
                print(f"  Size:      {size} bytes")
                print(f"  MD5:       {md5}")
                print(f"  SHA256:    {sha256}")
                print(f"  Entropy:   {entropy:.4f}")
                print(f"  Magic (4): {magic_hex} ({magic_desc})")
                
                out_dir_resolved = os.path.abspath(out_dir)
                out_path = os.path.abspath(os.path.join(out_dir_resolved, filename))
                if not (out_path == out_dir_resolved or out_path.startswith(out_dir_resolved + os.sep)):
                    out_path = os.path.join(out_dir_resolved, "attachment_safe.bin")
                with open(out_path, "wb") as out_f:
                    out_f.write(payload)
                print(f"  [+] Saved to: {out_path}")
                
    if not attachments_found:
        print("No attachments found.")

if __name__ == "__main__":
    main()
