# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: full_doc_scan.py
Назначение: Быстрый статический разбор структуры документов OLE2/OpenXML.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import re
import sys
import hashlib
import binascii

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def get_hashes(file_path):
    with open(file_path, 'rb') as f:
        data = f.read()
    return hashlib.md5(data).hexdigest(), hashlib.sha256(data).hexdigest(), data

def check_vba_api(data):
    api_list = [
        b'CreateObject', b'Shell', b'WScript', b'powershell', b'cmd.exe',
        b'URLDownloadToFile', b'XMLHTTP', b'WinHttp', b'certutil', b'mshta'
    ]
    found = []
    for api in api_list:
        if api in data:
            found.append(api.decode("ascii", errors="ignore"))
    return found

def check_gps(data):
    # Pattern for NN.NNNN, NN.NNNN
    coords = re.findall(rb'(\d{1,2}\.\d{4,6},\s?\d{1,2}\.\d{4,6})', data)
    return [c.decode("utf-8", errors="ignore") for c in coords]

def check_hex_injection(data):
    # Pattern for 0xXX, 0xXX... or XX XX XX
    p1 = re.findall(rb'(0x[0-9a-fA-F]{2},\s?0x[0-9a-fA-F]{2})', data)
    return len(p1) > 5

def analyze_doc(path):
    md5, sha256, data = get_hashes(path)
    print(f"MD5: {md5}")
    print(f"SHA256: {sha256}")
    
    # 1. Format
    if data.startswith(b'\xd0\xcf\x11\xe0'):
        print("[+] Format: OLE (Legacy Doc)")
    elif data.startswith(b'PK\x03\x04'):
        print("[+] Format: OpenXML (Modern Docx/Xlsx)")
    
    # 2. VBA/Macros
    if b'vbaProject' in data or b'AutoOpen' in data or b'Document_Open' in data:
        print("[!] ALERT: VBA/Macro elements detected.")
    
    # 3. OLE Objects
    if b'Ole10Native' in data or b'Package' in data or b'Equation' in data:
        print("[!] ALERT: Embedded OLE objects / Equation detected (CVE risk).")
    
    # 4. APIs
    apis = check_vba_api(data)
    if apis:
        print(f"[!] DANGEROUS APIs: {', '.join(apis)}")
    
    # 5. URLs
    urls = re.findall(rb'https?://[^\s\"\'\>]+', data)
    for u in urls:
        print(f"[+] Found URL: {u.decode('utf-8', errors='ignore')}")
        
    # 6. GPS
    gps = check_gps(data)
    if gps:
        print(f"[!] GPS COORDS FOUND: {', '.join(gps)}")
        
    # 7. HEX Injection
    if check_hex_injection(data):
        print("[!] HIGH PROBABILITY of HEX Injection (encoded payload).")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python full_doc_scan.py <doc>")
        sys.exit(1)
    target_path = sys.argv[1]
    if not os.path.exists(target_path):
        print(f"[-] File not found: {target_path}")
        sys.exit(1)
    analyze_doc(target_path)
