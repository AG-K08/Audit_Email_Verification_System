# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: metadata_hex_scanner.py
Назначение: Карвинг метаданных PDF, извлечение скрытых HEX-полезных нагрузок, поиск GPS-координат и подозрительных строк в бинарных потоках.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.1 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
import re
import binascii

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

try:
    import PyPDF2
except ImportError:
    PyPDF2 = None


class MetadataHexScanner:
    def __init__(self, target):
        self.target = target
        self.output_dir = "carved_metadata"
        if not os.path.exists(self.output_dir):
            os.makedirs(self.output_dir)

    def extract_hex_from_text(self, text):
        # Match 0xXX or raw HEX pairs if they look like a file header (FFD8...) or PE (4D5A...)
        hex_data = re.findall(r"0x([0-9A-Fa-f]{2})", text)
        if not hex_data:
            raw_match = re.search(r"((?:ffd8ff|4d5a90)[0-9a-fA-F]+)", text.lower())
            if raw_match:
                content = raw_match.group(1)
                if len(content) % 2 == 0:
                    return [content[i:i+2] for i in range(0, len(content), 2)]
        return hex_data

    def scan_pdf(self, file_path):
        print(f"[*] Analyzing PDF Metadata & Hidden HEX Streams: {os.path.basename(file_path)}")
        if not PyPDF2:
            print("  [i] Режим прямого парсинга метаданных PDF (Native Engine)...")
            try:
                with open(file_path, "rb") as f:
                    header_bytes = f.read(262144)
                meta_matches = re.findall(rb'/([A-Za-z]{3,20})\s*\((.*?)\)', header_bytes)
                all_hex_bytes = []
                for k, v in meta_matches:
                    key_str = k.decode('ascii', errors='ignore')
                    val_str = v.decode('utf-8', errors='ignore')
                    if key_str in ("Title", "Author", "Subject", "Keywords", "Creator", "Producer", "CreationDate", "ModDate"):
                        print(f"  [+] Metadata {key_str}: {val_str}")
                    extracted = self.extract_hex_from_text(val_str)
                    if extracted:
                        all_hex_bytes.extend(extracted)
                        print(f"  [!] HEX pattern found in {key_str}!")

                if all_hex_bytes:
                    hex_str = "".join(all_hex_bytes)
                    if len(hex_str) % 2 != 0:
                        hex_str = hex_str[:-1]
                    try:
                        payload = binascii.unhexlify(hex_str)
                        extracted_path = os.path.join(self.output_dir, f"carved_from_{os.path.basename(file_path)}.bin")
                        with open(extracted_path, "wb") as pf:
                            pf.write(payload)
                        print(f"  [+] SUCCESS: Carved hidden payload to {extracted_path}")
                        self.scan_file(extracted_path)
                    except Exception as hex_err:
                        print(f"  [-] Hex payload carving failed: {hex_err}")
            except Exception as e:
                print(f"  [-] Metadata extraction error: {e}")
            return

        try:
            with open(file_path, "rb") as f:
                reader = PyPDF2.PdfReader(f)
                meta = reader.metadata or {}

                all_hex_bytes = []
                for key, value in meta.items():
                    val_str = str(value)
                    extracted = self.extract_hex_from_text(val_str)
                    if extracted:
                        all_hex_bytes.extend(extracted)
                        print(f"  [!] HEX pattern found in {key}!")

                if all_hex_bytes:
                    hex_str = "".join(all_hex_bytes)
                    if len(hex_str) % 2 != 0:
                        hex_str = hex_str[:-1]
                    try:
                        payload = binascii.unhexlify(hex_str)
                        extracted_path = os.path.join(self.output_dir, f"carved_from_{os.path.basename(file_path)}.bin")
                        with open(extracted_path, "wb") as pf:
                            pf.write(payload)
                        print(f"  [+] SUCCESS: Carved hidden payload to {extracted_path}")
                        # Re-scan the carved file
                        self.scan_file(extracted_path)
                    except Exception as hex_err:
                        print(f"  [-] Hex payload carving failed: {hex_err}")
        except Exception as e:
            print(f"  [-] PDF Analysis Error: {e}")

    def scan_strings(self, file_path):
        print(f"[*] Searching for GPS coordinates and suspicious strings in: {os.path.basename(file_path)}")
        try:
            with open(file_path, "rb") as f:
                data = f.read()
                # 1. GPS Coordinates (e.g. 53.900598, 27.557982)
                gps_pattern = re.compile(br'(\d{1,3}\.\d{4,15},\s*\d{1,3}\.\d{4,15})')
                coords = gps_pattern.findall(data)
                for c in coords:
                    print(f"  [!!!] GPS COORDINATES FOUND: {c.decode(errors='ignore')}")

                # 2. Potential Shell/PowerShell/SQL/URLs
                susp_patterns = [
                    (br'powershell', "PowerShell execution indicator"),
                    (br'CreateObject', "COM Object creation (Macro-like)"),
                    (br'WScript', "Windows Script Host indicator"),
                    (br'http[s]?://', "Embedded URL"),
                    (br'SELECT .* FROM', "SQL Query pattern")
                ]

                # Use a strings-like approach for general inspection
                text_strings = re.findall(b'[ -~]{8,}', data)
                for s in text_strings:
                    decoded = s.decode(errors='ignore')
                    for pat, desc in susp_patterns:
                        if re.search(pat, s, re.IGNORECASE):
                            print(f"  [!] {desc}: {decoded[:80]}...")

        except Exception as e:
            print(f"  [-] String scanning error: {e}")

    def scan_file(self, file_path):
        ext = file_path.lower()
        if ext.endswith(".pdf"):
            self.scan_pdf(file_path)

        # General string scan for all files
        self.scan_strings(file_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python metadata_hex_scanner.py <file_or_dir>")
        sys.exit(1)

    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except AttributeError:
        pass

    scanner = MetadataHexScanner(sys.argv[1])

    if os.path.isdir(scanner.target):
        for root, _, files in os.walk(scanner.target):
            for f in files:
                try:
                    scanner.scan_file(os.path.join(root, f))
                except Exception as e:
                    print(f"  [!] CRITICAL ERROR scanning {f}: {e}")
    elif os.path.exists(scanner.target):
        scanner.scan_file(scanner.target)
    else:
        print(f"[-] Target {scanner.target} not found.")
