# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: string_extractor.py
Назначение: Извлечение закодированных строк Base64 и HEX полезной нагрузки.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import re
import os

def find_b64(path):
    # Regex for potential base64 (min length 16)
    b64_pattern = rb'[a-zA-Z0-9+/]{16,}(?:==)?'
    try:
        with open(path, 'rb') as f:
            data = f.read()
        matches = re.findall(b64_pattern, data)
        if matches:
            print(f"Found {len(matches)} potential B64 strings in {os.path.basename(path)}")
            for m in matches[:5]:
                try:
                    s = m.decode()
                    print(f"  - {s[:50]}...")
                except: pass
    except: pass

if __name__ == "__main__":
    import sys
    from pathlib import Path
    default_target = Path(__file__).resolve().parents[4] / "06_Audit_Tests_and_Samples" / "test.eml"
    target = sys.argv[1] if len(sys.argv) > 1 else str(default_target)
    if os.path.exists(target):
        find_b64(target)



