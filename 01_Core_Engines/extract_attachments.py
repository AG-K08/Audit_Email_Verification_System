# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: extract_attachments.py
Назначение: Автоматическое безопасное извлечение всех вложений из EML / MSG.
"""
import os
import sys
import email
from email import policy
from pathlib import Path

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def extract_all(target_file: str, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    try:
        with open(target_file, 'rb') as f:
            msg = email.message_from_binary_file(f, policy=policy.default)
        count = 0
        for part in msg.walk():
            if part.is_multipart():
                continue
            fn = part.get_filename()
            if fn:
                # Защита от Path Traversal в имени вложения
                base_fn = os.path.basename(fn.replace("\\", "/"))
                clean_fn = "".join(c for c in base_fn if c.isalnum() or c in (" ", ".", "_", "-")).strip()
                if not clean_fn or clean_fn.startswith("."):
                    clean_fn = f"attachment_{count}.bin"
                dst = os.path.abspath(os.path.join(out_dir, clean_fn))
                # Гарантия, что путь находится строго внутри out_dir
                if not dst.startswith(os.path.abspath(out_dir)):
                    dst = os.path.join(out_dir, f"attachment_{count}.bin")
                payload = part.get_payload(decode=True) or b""
                with open(dst, 'wb') as out_f:
                    out_f.write(payload)
                print(f"  [+] Извлечено вложение: {clean_fn} ({len(payload)} байт)")
                count += 1
        print(f"[OK] Всего успешно извлечено объектов: {count}")
    except Exception as e:
        print(f"[ERROR] Ошибка извлечения вложений: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Использование: python extract_attachments.py <eml_file> <out_dir>")
        sys.exit(1)
    extract_all(sys.argv[1], sys.argv[2])
