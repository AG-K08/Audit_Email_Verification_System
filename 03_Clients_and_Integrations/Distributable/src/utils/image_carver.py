# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: image_carver.py
Назначение: Карвинг и проверка графических объектов на стеганографию.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import re
import sys

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

def carve(file_path, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    signatures = {
        'jpg': (b'\xff\xd8\xff', b'\xff\xd9'),
        'png': (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', b'\x49\x45\x4e\x44\xae\x42\x60\x82'),
        'gif': (b'GIF87a', b'\x00\x3b'),
        'gif89': (b'GIF89a', b'\x00\x3b'),
        'bmp': (b'BM', None), # BMP has no specific trailer, size is in header
        'emf': (b'\x01\x00\x00\x00', None),
        'pdf': (b'%PDF', b'%%EOF')
    }
    
    try:
        with open(file_path, 'rb') as f:
            data = f.read()
    except Exception as e:
        print(f"[-] Ошибка чтения файла {file_path}: {e}")
        return
    
    count = 0
    max_carved = 500  # Защита от переполнения диска
    for name, (start, end) in signatures.items():
        if count >= max_carved:
            print(f"[!] Достигнут лимит извлеченных объектов ({max_carved}). Остановка карвинга.")
            break
        start_indices = [m.start() for m in re.finditer(re.escape(start), data)]
        for s_idx in start_indices:
            if count >= max_carved:
                break
            if end:
                e_match = re.search(re.escape(end), data[s_idx:])
                if e_match:
                    e_idx = s_idx + e_match.end()
                    img_data = data[s_idx:e_idx]
                    out_path = os.path.join(out_dir, f"carved_{count}.{name.strip('89')}")
                    try:
                        with open(out_path, 'wb') as img_f:
                            img_f.write(img_data)
                        count += 1
                    except Exception as e:
                        print(f"[-] Ошибка записи {out_path}: {e}")
            else:
                # For BM/EMF just dump a chunk (basic carving)
                img_data = data[s_idx:s_idx+1000000] # Max 1MB
                out_path = os.path.join(out_dir, f"carved_{count}.{name}")
                try:
                    with open(out_path, 'wb') as img_f:
                        img_f.write(img_data)
                    count += 1
                except Exception as e:
                    print(f"[-] Ошибка записи {out_path}: {e}")
    
    print(f"Total carved objects: {count}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python carve_images.py <file>")
    else:
        carve(sys.argv[1], "carved_output")



