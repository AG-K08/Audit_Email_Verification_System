# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: archive_extractor.py
Назначение: Безопасное извлечение архивов с защитой от Zip-Bomb.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
try:
    import extract_msg
except ImportError:
    extract_msg = None
import zipfile

def main():
    if len(sys.argv) < 3:
        print("Usage: python archive_extractor.py <file_path> <out_dir>")
        return
    
    file_path = sys.argv[1]
    out_dir = sys.argv[2]
    
    if not os.path.exists(out_dir):
        os.makedirs(out_dir)
        
    out_dir_resolved = os.path.abspath(out_dir)
    ext = file_path.lower().split('.')[-1]
    
    if ext == 'msg':
        if extract_msg is None:
            print("Error extracting MSG: extract_msg is not installed")
            return
        msg = None
        try:
            msg = extract_msg.Message(file_path)
            for attr in msg.attachments:
                raw_fn = attr.getFilename() if hasattr(attr, "getFilename") else getattr(attr, "longFilename", None)
                if raw_fn and getattr(attr, "data", None):
                    base_fn = os.path.basename(str(raw_fn).replace("\\", "/"))
                    clean_fn = "".join(c for c in base_fn if c.isalnum() or c in (" ", ".", "_", "-")).strip()
                    if not clean_fn or clean_fn.startswith("."):
                        clean_fn = "attachment.bin"
                    f_path = os.path.abspath(os.path.join(out_dir_resolved, clean_fn))
                    if not (f_path == out_dir_resolved or f_path.startswith(out_dir_resolved + os.sep)):
                        continue
                    with open(f_path, 'wb') as f:
                        f.write(attr.data)
                    print(f"Extracted: {clean_fn}")
        except Exception as e:
            print(f"Error extracting MSG: {e}")
        finally:
            if msg is not None and hasattr(msg, "close"):
                try:
                    msg.close()
                except Exception:
                    pass
            
    elif ext in ('docx', 'xlsx', 'pptx', 'zip'):
        try:
            with zipfile.ZipFile(file_path, 'r') as z:
                total_sz = 0
                for info in z.infolist():
                    name = info.filename
                    total_sz += info.file_size
                    if total_sz > 100 * 1024 * 1024:
                        print("Warning: Max extraction limit reached (100MB)")
                        break
                    # Extract images or embedded objects
                    if 'media/' in name or 'embeddings/' in name:
                        base_name = os.path.basename(name.replace("\\", "/"))
                        clean_name = "".join(c for c in base_name if c.isalnum() or c in (" ", ".", "_", "-")).strip()
                        if clean_name and not clean_name.startswith("."):
                            f_path = os.path.abspath(os.path.join(out_dir_resolved, clean_name))
                            if not (f_path == out_dir_resolved or f_path.startswith(out_dir_resolved + os.sep)):
                                continue
                            with open(f_path, 'wb') as f:
                                f.write(z.read(info))
                            print(f"Extracted: {clean_name}")
        except Exception as e:
            print(f"Error extracting ZIP/Office: {e}")
            
    elif ext == 'pdf':
        # PDF carving can be done using image_carver or other tools, but we can also do basic image carving here
        pass

if __name__ == "__main__":
    main()
