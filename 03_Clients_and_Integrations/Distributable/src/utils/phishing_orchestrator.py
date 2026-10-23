# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: phishing_orchestrator.py
Назначение: Оркестратор комплексного анализа фишинговых писем.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
import email
import subprocess
import shutil
import hashlib
import re
import tempfile
from email.header import decode_header

# --- Configuration & Paths ---
# В дистрибутиве все утилиты находятся в той же папке
UTILS_DIR = os.path.dirname(os.path.abspath(__file__))
PDF_FORENSICS = os.path.join(UTILS_DIR, "pdf_scanner.py")
MEDIA_FORENSICS = os.path.join(UTILS_DIR, "image_carver.py") # Note: renamed or same logic
CONTENT_EXTRACTOR = os.path.join(UTILS_DIR, "archive_extractor.py")
_DEFAULT_YARA = os.path.join(os.path.dirname(UTILS_DIR), "rules", "professional_threats.yar")
if not os.path.exists(_DEFAULT_YARA):
    _DEFAULT_YARA = os.path.abspath(os.path.join(UTILS_DIR, "..", "..", "..", "..", "04_Detection_Rules", "professional_threats.yar"))
YARA_RULES = _DEFAULT_YARA

class PhishingOrchestrator:
    def __init__(self, target):
        self.target = target
        self.report_data = {
            "email": {},
            "attachments": [],
            "overall_verdict": "CLEAN",
            "warnings": [],
            "yara_hits": []
        }
        # Create a unique, isolated temporary directory for this run
        self.temp_dir = tempfile.mkdtemp(prefix="phish_orch_")
        
        # Load analysis cache (Step 3: Hash Caching)
        import json
        self.cache_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_cache.json")
        self.cache = {}
        if os.path.exists(self.cache_path):
            try:
                with open(self.cache_path, "r", encoding="utf-8") as f:
                    self.cache = json.load(f)
            except Exception as e:
                print(f"[-] Failed to load cache: {e}")

    def save_cache(self):
        import json
        try:
            with open(self.cache_path, "w", encoding="utf-8") as f:
                json.dump(self.cache, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[-] Failed to save cache: {e}")

    def log_warning(self, msg, severity="SUSPICIOUS"):
        print(f"[!] {msg}")
        self.report_data["warnings"].append(msg)
        if severity == "MALICIOUS":
            self.report_data["overall_verdict"] = "MALICIOUS"
        elif self.report_data["overall_verdict"] != "MALICIOUS":
            self.report_data["overall_verdict"] = "SUSPICIOUS"

    def run_tool(self, cmd):
        # Try running with python if it's a script
        if cmd[0].endswith('.py'):
            cmd = [sys.executable] + cmd
            
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            return res.stdout + "\n" + res.stderr
        except Exception as e:
            return f"Error running {' '.join(cmd)}: {e}"

    def decode_mime(self, text):
        if not text: return ""
        # Handle RFC 2231 tuple parameter: (charset, language, value)
        if isinstance(text, tuple):
            if len(text) == 3:
                text = text[2]
            elif len(text) > 0:
                text = text[0]
        # In case it's any other non-string iterable
        if not isinstance(text, str):
            text = str(text)

        try:
            dh = decode_header(text)
            decoded = []
            for part, encoding in dh:
                if isinstance(part, bytes):
                    decoded.append(part.decode(encoding or 'utf-8', errors='ignore'))
                else:
                    decoded.append(str(part))
            return "".join(decoded)
        except:
            return str(text)

    def analyze_email(self, eml_path):
        print(f"[*] Stage 1: Email Forensic - {os.path.basename(eml_path)}")
        try:
            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f)
            
            # Headers
            self.report_data["email"]["subject"] = self.decode_mime(msg.get("Subject", "No Subject"))
            self.report_data["email"]["from"] = msg.get("From")
            self.report_data["email"]["to"] = msg.get("To")
            self.report_data["email"]["date"] = msg.get("Date")
            
            # Auth Check (SPF/DKIM)
            auth_results = msg.get("Authentication-Results", "")
            self.report_data["email"]["spf"] = "PASS" if "spf=pass" in auth_results.lower() else "UNKNOWN"
            self.report_data["email"]["dkim"] = "PASS" if "dkim=pass" in auth_results.lower() else "NONE"
            
            if self.report_data["email"]["dkim"] == "NONE":
                self.log_warning("DKIM signature missing or invalid.")

            # Body & Links
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            charset = part.get_content_charset() or "utf-8"
                            try:
                                body += payload.decode(charset, errors="ignore")
                            except:
                                body += payload.decode("utf-8", errors="ignore")
            else:
                payload = msg.get_payload(decode=True)
                if payload:
                    charset = msg.get_content_charset() or "utf-8"
                    try:
                        body = payload.decode(charset, errors="ignore")
                    except:
                        body = payload.decode("utf-8", errors="ignore")
            
            links = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
            # Filter out technical XML namespaces/schemas
            technical_domains = ["w3.org", "xmlsoap.org", "openxmlformats.org", "purl.org", "iana.org", "schemas.microsoft.com", "opengraph.org", "schema.org"]
            filtered_links = []
            for link in links:
                # Clean trailing punctuation
                link = link.rstrip(".,;:!?)]")
                lower_link = link.lower()
                if "/2008/fbml" in lower_link or "/schema/" in lower_link or "/schemas/" in lower_link or lower_link.endswith(".xsd") or lower_link.endswith(".dtd"):
                    continue
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(link if link.startswith("http") else "http://" + link)
                    hostname = parsed.hostname.lower() if parsed.hostname else ""
                    if any(hostname == td or hostname.endswith("." + td) for td in technical_domains):
                        continue
                    filtered_links.append(link)
                except:
                    if any(td in lower_link for td in technical_domains):
                        continue
                    filtered_links.append(link)
            self.report_data["email"]["links"] = list(set(filtered_links))
            
            # Attachments
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart': continue
                
                # Check filename from Content-Disposition or Content-Type name param
                filename = part.get_filename()
                if not filename:
                    filename = part.get_param("name")
                    
                # If there's still no filename, but the content type is non-text, we can assign a generic name
                content_type = part.get_content_type()
                if not filename:
                    maintype = part.get_content_maintype()
                    if maintype not in ('text', 'multipart'):
                        ext = content_type.split('/')[-1] if '/' in content_type else 'bin'
                        ext = "".join([c for c in ext if c.isalnum()])
                        filename = f"attachment.{ext}"
                
                if filename:
                    filename = self.decode_mime(filename)
                    # Support spaces, Unicode letters, and common chars in filenames
                    filename = "".join([c for c in filename if c.isalnum() or c in (".", "_", "-", " ", "(", ")", "[", "]")]).strip()
                    if not filename: filename = "attachment.bin"
                    
                    # Ensure unique path in self.temp_dir
                    att_path = os.path.join(self.temp_dir, filename)
                    counter = 1
                    base_name, ext_part = os.path.splitext(filename)
                    while os.path.exists(att_path):
                        filename = f"{base_name}_{counter}{ext_part}"
                        att_path = os.path.join(self.temp_dir, filename)
                        counter += 1
                    
                    payload = part.get_payload(decode=True)
                    if payload is None:
                        payload = b""
                    
                    with open(att_path, 'wb') as att_f:
                        att_f.write(payload)
                    
                    self.report_data["attachments"].append({
                        "name": filename, 
                        "path": att_path, 
                        "type": "attachment",
                        "indicators": []
                    })
                    print(f"    [+] Attachment extracted: {filename}")

        except Exception as e:
            self.log_warning(f"Failed to parse email: {e}")

    def run_yara_scan(self):
        print("[*] Static Analysis: YARA scanning...")
        if not os.path.exists(YARA_RULES):
            print("    [-] YARA rules not found.")
            return

        for att in self.report_data["attachments"]:
            # Note: This assumes 'yara' is installed in system.
            # If not using yara-python, we skip for now or use a mockup.
            try:
                import yara
                rules = yara.compile(YARA_RULES)
                matches = rules.match(att["path"])
                if matches:
                    for match in matches:
                        hit = f"YARA Hit: {match.rule}"
                        att["indicators"].append(hit)
                        self.log_warning(f"File {att['name']} matched YARA rule {match.rule}")
            except ImportError:
                # If yara-python is not available, try subprocess 'yara' command
                res = self.run_tool(['yara', YARA_RULES, att["path"]])
                if res and not "Error" in res:
                    for line in res.splitlines():
                        if line.strip():
                            att["indicators"].append(f"YARA Hit: {line.strip()}")
                            self.log_warning(f"File {att['name']} matched YARA: {line.strip()}")
            except Exception as e:
                print(f"    [-] YARA scan error: {e}")

    def analyze_archive(self, archive_path, archive_name, indicators_list, new_attachments_list):
        print(f"[*] Deep analysis of archive: {archive_name}")
        unpacked_dir = os.path.join(self.temp_dir, f"unpacked_{archive_name.replace(' ', '_')}")
        if not os.path.exists(unpacked_dir):
            os.makedirs(unpacked_dir)
            
        seven_zip = r"C:\Program Files\7-Zip\7z.exe"
        if os.path.exists(seven_zip):
            cmd = [seven_zip, "x", archive_path, f"-o{unpacked_dir}", "-y"]
        else:
            cmd = ["7z", "x", archive_path, f"-o{unpacked_dir}", "-y"]
            
        success = False
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, timeout=45)
            if res.returncode == 0:
                success = True
        except Exception as e:
            print(f"    [-] 7z extraction failed: {e}")
            
        # Fallback to python zipfile if zip
        if not success and archive_name.lower().endswith(".zip"):
            try:
                import zipfile
                unpacked_dir_resolved = os.path.abspath(unpacked_dir)
                with zipfile.ZipFile(archive_path, 'r') as zf:
                    total_sz = 0
                    safe_members = []
                    for member in zf.infolist():
                        total_sz += member.file_size
                        if total_sz > 200 * 1024 * 1024:  # 200MB limit
                            indicators_list.append("[!] Превышен лимит размера распаковки (Zip Bomb риск).")
                            break
                        dest = os.path.abspath(os.path.join(unpacked_dir_resolved, member.filename))
                        if not (dest == unpacked_dir_resolved or dest.startswith(unpacked_dir_resolved + os.sep)):
                            indicators_list.append(f"[!] Zip Slip попытка обхода путей: {member.filename}")
                            continue
                        safe_members.append(member)
                    zf.extractall(unpacked_dir_resolved, members=safe_members)
                success = True
            except Exception as e:
                print(f"    [-] Python zip extraction fallback failed: {e}")
                
        if not success:
            indicators_list.append("[!] Не удалось распаковать архив для анализа.")
            return
            
        # Archive extracted successfully! Walk through the files inside
        inner_files_found = []
        for root, _, files in os.walk(unpacked_dir):
            for file in files:
                inner_path = os.path.join(root, file)
                rel_path = os.path.relpath(inner_path, unpacked_dir)
                inner_files_found.append((file, rel_path, inner_path))
                
        if not inner_files_found:
            indicators_list.append("[-] Архив пуст.")
            return
            
        indicators_list.append(f"[+] Успешно распаковано файлов из архива: {len(inner_files_found)}")
        
        # Analyze each nested file
        for file_name, rel_path, file_path in inner_files_found:
            inner_indicators = []
            inner_ext = file_name.lower().split('.')[-1] if '.' in file_name else ""
            
            # Calculate SHA256 of nested file
            inner_sha256 = "N/A"
            try:
                with open(file_path, "rb") as bf:
                    inner_sha256 = hashlib.sha256(bf.read()).hexdigest()
            except Exception as e:
                print(f"[-] Hashing error for nested file: {e}")
                
            if inner_sha256 != "N/A" and inner_sha256 in self.cache:
                print(f"    [+] Cache hit for nested file: {rel_path} ({inner_sha256})")
                cached_entry = self.cache[inner_sha256]
                inner_indicators = cached_entry.get("indicators", [])
                for w in cached_entry.get("warnings", []):
                    self.log_warning(w, cached_entry.get("verdict", "SUSPICIOUS"))
            else:
                # Dangerous executable and scripting extensions
                is_dangerous_ext = inner_ext in ('exe', 'dll', 'scr', 'sys', 'cpl', 'pif', 'jar', 'js', 'vbs', 'wsf', 'jse', 'vbe', 'bat', 'cmd', 'ps1', 'hta', 'lnk', 'com')
                is_macro_office = inner_ext in ('docm', 'xlsm', 'pptm', 'doc', 'xls', 'ppt')
                
                if is_dangerous_ext:
                    inner_indicators.append(f"[!] ОПАСНОЕ РАСШИРЕНИЕ ФАЙЛА В АРХИВЕ: .{inner_ext}")
                    self.log_warning(f"Архив {archive_name} содержит исполняемый или скриптовый файл: {rel_path}", "MALICIOUS")
                    
                # Scan with YARA if rules are available
                try:
                    if os.path.exists(YARA_RULES):
                        import yara
                        rules = yara.compile(YARA_RULES)
                        matches = rules.match(file_path)
                        if matches:
                            for match in matches:
                                inner_indicators.append(f"[YARA] Сработало правило: {match.rule}")
                                self.log_warning(f"Файл {rel_path} в архиве {archive_name} совпал с YARA-правилом {match.rule}", "MALICIOUS")
                except Exception as e:
                    # Fallback to CLI yara
                    try:
                        res = self.run_tool(['yara', YARA_RULES, file_path])
                        if res and not "Error" in res:
                            for line in res.splitlines():
                                if line.strip():
                                    inner_indicators.append(f"[YARA] {line.strip()}")
                                    self.log_warning(f"Файл {rel_path} в архиве {archive_name} совпал с YARA: {line.strip()}", "MALICIOUS")
                    except:
                        pass
                        
                # Check VBA macros
                if is_macro_office or inner_ext in ('docx', 'xlsx', 'pptx'):
                    try:
                        from oletools.olevba import VBA_Parser
                        vba = VBA_Parser(file_path)
                        if vba.detect_vba_macros():
                            inner_indicators.append("[!] ОБНАРУЖЕНЫ VBA МАКРОСЫ!")
                            self.log_warning(f"Документ {rel_path} в архиве {archive_name} содержит макросы VBA", "SUSPICIOUS")
                            for t, k, d in vba.analyze_macros():
                                if t == 'Suspicious':
                                    inner_indicators.append(f"  - VBA подозрительно: {k} ({d})")
                        vba.close()
                    except:
                        pass
                        
                # Check PDF structure
                if inner_ext == 'pdf':
                    try:
                        from pdfminer.pdfparser import PDFParser
                        from pdfminer.pdfdocument import PDFDocument
                        with open(file_path, 'rb') as f:
                            doc = PDFDocument(PDFParser(f))
                            c = doc.catalog
                            if 'OpenAction' in c or 'AA' in c:
                                inner_indicators.append("[!] PDF: обнаружено автозапускаемое действие OpenAction/AA")
                                self.log_warning(f"PDF {rel_path} в архиве {archive_name} содержит OpenAction/AA", "SUSPICIOUS")
                            if 'Names' in c and 'JavaScript' in str(c['Names']):
                                inner_indicators.append("[!] PDF: обнаружен JavaScript код")
                                self.log_warning(f"PDF {rel_path} в архиве {archive_name} содержит JavaScript", "MALICIOUS")
                    except:
                        pass
                
                # Save to cache!
                if inner_sha256 != "N/A":
                    self.cache[inner_sha256] = {
                        "indicators": inner_indicators,
                        "warnings": [w for w in self.report_data["warnings"] if rel_path in w or file_name in w],
                        "verdict": "MALICIOUS" if any("YARA" in ind or "JavaScript" in ind or "ОПАСНОЕ" in ind for ind in inner_indicators) else "SUSPICIOUS" if any("VBA" in ind or "OpenAction" in ind for ind in inner_indicators) else "CLEAN"
                    }
                    
            # Add detailed lines to parent archive's findings
            status_prefix = "💀 [ВРЕДОНОСНЫЙ]" if any("ОПАСНОЕ" in ind or "YARA" in ind or "JavaScript" in ind for ind in inner_indicators) else "⚠️ [ПОДОЗРИТЕЛЬНЫЙ]" if any("VBA" in ind or "OpenAction" in ind for ind in inner_indicators) else "🟢 [ЧИСТЫЙ]"
            
            indicators_list.append(f"{status_prefix} Файл в архиве: {rel_path}")
            for ind in inner_indicators:
                indicators_list.append(f"   ↳ {ind}")
                
            # Add to deep analysis attachments so it calculates hashes and displays details!
            new_attachments_list.append({
                "name": f"{archive_name} -> {rel_path}",
                "path": file_path,
                "type": "attachment",
                "indicators": inner_indicators
            })

    def extract_content(self, file_path, out_dir):
        if not os.path.exists(out_dir):
            os.makedirs(out_dir)
            
        ext = file_path.lower().split('.')[-1]
        
        if ext == 'msg':
            msg = None
            try:
                import extract_msg
                out_dir_resolved = os.path.abspath(out_dir)
                msg = extract_msg.Message(file_path)
                for attr in msg.attachments:
                    raw_fn = attr.getFilename() if hasattr(attr, "getFilename") else getattr(attr, "longFilename", None)
                    if raw_fn and getattr(attr, "data", None):
                        base_fn = os.path.basename(str(raw_fn).replace("\\", "/"))
                        clean_fn = "".join(c for c in base_fn if c.isalnum() or c in (" ", ".", "_", "-")).strip(" .")
                        if not clean_fn or clean_fn in (".", ".."):
                            clean_fn = "attachment.bin"
                        f_path = os.path.abspath(os.path.join(out_dir_resolved, clean_fn))
                        if not (f_path == out_dir_resolved or f_path.startswith(out_dir_resolved + os.sep)):
                            continue
                        with open(f_path, 'wb') as f:
                            f.write(attr.data)
                        print(f"    [+] Extracted from MSG: {clean_fn}")
            except Exception as e:
                print(f"    [-] Error extracting MSG: {e}")
            finally:
                if msg is not None and hasattr(msg, "close"):
                    try:
                        msg.close()
                    except Exception:
                        pass
                
        elif ext in ('docx', 'xlsx', 'pptx', 'zip'):
            try:
                import zipfile
                with zipfile.ZipFile(file_path, 'r') as z:
                    for name in z.namelist():
                        if 'media/' in name or 'embeddings/' in name:
                            base_name = os.path.basename(name)
                            if base_name:
                                f_path = os.path.join(out_dir, base_name)
                                with open(f_path, 'wb') as f:
                                    f.write(z.read(name))
                                print(f"    [+] Extracted from Office/ZIP: {base_name}")
            except Exception as e:
                print(f"    [-] Error extracting ZIP/Office: {e}")

    def carve_images(self, file_path, out_dir):
        os.makedirs(out_dir, exist_ok=True)
        signatures = {
            'jpg': (b'\xff\xd8\xff', b'\xff\xd9'),
            'png': (b'\x89\x50\x4e\x47\x0d\x0a\x1a\x0a', b'\x49\x45\x4e\x44\xae\x42\x60\x82'),
            'gif': (b'GIF87a', b'\x00\x3b'),
            'gif89': (b'GIF89a', b'\x00\x3b'),
            'bmp': (b'BM', None),
            'emf': (b'\x01\x00\x00\x00', None),
            'pdf': (b'%PDF', b'%%EOF')
        }
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
        except Exception as e:
            print(f"    [-] Error reading for carving: {e}")
            return []
        
        carved_files = []
        count = 0
        for name, (start, end) in signatures.items():
            start_indices = [m.start() for m in re.finditer(re.escape(start), data)]
            for s_idx in start_indices:
                if end:
                    e_match = re.search(re.escape(end), data[s_idx:])
                    if e_match:
                        e_idx = s_idx + e_match.end()
                        img_data = data[s_idx:e_idx]
                        out_path = os.path.join(out_dir, f"carved_{count}.{name.strip('89')}")
                        with open(out_path, 'wb') as img_f:
                            img_f.write(img_data)
                        carved_files.append(out_path)
                        count += 1
                else:
                    img_data = data[s_idx:s_idx+1000000] # Max 1MB
                    out_path = os.path.join(out_dir, f"carved_{count}.{name}")
                    with open(out_path, 'wb') as img_f:
                        img_f.write(img_data)
                    carved_files.append(out_path)
                    count += 1
        return carved_files

    def deep_analyze_attachments(self):
        print("[*] Stage 2 & 3: Content Extraction & Deep Dive (Optimized)")
        new_items = []
        
        # Determine if email is suspicious/malicious for Smart Triage
        is_suspicious_email = len(self.report_data.get("warnings", [])) > 0 or self.report_data.get("overall_verdict") != "CLEAN"
        
        for att in self.report_data["attachments"]:
            name = att["name"]
            path = att["path"]
            ext = name.lower().split('.')[-1]
            
            # Calculate SHA256 of the attachment
            sha256_hash = "N/A"
            if path and os.path.exists(path):
                try:
                    with open(path, "rb") as bf:
                        sha256_hash = hashlib.sha256(bf.read()).hexdigest()
                except Exception as e:
                    print(f"[-] Hashing error: {e}")
                    
            # 1. Check Cache (Step 3: Hash Caching)
            if sha256_hash != "N/A" and sha256_hash in self.cache:
                print(f"    [+] Cache hit for attachment: {name} ({sha256_hash})")
                cached_entry = self.cache[sha256_hash]
                att["indicators"] = cached_entry.get("indicators", [])
                for w in cached_entry.get("warnings", []):
                    self.log_warning(w, cached_entry.get("verdict", "SUSPICIOUS"))
                continue

            # 2. Content Extraction (Step 4: In-Process)
            if ext in ('doc', 'pdf', 'docx'):
                carve_dir = os.path.join(self.temp_dir, f"carved_{name}")
                self.extract_content(path, carve_dir)
                
                if os.path.exists(carve_dir):
                    for f in os.listdir(carve_dir):
                        c_path = os.path.join(carve_dir, f)
                        new_items.append({
                            "name": f"{name} -> {f}", 
                            "path": c_path, 
                            "type": "carved",
                            "indicators": []
                        })

            # 3. Archive Extraction & Deep Scan
            if ext in ('zip', 'rar', '7z', 'tar', 'gz'):
                self.analyze_archive(path, name, att["indicators"], new_items)

            # 4. Deep Dive (Step 4: In-Process PDF and Image analysis)
            if ext == 'pdf':
                try:
                    from pdfminer.pdfparser import PDFParser
                    from pdfminer.pdfdocument import PDFDocument
                    with open(path, 'rb') as f:
                        doc = PDFDocument(PDFParser(f))
                        c = doc.catalog
                        if 'OpenAction' in c or 'AA' in c:
                            att["indicators"].append("[!] PDF: обнаружено автозапускаемое действие OpenAction/AA")
                            self.log_warning(f"PDF {name} содержит OpenAction/AA", "SUSPICIOUS")
                        if 'Names' in c and 'JavaScript' in str(c['Names']):
                            att["indicators"].append("[!] PDF: обнаружен JavaScript код")
                            self.log_warning(f"PDF {name} содержит JavaScript", "MALICIOUS")
                except Exception as e:
                    print(f"    [-] PDF in-process scan error: {e}")

            # Step 5: Smart Triage - Skip image carving for standalone images in clean emails
            if ext in ('png', 'jpg', 'jpeg', 'gif'):
                if is_suspicious_email:
                    carve_dir = os.path.join(self.temp_dir, f"carved_img_{name}")
                    carved = self.carve_images(path, carve_dir)
                    if carved:
                        att["indicators"].append(f"[+] Извлечено скрытых объектов из изображения: {len(carved)}")
                else:
                    print(f"    [~] Smart Triage: Skipping image carving for clean standalone image: {name}")

            # Save analyzed attachment to cache
            if sha256_hash != "N/A":
                self.cache[sha256_hash] = {
                    "indicators": att["indicators"],
                    "warnings": [w for w in self.report_data["warnings"] if name in w],
                    "verdict": "MALICIOUS" if any("YARA" in ind or "JavaScript" in ind or "ОПАСНОЕ" in ind for ind in att["indicators"]) else "SUSPICIOUS" if any("VBA" in ind or "OpenAction" in ind for ind in att["indicators"]) else "CLEAN"
                }

        self.report_data["attachments"].extend(new_items)
        
        # Scan carved items in-process (Step 4)
        for att in self.report_data["attachments"]:
            if att["type"] == "carved":
                name = att["name"]
                path = att["path"]
                
                # Calculate SHA256 of carved item
                sha256_hash = "N/A"
                if path and os.path.exists(path):
                    try:
                        with open(path, "rb") as bf:
                            sha256_hash = hashlib.sha256(bf.read()).hexdigest()
                    except:
                        pass
                        
                if sha256_hash != "N/A" and sha256_hash in self.cache:
                    att["indicators"] = self.cache[sha256_hash].get("indicators", [])
                    continue
                    
                # Only carve nested images if email is suspicious
                if is_suspicious_email and path.lower().split('.')[-1] in ('png', 'jpg', 'jpeg', 'gif'):
                    carve_dir = os.path.join(self.temp_dir, f"carved_nested_{name}")
                    carved = self.carve_images(path, carve_dir)
                    if carved:
                        att["indicators"].append(f"[!] Извлечено скрытых объектов из вложенного изображения: {len(carved)}")
                        
                if sha256_hash != "N/A":
                    self.cache[sha256_hash] = {
                        "indicators": att["indicators"],
                        "warnings": [],
                        "verdict": "CLEAN"
                    }

        # Save cache at the end of analysis
        self.save_cache()

    def generate_report(self):
        print("[*] Этап 4: Формирование отчета")
        report_path = os.path.join(self.temp_dir, "ОТЧЕТ_АНАЛИЗА.txt")
        with open(report_path, 'w', encoding='utf-8') as f:
            f.write("=== 🛡️ ОТЧЕТ О КРИМИНАЛИСТИЧЕСКОМ АНАЛИЗЕ ПИСЬМА ===\n\n")
            
            verdict = self.report_data['overall_verdict']
            v_str = "🟢 ЧИСТО" if verdict == "CLEAN" else ("🟡 ПОДОЗРИТЕЛЬНО" if verdict == "SUSPICIOUS" else "🔴 ВРЕДОНОСНО")
            f.write(f"ИТОГОВЫЙ ВЕРДИКТ: {v_str}\n\n")
            
            f.write("--- 📧 Основная информация о письме ---\n")
            e = self.report_data["email"]
            f.write(f"- Отправитель: {e.get('from')}\n- Тема: {e.get('subject')}\n")
            f.write(f"- Проверка подлинности: SPF={e.get('spf')}, DKIM={e.get('dkim')}\n\n")
            
            if e.get("links"):
                f.write("--- 🔍 Найденные ссылки ---\n")
                for l in e["links"]: f.write(f"- {l}\n")
                f.write("\n")

            f.write("--- 📎 Анализ вложений ---\n")
            for att in self.report_data["attachments"]:
                f.write(f"📎 Файл: {att['name']} (Тип: {att['type']})\n")
                if att["indicators"]:
                    f.write("Индикаторы:\n")
                    f.write("\n".join(att["indicators"]))
                    f.write("\n")
                else:
                    f.write("- Подозительных признаков не обнаружено.\n")
                f.write("\n")

            if self.report_data["warnings"]:
                f.write("--- ⚠️ Предупреждения и аномалии ---\n")
                for w in self.report_data["warnings"]: f.write(f"- {w}\n")
        
        print(f"[+] Отчет успешно сохранен в: {report_path}")

    def cleanup(self):
        print("[*] Stage 5: Cleanup")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run(self):
        if self.target.lower().endswith(('.eml', '.msg')):
            self.analyze_email(self.target)
        else:
            # If folder, walk it? Or just single file
            if os.path.isfile(self.target):
                self.report_data["attachments"].append({
                    "name": os.path.basename(self.target), 
                    "path": self.target, 
                    "type": "direct_input",
                    "indicators": []
                })
        
        self.run_yara_scan()
        self.deep_analyze_attachments()
        self.generate_report()
        self.cleanup()

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    orchestrator = PhishingOrchestrator(target)
    orchestrator.run()



