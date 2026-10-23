
# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: analyze_threats.py
Назначение: 7-уровневый оркестратор криминалистического анализа писем и вложений.

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
import datetime
from pathlib import Path
from email.header import decode_header

# Гарантия безопасной работы с Unicode/Emoji именами файлов на Windows консоли (cp1251 fix)
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# --- Динамические пути относительно проекта ---
CURRENT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = CURRENT_DIR.parent
PDF_FORENSICS = str(CURRENT_DIR / "metadata_hex_scanner.py")
MEDIA_FORENSICS = str(CURRENT_DIR / "carve_images.py")
CONTENT_EXTRACTOR = str(CURRENT_DIR / "carve_images.py")
OFFICE_FORENSICS = str(CURRENT_DIR / "safe_office_deep_scan.py")
YARA_RULES = str(PROJECT_ROOT / "04_Detection_Rules" / "professional_threats.yar")

try:
    from tools_bridge import bridge
except ImportError:
    try:
        from .tools_bridge import bridge
    except Exception:
        bridge = None

try:
    from phish_engine import PhishingEngine
except ImportError:
    try:
        from .phish_engine import PhishingEngine
    except ImportError:
        PhishingEngine = None

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
        self.temp_dir = tempfile.mkdtemp(prefix="phish_orch_")

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

    def _save_unique_attachment(self, raw_filename, payload_data):
        filename = self.decode_mime(raw_filename)
        filename = os.path.basename(str(filename).replace("\\", "/"))
        filename = "".join([c for c in filename if c.isalnum() or c in (" ", ".", "_", "-", "(", ")", "[", "]")]).strip(" .")
        if not filename or filename in (".", ".."):
            filename = "attachment.bin"
        att_path = os.path.join(self.temp_dir, filename)
        counter = 1
        base_name, ext_part = os.path.splitext(filename)
        while os.path.exists(att_path):
            filename = f"{base_name}_{counter}{ext_part}"
            att_path = os.path.join(self.temp_dir, filename)
            counter += 1
        payload_data = payload_data or b""
        with open(att_path, 'wb') as att_f:
            att_f.write(payload_data)
        att_sha256 = hashlib.sha256(payload_data).hexdigest()
        self.report_data["attachments"].append({
            "name": filename,
            "path": att_path,
            "size": len(payload_data),
            "sha256": att_sha256,
            "type": "attachment",
            "indicators": []
        })
        print(f"    [+] Извлечено вложение: {filename} ({len(payload_data)} байт, SHA256: {att_sha256[:16]}...)")

    def analyze_email(self, eml_path):
        clean_name = os.path.basename(eml_path)
        print(f"[*] Stage 1: Email Forensic - {clean_name}")
        try:
            with open(eml_path, 'rb') as f_check:
                magic = f_check.read(8)
            is_msg = eml_path.lower().endswith(".msg") or magic.startswith(b"\xd0\xcf\x11\xe0")

            if is_msg:
                try:
                    import extract_msg
                    msg_obj = extract_msg.Message(eml_path)
                    try:
                        subj = str(msg_obj.subject or "No Subject")
                        sender = str(msg_obj.sender or "")
                        to_addr = str(msg_obj.to or "")
                        date_hdr = str(msg_obj.date or "")
                        hdr_dict = getattr(msg_obj, "headerDict", {}) or {}
                        return_path = str(hdr_dict.get("Return-Path", ""))
                        reply_to = str(hdr_dict.get("Reply-To", ""))
                        self.report_data["email"].update({
                            "subject": subj, "from": sender, "return_path": return_path,
                            "reply_to": reply_to, "to": to_addr, "date": date_hdr,
                            "spf": "UNKNOWN", "dkim": "NONE"
                        })
                        body = str(msg_obj.body or "")
                        if getattr(msg_obj, "htmlBody", None):
                            hb = msg_obj.htmlBody
                            body += "\n" + (hb.decode("utf-8", errors="ignore") if isinstance(hb, bytes) else str(hb))
                        found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
                        self.report_data["email"]["links"] = sorted(list(set(found_urls)))
                        for att in getattr(msg_obj, "attachments", []):
                            fn = getattr(att, "longFilename", None) or getattr(att, "shortFilename", None) or (att.getFilename() if hasattr(att, "getFilename") else None) or "attachment.bin"
                            data = getattr(att, "data", b"")
                            if isinstance(data, bytes):
                                self._save_unique_attachment(fn, data)
                        return
                    finally:
                        if hasattr(msg_obj, "close"):
                            msg_obj.close()
                except Exception as msg_err:
                    print(f"    [!] Fallback MSG parser warning: {msg_err}")

            with open(eml_path, 'rb') as f:
                msg = email.message_from_binary_file(f)
            
            # 1. Заголовки (Headers)
            subj = self.decode_mime(msg.get("Subject", "No Subject"))
            sender = self.decode_mime(msg.get("From", ""))
            return_path = self.decode_mime(msg.get("Return-Path", ""))
            reply_to = self.decode_mime(msg.get("Reply-To", ""))
            to_addr = self.decode_mime(msg.get("To", ""))
            date_hdr = msg.get("Date", "")
            
            self.report_data["email"]["subject"] = subj
            self.report_data["email"]["from"] = sender
            self.report_data["email"]["return_path"] = return_path
            self.report_data["email"]["reply_to"] = reply_to
            self.report_data["email"]["to"] = to_addr
            self.report_data["email"]["date"] = date_hdr
            
            print(f"    [+] From: {sender}")
            if return_path:
                print(f"    [+] Return-Path: {return_path}")
            print(f"    [+] Subject: {subj}")
            
            # Проверка подделки отправителя (Spoofing Check)
            from_domain = sender.split("@")[-1].replace(">", "").strip().lower() if "@" in sender else ""
            ret_domain = return_path.split("@")[-1].replace(">", "").strip().lower() if "@" in return_path else ""
            if from_domain and ret_domain and from_domain != ret_domain:
                self.log_warning(
                    f"ПОДМЕНА ОТПРАВИТЕЛЯ (Spoofing/Compromise): Видимый адрес [{sender}] не совпадает с Return-Path [{return_path}]!",
                    "MALICIOUS"
                )

            # 2. Проверка подлинности (Auth Check - SPF / DKIM / DMARC)
            auth_headers = []
            for h_key in ("Authentication-Results", "Received-SPF", "ARC-Authentication-Results", "X-FEAS-SPF", "X-FEAS-DKIM"):
                for val in msg.get_all(h_key, []):
                    auth_headers.append(str(val))
            combined_auth = " ".join(auth_headers).lower()

            if "spf=pass" in combined_auth or "spf-result=pass" in combined_auth:
                spf_status = "PASS"
            elif "spf=fail" in combined_auth or "spf=softfail" in combined_auth:
                spf_status = "FAIL"
            else:
                spf_status = "UNKNOWN"

            if "dkim=pass" in combined_auth:
                dkim_status = "PASS"
            elif "dkim=fail" in combined_auth:
                dkim_status = "FAIL"
            else:
                dkim_status = "NONE"
            
            self.report_data["email"]["spf"] = spf_status
            self.report_data["email"]["dkim"] = dkim_status
            
            if dkim_status in ("NONE", "FAIL"):
                self.log_warning(f"DKIM подпись отсутствует или невалидна (DKIM={dkim_status}).")
            if spf_status == "PASS" and from_domain != ret_domain and ret_domain:
                self.log_warning("SPF=PASS пройден для стороннего релея, но заголовок From сфальсифицирован (Компрометация ящика)!", "MALICIOUS")

            # 3. Извлечение тела и ссылок (Body & Links)
            body = ""
            if msg.is_multipart():
                for part in msg.walk():
                    if part.get_content_type() in ("text/plain", "text/html"):
                        payload = part.get_payload(decode=True)
                        if payload:
                            body += payload.decode(errors='ignore')
            else:
                raw_payload = msg.get_payload(decode=True)
                body = raw_payload.decode(errors='ignore') if raw_payload else ""
            
            found_urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', body)
            unique_urls = sorted(list(set(found_urls)))
            self.report_data["email"]["links"] = unique_urls
            print(f"    [+] Извлечено URL-ссылок: {len(unique_urls)}")
            
            # Анализ ссылок на фишинговые и вредоносные паттерны
            suspicious_hosting_patterns = [
                "web.core.windows.net", "blob.core.windows.net", "firebaseapp.com",
                "workers.dev", "pages.dev", "glitch.me", "ipfs.io", "fleek.co",
                "ngrok.io", "loca.lt", "github.io"
            ]
            for u in unique_urls:
                u_lower = u.lower()
                for pat in suspicious_hosting_patterns:
                    if pat in u_lower:
                        self.log_warning(f"КРИТИЧЕСКИЙ ФИШИНГ: Ссылка на облачный хостинг для сбора учетных данных ({pat}): {u}", "MALICIOUS")

            # 4. Извлечение вложений
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart': continue
                if part.get('Content-Disposition') is None and not part.get_filename() and not part.get_param("name"): continue
                
                filename = part.get_filename() or part.get_param("name")
                if filename:
                    payload_data = part.get_payload(decode=True) or b""
                    self._save_unique_attachment(filename, payload_data)

        except Exception as e:
            self.log_warning(f"Ошибка при разборе письма: {e}")

    def run_yara_scan(self):
        print("[*] Static Analysis: YARA scanning...")
        if not os.path.exists(YARA_RULES):
            print("    [-] YARA rules not found.")
            return

        for att in self.report_data["attachments"]:
            try:
                import yara
                rules = yara.compile(YARA_RULES)
                matches = rules.match(att["path"])
                if matches:
                    for match in matches:
                        hit = f"YARA Hit: {match.rule}"
                        att["indicators"].append(hit)
                        self.log_warning(f"Файл {att['name']} содержит сигнатуру YARA {match.rule}")
            except ImportError:
                res = self.run_tool(['yara', YARA_RULES, att["path"]])
                if res and not "Error" in res:
                    for line in res.splitlines():
                        if line.strip():
                            att["indicators"].append(f"YARA Hit: {line.strip()}")
                            self.log_warning(f"Файл {att['name']} содержит сигнатуру YARA: {line.strip()}")
            except Exception as e:
                print(f"    [-] YARA scan error: {e}")

    def deep_analyze_attachments(self):
        print("[*] Stage 2 & 3: Content Extraction & Deep Dive")
        new_items = []
        
        for att in self.report_data["attachments"]:
            name = att["name"]
            path = att["path"]
            ext = name.lower().split('.')[-1]

            # 1. Content Extraction
            if ext in ('doc', 'pdf', 'docx'):
                carve_dir = os.path.join(self.temp_dir, f"carved_{name}")
                self.run_tool([CONTENT_EXTRACTOR, path, carve_dir])
                
                if os.path.exists(carve_dir):
                    for f in os.listdir(carve_dir):
                        c_path = os.path.join(carve_dir, f)
                        new_items.append({
                            "name": f"{name} -> {f}", 
                            "path": c_path, 
                            "type": "carved",
                            "indicators": []
                        })

            # 2. Deep Dive
            if ext in ('doc', 'docx', 'docm', 'xls', 'xlsx', 'xlsm', 'ppt', 'pptm', 'rtf'):
                res = self.run_tool([OFFICE_FORENSICS, path])
                for line in res.splitlines():
                    if "[!]" in line or "ALERT" in line or "DANGEROUS" in line:
                        att["indicators"].append(line.strip())
                        self.log_warning(f"Угроза Office в {name}: {line.strip()}")
                
                # Внешний модуль: OfficeMalScanner / RTFScan
                if bridge:
                    oms_out = bridge.scan_office_malware(path)
                    if "Malicious" in oms_out or "Shellcode" in oms_out or "Found" in oms_out:
                        att["indicators"].append("[OfficeMalScanner] Сигнатурный детект подозрительных блоков/шеллкода")
                    if ext == 'rtf':
                        rtf_out = bridge.scan_rtf(path)
                        if "threat" in rtf_out.lower() or "exploit" in rtf_out.lower():
                            att["indicators"].append("[RTFScan] Обнаружена аномалия в RTF структуре")
                            self.log_warning(f"RTFScan обнаружил аномалию в {name}!", "MALICIOUS")

            if ext == 'pdf':
                res = self.run_tool([PDF_FORENSICS, path])
                for line in res.splitlines():
                    if "[!]" in line or "[+]" in line:
                        att["indicators"].append(line.strip())
                        if "[!] CRITICAL" in line: self.log_warning(f"CRITICAL в PDF {name}: {line}")
                
                # Внешний модуль: pdf-parser (Didier Stevens)
                if bridge:
                    pdf_out = bridge.scan_pdf_deep(path)
                    if "ПОИСК JAVASCRIPT" in pdf_out and "JavaScript не обнаружен." not in pdf_out:
                        att["indicators"].append("[pdf-parser] Внимание: В PDF обнаружены JavaScript-скрипты!")
                        self.log_warning(f"pdf-parser нашел скрытый JavaScript в {name}!", "SUSPICIOUS")
                    if "ПОИСК OPENACTION" in pdf_out and "OpenAction не обнаружен." not in pdf_out:
                        att["indicators"].append("[pdf-parser] Внимание: Обнаружен триггер автозапуска OpenAction!")
                        self.log_warning(f"pdf-parser нашел OpenAction в {name}!", "SUSPICIOUS")

            if ext in ('png', 'jpg', 'jpeg', 'gif'):
                res = self.run_tool([MEDIA_FORENSICS, path])
                for line in res.splitlines():
                    if "[!]" in line or "[+]" in line:
                        att["indicators"].append(line.strip())
                        if "[!]" in line: self.log_warning(f"Предупреждение в изображении {name}: {line}")

            # Внешние модули: Нативный YARA 64 и Sysinternals Strings для всех вложений
            if bridge:
                yara_res = bridge.scan_yara(path)
                for yline in yara_res.splitlines():
                    if yline.strip() and not yline.startswith("[-]") and "error" not in yline.lower():
                        att["indicators"].append(f"[YARA64] {yline.strip()}")
                        self.log_warning(f"Нативный YARA64 обнаружил совпадение в {name}: {yline.strip()}")
                
                str_res = bridge.extract_strings(path)
                if "Извлечено подозрительных строк: 0" not in str_res:
                    att["indicators"].append("[Strings] Найдены исполняемые вызовы / URL / команды")

        self.report_data["attachments"].extend(new_items)

    def generate_report(self):
        print("[*] Этап 4: Формирование отчета (FINAL_REPORT.md)")
        verdict = self.report_data['overall_verdict']
        v_str = "🟢 ЧИСТО (CLEAN)" if verdict == "CLEAN" else ("🟡 ПОДОЗРИТЕЛЬНО (SUSPICIOUS)" if verdict == "SUSPICIOUS" else "🔴 ВРЕДОНОСНО (MALICIOUS)")
        
        md_lines = [
            "# 🛡️ КРИМИНАЛИСТИЧЕСКИЙ ОТЧЕТ АНАЛИЗА СООБЩЕНИЯ",
            "",
            f"**Дата анализа:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  ",
            f"**Исследуемый объект:** `{os.path.basename(self.target)}`  ",
            f"**Итоговый вердикт:** ## **{v_str}**",
            "",
            "---",
            "",
            "## 1. 📧 Паспорт почтового сообщения",
            f"- **Тема (Subject):** {self.report_data['email'].get('subject', 'N/A')}",
            f"- **Отправитель (From):** `{self.report_data['email'].get('from', 'N/A')}`",
            f"- **Обратный путь (Return-Path):** `{self.report_data['email'].get('return_path', 'N/A')}`",
            f"- **Получатель (To):** `{self.report_data['email'].get('to', 'N/A')}`",
            f"- **Дата письма:** {self.report_data['email'].get('date', 'N/A')}",
            f"- **SPF статус:** `{self.report_data['email'].get('spf', 'N/A')}` | **DKIM статус:** `{self.report_data['email'].get('dkim', 'N/A')}`",
            "",
            "---",
            "",
            "## 2. ⚠️ Предупреждения и аномалии безопасности"
        ]
        
        if self.report_data["warnings"]:
            for w in self.report_data["warnings"]:
                md_lines.append(f"- 🚨 **ВНИМАНИЕ:** {w}")
        else:
            md_lines.append("- Критических аномалий в заголовках не обнаружено.")
            
        md_lines.extend([
            "",
            "---",
            "",
            "## 3. 🔍 Извлеченные сетевые индикаторы (URLs)",
        ])
        
        links = self.report_data["email"].get("links", [])
        if links:
            for l in links:
                is_danger = any(p in l.lower() for p in ["web.core.windows.net", "firebase", "workers.dev", "ipfs"])
                badge = "🔴 [DANGEROUS PHISHING HOST]" if is_danger else "🔹 [EXTRACTED]"
                md_lines.append(f"- {badge} `{l}`")
        else:
            md_lines.append("- В теле сообщения ссылок не обнаружено.")
            
        # 4. Включение данных PhishingEngine v4.0 (если доступны)
        score_res = self.report_data.get("score_result")
        if score_res:
            md_lines.extend([
                "",
                "---",
                "",
                "## 4. 📊 Взвешенный скоринг угроз (PhishingEngine v4.0)",
                f"- **Суммарный балл риска:** `{score_res.total_score} / 100`",
                f"- **Категоризация вердикта:** `{score_res.verdict}`",
                "",
                "| ID | Категория | Важность | Вес | Описание угрозы | Доказательства |",
                "|---|---|---|---|---|---|"
            ])
            for f in score_res.findings:
                md_lines.append(f"| `{f.id}` | {f.category.value} | `{f.severity.value}` | +{f.weight} | {f.title} | {f.evidence} |")

            if score_res.uninspected:
                md_lines.extend([
                    "",
                    "### 🛡️ Непроверенные области анализа (Uninspected Scope):"
                ])
                for u in score_res.uninspected:
                    md_lines.append(f"- ℹ️ {u}")

        md_lines.extend([
            "",
            "---",
            "",
            "## 5. 📎 Анализ вложений и извлеченных объектов",
        ])
        
        atts = self.report_data["attachments"]
        if atts:
            for att in atts:
                md_lines.append(f"### Файл: `{att['name']}` ({att.get('size', 0)} байт)")
                if att.get('sha256'):
                    md_lines.append(f"- **SHA256:** `{att['sha256']}`")
                if att.get('indicators'):
                    md_lines.append("- **Обнаруженные индикаторы:**")
                    for ind in att['indicators']:
                        md_lines.append(f"  - `{ind}`")
                else:
                    md_lines.append("- Подозрительных макросов и эксплойтов не обнаружено.")
        else:
            md_lines.append("- Письмо не содержит вложений.")
            
        md_lines.extend([
            "",
            "---",
            "**Система анализа:** Audit_Email_Verification_System v4.0 (Red Edition / OMSA v1.0)  ",
            "**Автор:** AG-K08 (@And_8) <mznxncbv888@gmail.com> (2026)"
        ])
        
        md_content = "\n".join(md_lines)
        
        # Сохранение отчета в нескольких точках (рядом с файлом и в текущей папке)
        target_dir = os.path.dirname(os.path.abspath(self.target))
        primary_report = os.path.join(target_dir, "FINAL_REPORT.md")
        local_report = "FINAL_REPORT.md"
        local_txt = "ОТЧЕТ_АНАЛИЗА.txt"
        
        try:
            with open(primary_report, 'w', encoding='utf-8') as f:
                f.write(md_content)
            print(f"[+] Отчет успешно сохранен в: {primary_report}")
        except Exception as e:
            print(f"[!] Предупреждение при записи {primary_report}: {e}")
            
        try:
            with open(local_report, 'w', encoding='utf-8') as f:
                f.write(md_content)
            with open(local_txt, 'w', encoding='utf-8') as f:
                f.write(md_content)
        except Exception:
            pass

    def cleanup(self):
        print("[*] Stage 5: Cleanup")
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def run(self):
        if self.target.lower().endswith(('.eml', '.msg')):
            # 1. Запуск передового движка PhishingEngine
            if PhishingEngine:
                try:
                    print("[*] Stage 0: PhishingEngine v4.0 Core Scan")
                    engine = PhishingEngine()
                    score_res = engine.analyze_email_file(Path(self.target))
                    self.report_data["score_result"] = score_res
                    if score_res.verdict == "MALICIOUS":
                        self.report_data["overall_verdict"] = "MALICIOUS"
                    elif score_res.verdict == "SUSPICIOUS" and self.report_data["overall_verdict"] != "MALICIOUS":
                        self.report_data["overall_verdict"] = "SUSPICIOUS"

                    for f in score_res.findings:
                        msg = f"[{f.severity.value}] {f.title}: {f.evidence}"
                        print(f"    [!] PhishEngine finding: {msg}")
                        if f.severity.value in ("CRITICAL", "HIGH"):
                            self.log_warning(msg, "MALICIOUS")
                        elif f.severity.value == "MEDIUM":
                            self.log_warning(msg, "SUSPICIOUS")
                        else:
                            self.report_data["warnings"].append(msg)
                except Exception as e:
                    print(f"[-] PhishingEngine execution note: {e}")

            self.analyze_email(self.target)
        else:
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
    default_sample = PROJECT_ROOT / "06_Audit_Tests_and_Samples" / "test.eml"
    target = sys.argv[1] if len(sys.argv) > 1 else str(default_sample if default_sample.exists() else ".")
    orchestrator = PhishingOrchestrator(target)
    orchestrator.run()
