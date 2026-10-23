# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: robust_analyzer.py
Назначение: Отказоустойчивый статический анализатор вложений и исполняемых объектов.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys

if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

import json
import shutil
from pathlib import Path
try:
    import yara
except ImportError:
    yara = None

try:
    from oletools.olevba import VBA_Parser
except ImportError:
    VBA_Parser = None

try:
    import extract_msg
except ImportError:
    extract_msg = None

try:
    from pdfminer.pdfparser import PDFParser
    from pdfminer.pdfdocument import PDFDocument
except ImportError:
    PDFParser = None
    PDFDocument = None

import re
import subprocess
import xml.etree.ElementTree as ET
import tempfile
from datetime import datetime
import hashlib

PROJECT_ROOT = Path(__file__).resolve().parents[1]

class ThreatAnalyzer:
    def __init__(self, yara_rules_path=None, reports_dir=None):
        self.report = {"meta": {}, "critical_flags": [], "warnings": [], "analyzed_files": {}}
        self.yara_rules = None
        self.yara_rules_path = yara_rules_path or str(PROJECT_ROOT / "04_Detection_Rules" / "professional_threats.yar")
        self.reports_dir = reports_dir or str(PROJECT_ROOT / "Reports")
        
        # Tool Paths (with dynamic PATH fallbacks)
        self.tools = {
            "pestudio": self._find_tool([
                shutil.which("pestudio"),
                r"C:\Program Files\pestudio\pestudio.exe",
                r"D:\Program Files\pestudio\pestudio.exe"
            ]),
            "floss": self._find_tool([
                shutil.which("floss"),
                r"C:\Program Files\floss\floss.exe",
                r"D:\Program Files\floss\floss.exe"
            ])
        }
        
        if not os.path.exists(self.reports_dir):
            try: os.makedirs(self.reports_dir)
            except: pass

        if yara and self.yara_rules_path and os.path.exists(self.yara_rules_path):
            try:
                self.yara_rules = yara.compile(filepath=self.yara_rules_path)
            except Exception as e:
                self.report["warnings"].append(f"YARA compile error: {e}")

    def _find_tool(self, paths):
        for p in paths:
            if p and os.path.exists(p):
                return p
        return None

    def analyze(self, target_path):
        self.report["meta"]["scan_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.report["meta"]["target"] = os.path.abspath(target_path)
        
        files_to_scan = []
        if os.path.isfile(target_path):
            files_to_scan.append(target_path)
        elif os.path.isdir(target_path):
            for root, _, files in os.walk(target_path):
                for file in files:
                    fp = os.path.join(root, file)
                    if file.endswith('.py') or file.endswith('.yar') or file.startswith('~'): continue
                    files_to_scan.append(fp)
        
        # Основной цикл анализа (включая динамическое добавление вложенных файлов)
        processed_files = set()
        queue = files_to_scan[:]
        
        while queue:
            fp = queue.pop(0)
            if fp in processed_files: continue
            
            # Если это вложение в MSG, оно может быть временным файлом
            is_temp = "tmp_attachment" in fp
            display_name = os.path.basename(fp)
            
            file_report = self._process_file(fp, display_name)
            
            # Если это MSG - извлекаем вложения для дальнейшего анализа
            if file_report["type"] == 'msg':
                attachments = self._extract_msg_attachments(fp)
                queue.extend(attachments)
                if attachments:
                    file_report["findings"].append(f"[MSG] Извлечено вложений: {len(attachments)}")
            
            self.report["analyzed_files"][display_name] = file_report
            processed_files.add(fp)
            
            # Если файл был временным вложением, он удалится в конце (опционально)
            # Но для репорта мы его сохраняем в структуре

        # Очистка временных директорий
        for td in getattr(self, "_temp_dirs", []):
            shutil.rmtree(td, ignore_errors=True)
        self._temp_dirs = []

        # Генерация отчетов
        json_output = json.dumps(self.report, indent=4, ensure_ascii=False)
        self.generate_markdown_report()
        return json_output

    def _extract_msg_attachments(self, file_path):
        extracted_paths = []
        msg = None
        temp_dir = None
        try:
            if extract_msg is None:
                return []
            msg = extract_msg.Message(file_path)
            temp_dir = tempfile.mkdtemp(prefix="msg_scan_")
            if not hasattr(self, "_temp_dirs"):
                self._temp_dirs = []
            self._temp_dirs.append(temp_dir)
            for attr in getattr(msg, "attachments", []):
                raw_fn = attr.getFilename() if hasattr(attr, "getFilename") else getattr(attr, "longFilename", None)
                if raw_fn and getattr(attr, "data", None):
                    clean_fn = os.path.basename(str(raw_fn).replace("\\", "/"))
                    clean_fn = "".join(c for c in clean_fn if c.isalnum() or c in (" ", ".", "_", "-")).strip()
                    if not clean_fn:
                        clean_fn = "attachment.bin"
                    # Фильтруем картинки-подписи
                    if any(clean_fn.lower().endswith(e) for e in ['.png', '.jpg', '.jpeg', '.gif']) and len(attr.data) < 50000:
                        continue
                    at_path = os.path.join(temp_dir, f"tmp_attachment_{clean_fn}")
                    with open(at_path, 'wb') as f:
                        f.write(attr.data)
                    extracted_paths.append(at_path)
        except Exception as e:
            self.report["warnings"].append(f"Ошибка извлечения вложений из {os.path.basename(file_path)}: {e}")
        finally:
            if msg is not None and hasattr(msg, "close"):
                try:
                    msg.close()
                except Exception:
                    pass
        return extracted_paths

    def _process_file(self, file_path, display_name):
        ext = display_name.lower().split('.')[-1]
        file_report = {"type": ext, "findings": [], "score": 0, "verdict": "CLEAN", "hashes": {}}
        
        # 0. Расчет хэшей
        file_report["hashes"] = self._calculate_hashes(file_path)
        
        # 1. Защита от OOM и YARA Scan
        self._yara_scan(file_path, file_report)
        
        # 2. Структурный анализ
        try:
            if ext in ['doc', 'xls', 'ppt', 'docx', 'xlsx', 'docm', 'xlsm']:
                self._analyze_office(file_path, file_report)
            elif ext == 'pdf':
                self._analyze_pdf(file_path, file_report)
            elif ext == 'msg':
                self._analyze_msg(file_path, file_report)
            elif ext in ['exe', 'dll', 'scr', 'bin']:
                self._analyze_pe(file_path, file_report)
        except Exception as e:
            file_report["findings"].append(f"[CRITICAL ERROR] Сбой анализа {display_name}: {e}")
            file_report["score"] += 50
            
        # 3. Финальный вердикт
        if file_report["score"] > 70:
            file_report["verdict"] = "MALICIOUS"
        elif file_report["score"] > 30:
            file_report["verdict"] = "SUSPICIOUS"
            
        return file_report

    def _yara_scan(self, file_path, file_report):
        if not self.yara_rules:
            return
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            matches = self.yara_rules.match(data=data)
            if matches:
                for match in matches:
                    weight = 40
                    sev = match.meta.get('severity', 'High')
                    if "Critical" in str(sev): weight = 80
                    elif "High" in str(sev): weight = 60
                    
                    file_report["findings"].append(f"[YARA HIT] {match.rule} (Sev: {sev})")
                    file_report["score"] += weight
                    self.report["critical_flags"].append(f"{os.path.basename(file_path)}: {match.rule}")
        except Exception:
            pass

    def _analyze_office(self, file_path, file_report):
        if VBA_Parser is None:
            return
        try:
            vba = VBA_Parser(file_path)
            if vba.detect_vba_macros():
                file_report["findings"].append("[MACRO] VBA обнаружен")
                file_report["score"] += 20
                for t, k, d in vba.analyze_macros():
                    if t == 'Suspicious':
                        file_report["findings"].append(f"[VBA] {k}: {d}")
                        file_report["score"] += 10
            vba.close()
        except Exception:
            pass

    def _analyze_pdf(self, file_path, file_report):
        if PDFDocument is None or PDFParser is None:
            return
        try:
            with open(file_path, 'rb') as f:
                doc = PDFDocument(PDFParser(f))
                c = doc.catalog
                if 'OpenAction' in c or 'AA' in c:
                    file_report["findings"].append("[PDF] OpenAction/AA detected")
                    file_report["score"] += 45
                if 'Names' in c and 'JavaScript' in str(c['Names']):
                    file_report["findings"].append("[PDF] JavaScript found")
                    file_report["score"] += 60
        except Exception:
            pass

    def _analyze_msg(self, file_path, file_report):
        if extract_msg is None:
            return
        msg = None
        try:
            msg = extract_msg.Message(file_path)
            sender = (msg.sender or "").lower()
            if sender and any(p in sender for p in ['@yandex.', '@gmail.', '@mail.ru']):
                file_report["findings"].append(f"[BEC] Бесплатная почта: {msg.sender}")
                file_report["score"] += 35
            body = msg.body or ""
            if body:
                for kw in [r'\bкп\b', r'тендер', r'счет', r'оплат']:
                    if re.search(kw, body, re.IGNORECASE):
                        file_report["findings"].append(f"[MARKER] Phish-keyword: {kw}")
                        file_report["score"] += 15
        except Exception:
            pass
        finally:
            if msg is not None and hasattr(msg, "close"):
                try:
                    msg.close()
                except Exception:
                    pass

    def _analyze_pe(self, file_path, file_report):
        # pestudio
        ps = self.tools["pestudio"]
        if ps:
            try:
                with tempfile.NamedTemporaryFile(delete=False, suffix=".xml") as t_xml:
                    xp = t_xml.name
                subprocess.run([ps, "-file", file_path, "-xml", xp], check=True, capture_output=True, timeout=60)
                root = ET.parse(xp).getroot()
                imps = [i.get('name') for i in root.findall(".//import") if i.get('bl') == 'true']
                if imps:
                    file_report["findings"].append(f"[PE] Вредоносные импорты (IAT): {len(imps)}")
                    file_report["score"] += min(len(imps) * 10, 80)
                os.remove(xp)
            except: pass
        
        # FLOSS
        fl = self.tools["floss"]
        if fl:
            try:
                res = subprocess.run([fl, "-n", "6", "--no-static-strings", file_path], capture_output=True, text=True, timeout=120)
                found = [l.strip() for l in res.stdout.split('\n') if any(p in l.lower() for p in ['http', 'cmd', 'powershell', 'wscript'])]
                if found:
                    file_report["findings"].append(f"[FLOSS] Скрытых строк: {len(found)}")
                    file_report["score"] += 50
            except: pass

    def _calculate_hashes(self, file_path):
        h_md5, h_sha = hashlib.md5(), hashlib.sha256()
        try:
            with open(file_path, "rb") as f:
                for chunk in iter(lambda: f.read(8192), b""):
                    h_md5.update(chunk)
                    h_sha.update(chunk)
            return {"md5": h_md5.hexdigest(), "sha256": h_sha.hexdigest()}
        except: return {"md5": "err", "sha256": "err"}

    def generate_markdown_report(self):
        report_name = f"AUTO_REPORT_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        report_path = os.path.join(self.reports_dir, report_name)
        
        md = f"# 🛡️ Автоматический отчет анализа угроз (v3.3)\n\n"
        md += f"**Дата:** {self.report['meta']['scan_time']}\n"
        md += f"**Объект:** `{self.report['meta']['target']}`\n\n"
        
        md += "## 📊 Сводка вердиктов\n"
        md += "| Файл | Тип | Score | Вердикт |\n| :--- | :--- | :--- | :--- |\n"
        for fn, r in self.report["analyzed_files"].items():
            icon = "✅" if r['verdict'] == "CLEAN" else ("⚠️" if r['verdict'] == "SUSPICIOUS" else "💀")
            md += f"| {fn} | {r['type']} | {r['score']} | {icon} {r['verdict']} |\n"
        
        md += "\n---\n\n## 🔍 Детальный разбор\n"
        for fn, r in self.report["analyzed_files"].items():
            md += f"### 📂 {fn} ({r['type']})\n"
            md += f"- **Вердикт:** {r['verdict']} (Score: {r['score']})\n"
            md += f"- **SHA-256:** `{r['hashes'].get('sha256')}`\n"
            md += "- **Находки:**\n"
            if not r['findings']:
                md += "  - Угроз не обнаружено.\n"
            else:
                for f in r['findings']: md += f"  - {f}\n"
            md += "\n"
        
        with open(report_path, 'w', encoding='utf-8') as f: f.write(md)
        print(f"[SUCCESS] Markdown отчет сохранен: {report_path}")

if __name__ == '__main__':
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else '.'
    analyzer = ThreatAnalyzer()
    print(analyzer.analyze(target))
