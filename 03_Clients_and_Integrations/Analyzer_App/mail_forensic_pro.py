# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: mail_forensic_pro.py
Назначение: Графический центр расследований аналитика «Mail Forensic Pro» (Red Edition v4.0).
Модульная интеграция: Внутренние движки OMSA + Внешние утилиты Tools (OfficeMalScanner, pdf-parser, YARA, Strings, CyberChef).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import os
import sys
import shutil
import datetime
import subprocess
import tkinter as tk
from pathlib import Path
from tkinter import ttk, filedialog, messagebox, simpledialog
import threading
import webbrowser
import hashlib

# Гарантия безопасной работы с Unicode/Emoji в stdout/stderr Windows
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False
    DND_FILES = None
    TkinterDnD = None

# Paths and Resource Handling
is_frozen = getattr(sys, 'frozen', False)
if is_frozen:
    bundle_dir = getattr(sys, '_MEIPASS', os.path.dirname(os.path.abspath(__file__)))
    SCRIPTS_DIR = os.path.join(bundle_dir, "Scripts")
    BASE_DIR = os.environ.get("MAIL_FORENSIC_HOME", str(Path.home() / "MailForensicPro"))
    p_core = Path(SCRIPTS_DIR)
else:
    BASE_DIR = str(Path(__file__).resolve().parent.parent.parent)
    p_core = Path(BASE_DIR) / "01_Core_Engines"
    SCRIPTS_DIR = str(p_core if p_core.is_dir() else (Path(BASE_DIR) / "Scripts"))

if str(p_core) not in sys.path:
    sys.path.insert(0, str(p_core))

try:
    from tools_bridge import bridge
except ImportError:
    bridge = None

CASES_DIR = str(Path(BASE_DIR) / "06_Audit_Tests_and_Samples" / "Cases")

# Red / Obsidian / Gray Palette
BG_DEEP = "#0A0A0A"
BG_CARD = "#171717"
ACCENT_RED = "#E11D48"  # Rose-600
DARK_RED = "#881337"    # Rose-900
LIGHT_RED = "#FB7185"   # Rose-400
TEXT_WHITE = "#FAFAFA"
TEXT_GRAY = "#A1A1AA"
BORDER_GRAY = "#27272A"


class FishingAnalyzerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("MailForensic Pro v4.0 (Red Edition) | AG-K08 (@And_8)")
        self.root.geometry("1220x920")
        self.root.minsize(1050, 780)
        self.root.configure(bg=BG_DEEP)
        self.selected_file = None
        self.last_report = None
        
        self.setup_ui()
        self.setup_dnd()
        self.log("Система инициализирована. Дизайн: Red Edition v4.0 (OMSA v1.0)", "SUCCESS")
        
        # Проверка доступности внешних модулей
        if bridge:
            status = bridge.get_status()
            active_count = sum(1 for v in status.values() if v)
            self.log(f"Подключено внешних аналитических инструментов: {active_count}/{len(status)}", "SUCCESS")
            for t_name, ok in status.items():
                if ok:
                    self.log(f"  [+] Доступен модуль: {t_name}", "INFO")

    def setup_ui(self):
        # 1. Header with branding
        header = tk.Frame(self.root, bg=BG_CARD, height=110)
        header.pack(fill="x", padx=0, pady=0)
        
        tk.Frame(header, bg=ACCENT_RED, width=8).pack(side="left", fill="y")
        
        content_header = tk.Frame(header, bg=BG_CARD)
        content_header.pack(side="left", padx=25, fill="y")

        tk.Label(content_header, text="🛡️ MAILFORENSIC PRO", bg=BG_CARD, fg=TEXT_WHITE, 
                 font=("Segoe UI Semibold", 24)).pack(anchor="w", pady=(15, 0))
        tk.Label(content_header, text="INTEGRATED EMAIL & MALWARE FORENSICS SYSTEM | AG-K08 (@And_8)", bg=BG_CARD, fg=ACCENT_RED, 
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(0, 15))

        # Top Right Badges
        badge_frame = tk.Frame(header, bg=BG_CARD)
        badge_frame.pack(side="right", padx=25, pady=20)
        tk.Label(badge_frame, text="RELEASE v4.0 RED", bg=DARK_RED, fg=TEXT_WHITE, 
                 font=("Segoe UI Bold", 9), padx=10, pady=4).pack(anchor="e")

        # 2. Main Container
        main_frame = tk.Frame(self.root, bg=BG_DEEP, padx=25, pady=12)
        main_frame.pack(fill="both", expand=True)

        # Target Selector Area
        self.file_frame = tk.LabelFrame(main_frame, text=" [ 🎯 ИССЛЕДУЕМЫЙ ОБЪЕКТ / ТАРГЕТ ] ", bg=BG_DEEP, fg=ACCENT_RED, 
                                        font=("Segoe UI", 10, "bold"), padx=15, pady=12, borderwidth=1, relief="solid")
        self.file_frame.pack(fill="x", pady=(0, 10))

        self.lbl_path = tk.Label(self.file_frame, text="Перетащите файл (.eml, .msg, .pdf, .docx, .rtf) сюда или нажмите «ВЫБРАТЬ»...", 
                                 bg=BG_DEEP, fg=TEXT_GRAY, font=("Consolas", 10), wraplength=900, justify="left")
        self.lbl_path.pack(side="left", fill="x", expand=True)

        btn_select = tk.Button(self.file_frame, text="📂 ВЫБРАТЬ ФАЙЛ", bg=ACCENT_RED, fg=TEXT_WHITE, 
                               font=("Segoe UI Bold", 9), command=self.select_file, relief="flat", padx=18, pady=6, cursor="hand2")
        btn_select.pack(side="right")

        # Row 1: Primary Pipeline Actions
        cmd_frame_top = tk.Frame(main_frame, bg=BG_DEEP)
        cmd_frame_top.pack(fill="x", pady=(0, 10))

        self.btn_analyze = self.create_button(cmd_frame_top, "🚀 ПОЛНЫЙ АУДИТ (0-9)", ACCENT_RED, self.start_full_analysis)
        self.btn_analyze.pack(side="left", padx=(0, 10))

        self.btn_report = self.create_button(cmd_frame_top, "📝 ОТКРЫТЬ ОТЧЕТ", "#27272A", self.open_report)
        self.btn_report.pack(side="left", padx=5)

        self.btn_case = self.create_button(cmd_frame_top, "📦 В КЕЙС", "#1F2937", self.move_to_case)
        self.btn_case.pack(side="left", padx=5)

        self.btn_vt = self.create_button(cmd_frame_top, "🔍 VIRUSTOTAL", "#374151", self.check_vt)
        self.btn_vt.pack(side="left", padx=5)

        self.btn_sandbox = self.create_button(cmd_frame_top, "🌐 ANY.RUN", "#4B5563", self.open_sandbox)
        self.btn_sandbox.pack(side="right")

        # Row 2: Modular Internal Engines (OMSA Suite)
        cmd_frame_omsa = tk.LabelFrame(main_frame, text=" [ 🧩 ВНУТРЕННИЕ МОДУЛИ ЯДРА OMSA ] ", bg=BG_DEEP, fg=TEXT_GRAY,
                                       font=("Segoe UI", 8, "bold"), padx=10, pady=6, borderwidth=1, relief="solid")
        cmd_frame_omsa.pack(fill="x", pady=(0, 8))

        self.create_small_button(cmd_frame_omsa, "📧 Аудит письма (SPF/DKIM/URLs)", self.run_module_email).pack(side="left", padx=4)
        self.create_small_button(cmd_frame_omsa, "📄 OMSA (Макросы Office)", self.run_module_office).pack(side="left", padx=4)
        self.create_small_button(cmd_frame_omsa, "📑 Метаданные / HEX (PDF)", self.run_module_pdf).pack(side="left", padx=4)
        self.create_small_button(cmd_frame_omsa, "📎 Карвинг вложений / Stego", self.run_module_carve).pack(side="left", padx=4)

        # Row 3: Modular External Tools (Connected from Tools/)
        cmd_frame_tools = tk.LabelFrame(main_frame, text=" [ 🛠️ ВНЕШНИЕ КРИМИНАЛИСТИЧЕСКИЕ ИНСТРУМЕНТЫ (TOOLS) ] ", bg=BG_DEEP, fg=LIGHT_RED,
                                        font=("Segoe UI", 8, "bold"), padx=10, pady=6, borderwidth=1, relief="solid")
        cmd_frame_tools.pack(fill="x", pady=(0, 10))

        self.create_tool_button(cmd_frame_tools, "🛠️ OfficeMalScanner", self.run_tool_officemalscanner).pack(side="left", padx=4)
        self.create_tool_button(cmd_frame_tools, "📑 pdf-parser (Didier)", self.run_tool_pdfparser).pack(side="left", padx=4)
        self.create_tool_button(cmd_frame_tools, "🎯 YARA 64 (База правил)", self.run_tool_yara).pack(side="left", padx=4)
        self.create_tool_button(cmd_frame_tools, "🔎 Strings (Sysinternals)", self.run_tool_strings).pack(side="left", padx=4)
        self.create_tool_button(cmd_frame_tools, "🍳 Открыть CyberChef", self.open_cyberchef, color="#991B1B").pack(side="right", padx=4)

        # Progress bar
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Red.Horizontal.TProgressbar", thickness=6, troughcolor=BG_CARD, background=ACCENT_RED, borderwidth=0)
        
        self.progress = ttk.Progressbar(main_frame, orient="horizontal", mode="determinate", style="Red.Horizontal.TProgressbar")
        self.progress.pack(fill="x", pady=(0, 4))
        
        self.status = tk.Label(main_frame, text="ГОТОВ К КРИМИНАЛИСТИЧЕСКОМУ АНАЛИЗУ", bg=BG_DEEP, fg=TEXT_GRAY, font=("Segoe UI Semibold", 8))
        self.status.pack(anchor="e", pady=(0, 6))

        # Terminal Box (Real-time live audit)
        term_frame = tk.Frame(main_frame, bg=BORDER_GRAY, padx=1, pady=1)
        term_frame.pack(fill="both", expand=True)
        
        self.terminal = tk.Text(term_frame, bg="#050505", fg=TEXT_WHITE, font=("Consolas", 10), 
                                borderwidth=0, relief="flat", insertbackground=ACCENT_RED, 
                                padx=15, pady=15)
        self.terminal.pack(fill="both", expand=True)

    def setup_dnd(self):
        if not HAS_DND:
            return
        try:
            self.file_frame.drop_target_register(DND_FILES)
            self.file_frame.dnd_bind('<<Drop>>', self.handle_drop)
            self.lbl_path.drop_target_register(DND_FILES)
            self.lbl_path.dnd_bind('<<Drop>>', self.handle_drop)
        except Exception:
            pass

    def handle_drop(self, event):
        file_path = event.data.strip('{}').strip('"')
        if os.path.isfile(file_path):
            self.selected_file = os.path.abspath(file_path)
            self.lbl_path.config(text=self.selected_file, fg=LIGHT_RED)
            self.log(f"Мишень получена (Drag & Drop): {os.path.basename(file_path)}", "SUCCESS")
        else:
            self.log("Ошибка: Перетаскиваемый объект не является файлом", "ERR")

    def create_button(self, parent, text, color, cmd):
        btn = tk.Button(parent, text=text, bg=color, fg=TEXT_WHITE, font=("Segoe UI Bold", 9),
                        command=cmd, relief="flat", padx=16, pady=8, cursor="hand2",
                        activebackground=TEXT_WHITE, activeforeground=color)
        return btn

    def create_small_button(self, parent, text, cmd, color="#27272A"):
        btn = tk.Button(parent, text=text, bg=color, fg=TEXT_WHITE, font=("Segoe UI", 8),
                        command=cmd, relief="flat", padx=10, pady=4, cursor="hand2",
                        activebackground=TEXT_WHITE, activeforeground=color)
        return btn

    def create_tool_button(self, parent, text, cmd, color="#374151"):
        btn = tk.Button(parent, text=text, bg=color, fg=TEXT_WHITE, font=("Segoe UI Bold", 8),
                        command=cmd, relief="flat", padx=10, pady=4, cursor="hand2",
                        activebackground=LIGHT_RED, activeforeground=TEXT_WHITE)
        return btn

    def log(self, text, type="INFO"):
        colors = {"INFO": TEXT_WHITE, "WARN": "#FCD34D", "ERR": "#F43F5E", "SUCCESS": "#10B981"}
        tag = f"[{datetime.datetime.now().strftime('%H:%M:%S')}] "
        self.terminal.tag_config(type, foreground=colors.get(type, TEXT_WHITE))
        self.terminal.insert(tk.END, tag + str(text) + "\n", type)
        self.terminal.see(tk.END)
        self.root.update_idletasks()

    def select_file(self):
        f = filedialog.askopenfilename(
            title="Выбор исследуемого объекта",
            filetypes=[
                ("Все поддерживаемые форматы", "*.eml;*.msg;*.pdf;*.doc;*.docx;*.docm;*.xls;*.xlsx;*.rtf"),
                ("Почтовые сообщения", "*.eml;*.msg"),
                ("Документы Office", "*.doc;*.docx;*.docm;*.xls;*.xlsx;*.rtf"),
                ("PDF файлы", "*.pdf"),
                ("Все файлы", "*.*")
            ]
        )
        if f:
            self.selected_file = os.path.abspath(f)
            self.lbl_path.config(text=self.selected_file, fg=LIGHT_RED)
            self.log(f"Выбран объект для расследования: {os.path.basename(self.selected_file)}")

    # --- Полный конвейер анализа (Все модули) ---
    def start_full_analysis(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Сначала выберите файл для исследования!")
            return
        self.btn_analyze.config(state="disabled")
        threading.Thread(target=self.run_full_pipeline, daemon=True).start()

    def run_full_pipeline(self):
        try:
            f = self.selected_file
            ext = os.path.splitext(f.lower())[1]
            self.progress['value'] = 10
            self.status.config(text="СТАРТ ПОЛНОГО КОМПЛЕКСНОГО АУДИТА...")
            
            # Если это письмо (.eml/.msg)
            if ext in ['.eml', '.msg']:
                self.log(">>> [ЭТАП 0-9] Анализ письма, заголовков и вложений...", "INFO")
                self.run_script("analyze_threats.py", [f])
                self.last_report = os.path.join(os.path.dirname(f), "FINAL_REPORT.md")
            
            self.progress['value'] = 50
            self.status.config(text="СКАНИРОВАНИЕ ВЛОЖЕНИЙ ВНЕШНИМИ И ВНУТРЕННИМИ МОДУЛЯМИ...")
            
            # Если это документ
            if ext in ['.pdf']:
                self.log(">>> [МОДУЛЬ PDF] Запуск metadata_hex_scanner и pdf-parser...", "INFO")
                self.run_script("metadata_hex_scanner.py", [f])
                if bridge:
                    self.log(bridge.scan_pdf_deep(f), "INFO")
            elif ext in ['.doc', '.docx', '.docm', '.xls', '.xlsx', '.rtf']:
                self.log(">>> [МОДУЛЬ OFFICE] Запуск OMSA и OfficeMalScanner...", "INFO")
                self.run_script("safe_office_deep_scan.py", [f])
                if bridge:
                    self.log(bridge.scan_office_malware(f), "INFO")
            
            # Карвинг скрытых оверлеев
            self.log(">>> [CARVER] Поиск скрытых картинок и стеганографии...", "INFO")
            self.run_script("carve_images.py", [f])
            
            self.progress['value'] = 100
            self.status.config(text="АНАЛИЗ ЗАВЕРШЕН (100% SUCCESS)")
            self.log("✅ ВСЕ МОДУЛИ ЗАВЕРШИЛИ РАБОТУ УСПЕШНО", "SUCCESS")
            
            self.check_vt(auto=True)
            
        except Exception as e:
            self.log(f"❌ КРИТИЧЕСКИЙ СБОЙ: {e}", "ERR")
        finally:
            self.btn_analyze.config(state="normal")

    # --- Модульные запуски внутренних движков ---
    def run_module_email(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Выберите файл письма (.eml / .msg)!")
            return
        threading.Thread(target=lambda: self.run_script("analyze_threats.py", [self.selected_file]), daemon=True).start()

    def run_module_office(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Выберите документ Office (DOC, DOCX, XLS, RTF)!")
            return
        threading.Thread(target=lambda: self.run_script("safe_office_deep_scan.py", [self.selected_file]), daemon=True).start()

    def run_module_pdf(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Выберите PDF файл!")
            return
        threading.Thread(target=lambda: self.run_script("metadata_hex_scanner.py", [self.selected_file]), daemon=True).start()

    def run_module_carve(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Выберите файл для карвинга!")
            return
        threading.Thread(target=lambda: self.run_script("carve_images.py", [self.selected_file]), daemon=True).start()

    # --- Модульные запуски внешних инструментов Tools ---
    def run_tool_officemalscanner(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Сначала выберите документ Office!")
            return
        if not bridge:
            self.log("Модуль tools_bridge недоступен", "ERR")
            return
        self.log(f"Запуск внешнего модуля OfficeMalScanner для: {os.path.basename(self.selected_file)}", "INFO")
        threading.Thread(target=lambda: self.log(bridge.scan_office_malware(self.selected_file), "INFO"), daemon=True).start()

    def run_tool_pdfparser(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Сначала выберите файл PDF!")
            return
        if not bridge:
            self.log("Модуль tools_bridge недоступен", "ERR")
            return
        self.log(f"Запуск внешнего модуля pdf-parser для: {os.path.basename(self.selected_file)}", "INFO")
        threading.Thread(target=lambda: self.log(bridge.scan_pdf_deep(self.selected_file), "INFO"), daemon=True).start()

    def run_tool_yara(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Сначала выберите файл для сигнатурного аудита!")
            return
        if not bridge:
            self.log("Модуль tools_bridge недоступен", "ERR")
            return
        self.log(f"Запуск нативного сканера YARA64 для: {os.path.basename(self.selected_file)}", "INFO")
        threading.Thread(target=lambda: self.log(bridge.scan_yara(self.selected_file), "INFO"), daemon=True).start()

    def run_tool_strings(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Сначала выберите файл!")
            return
        if not bridge:
            self.log("Модуль tools_bridge недоступен", "ERR")
            return
        self.log(f"Извлечение строк Sysinternals Strings для: {os.path.basename(self.selected_file)}", "INFO")
        threading.Thread(target=lambda: self.log(bridge.extract_strings(self.selected_file), "INFO"), daemon=True).start()

    def run_script(self, name, args):
        script_path = os.path.join(SCRIPTS_DIR, name)
        python_cmd = sys.executable if sys.executable else "python"
        cmd = [python_cmd, script_path] + args
        
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        
        try:
            process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding='utf-8',
                errors='replace',
                shell=False,
                env=env
            )
            for line in process.stdout:
                self.terminal.insert(tk.END, line)
                self.terminal.see(tk.END)
                self.root.update_idletasks()
            process.wait()
        except Exception as e:
            self.log(f"Ошибка запуска {name}: {e}", "ERR")

    def open_report(self):
        target_report = None
        candidates = []
        if self.last_report:
            candidates.append(self.last_report)
        if self.selected_file:
            target_dir = os.path.dirname(self.selected_file)
            candidates.append(os.path.join(target_dir, "FINAL_REPORT.md"))
            candidates.append(os.path.join(target_dir, "ОТЧЕТ_АНАЛИЗА.txt"))
        candidates.append("FINAL_REPORT.md")
        candidates.append("ОТЧЕТ_АНАЛИЗА.txt")

        for c in candidates:
            if c and os.path.exists(c):
                target_report = c
                break

        if target_report:
            self.log(f"Открытие отчета: {target_report}", "SUCCESS")
            try:
                os.startfile(target_report)
            except Exception:
                subprocess.Popen(["notepad.exe", target_report])
        else:
            messagebox.showinfo("Информация", "Отчет еще не сформирован. Запустите анализ объекта.")

    def move_to_case(self):
        if not self.selected_file:
            messagebox.showwarning("Внимание", "Файл не выбран!")
            return
        name = simpledialog.askstring("Кейс-Менеджер", "Введите имя кейса/инцидента (например: Corp_Phish_2026):")
        if not name:
            return
        clean_name = "".join(c for c in name if c.isalnum() or c in ("_", "-")).strip()
        folder = os.path.join(CASES_DIR, f"{datetime.datetime.now().strftime('%Y-%m-%d')}_{clean_name}")
        os.makedirs(folder, exist_ok=True)
        
        new_file = os.path.join(folder, os.path.basename(self.selected_file))
        shutil.copy2(self.selected_file, new_file)
        self.selected_file = new_file
        self.lbl_path.config(text=new_file, fg=LIGHT_RED)
        self.log(f"Объект успешно перемещен в кейс: {folder}", "SUCCESS")
        
        try:
            os.startfile(folder)
        except Exception:
            pass

    def check_vt(self, auto=False):
        target = self.selected_file
        if target and os.path.exists(target):
            try:
                with open(target, 'rb') as f_binary:
                    sha256 = hashlib.sha256(f_binary.read()).hexdigest()
                self.log(f"SHA256: {sha256}", "INFO")
                url = f"https://www.virustotal.com/gui/file/{sha256}"
                
                try:
                    self.root.clipboard_clear()
                    self.root.clipboard_append(sha256)
                except Exception:
                    pass
                
                if auto:
                    self.log(f"VirusTotal URL: {url} (Хеш скопирован в буфер)", "INFO")
                else:
                    self.log(f"Переход к отчету VirusTotal: {url}", "INFO")
                    try:
                        webbrowser.open(url)
                    except Exception as wb_err:
                        self.log(f"Не удалось открыть браузер ВМ: {wb_err}", "WARN")
            except Exception as e:
                self.log(f"Ошибка вычисления хеша: {e}", "ERR")

    def open_sandbox(self):
        try:
            webbrowser.open("https://app.any.run")
            self.log("Открыт портал интерактивной песочницы ANY.RUN", "INFO")
        except Exception as e:
            self.log(f"Не удалось открыть Any.Run: {e}", "WARN")

    def open_cyberchef(self):
        chef_candidates = [
            os.path.join(BASE_DIR, "..", "Tools", "Анализ вредоносов", "CyberChef_v10.5.2", "CyberChef_v10.5.2.html"),
            os.path.join(BASE_DIR, "Tools", "CyberChef_v10.5.2", "CyberChef_v10.5.2.html")
        ]
        for c in chef_candidates:
            if os.path.exists(c):
                try:
                    os.startfile(c)
                    self.log(f"Локальный декодер CyberChef запущен: {c}", "SUCCESS")
                    return
                except Exception:
                    pass
        webbrowser.open("https://gchq.github.io/CyberChef/")
        self.log("Открыта онлайн-версия CyberChef", "INFO")


if __name__ == "__main__":
    if HAS_DND and TkinterDnD:
        try:
            root = TkinterDnD.Tk()
        except Exception:
            root = tk.Tk()
    else:
        root = tk.Tk()
    app = FishingAnalyzerGUI(root)
    root.mainloop()
