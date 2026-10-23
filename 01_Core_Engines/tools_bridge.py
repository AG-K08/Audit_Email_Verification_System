# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: tools_bridge.py
Назначение: Модульный интеграционный мост внешних аналитических инструментов (OfficeMalScanner, pdf-parser, YARA64, Strings, Munpack).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import os
import sys
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Any, Optional

# UTF-8 Safe Console IO
if sys.platform == 'win32':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

CURRENT_DIR = Path(__file__).resolve().parent
REPO_ROOT = CURRENT_DIR.parent
WORKSPACE_ROOT = REPO_ROOT.parent

# Базовые пути поиска инструментов
TOOLS_SEARCH_PATHS = [
    WORKSPACE_ROOT / "Tools",
    REPO_ROOT / "Tools",
]


class ExternalToolsBridge:
    def __init__(self):
        self.tools: Dict[str, Optional[Path]] = {
            "officemalscanner": self._locate_file("OfficeMalScanner.exe", "Анализ вредоносов/OfficeMalScanner_криминалистика_анализ документов/OfficeMalScanner"),
            "rtfscan": self._locate_file("RTFScan.exe", "Анализ вредоносов/OfficeMalScanner_криминалистика_анализ документов/OfficeMalScanner"),
            "pdf_parser": self._locate_file("pdf-parser.py", "Анализ вредоносов/pdf-parser_V0_7_8"),
            "yara64": self._locate_file("yara64.exe", "Обнаружение угроз/YARA/yara-v4.5.2-2326-win64"),
            "yara_rules_dir": self._locate_dir("Обнаружение угроз/YARA"),
            "strings64": self._locate_file("strings64.exe", "SysinternalsSuite"),
            "sigcheck64": self._locate_file("sigcheck64.exe", "SysinternalsSuite"),
            "munpack": self._locate_file("munpack20.exe", "Анализ вредоносов/munpack20_извлечение вложений из Eml файлов/munpack20/Release"),
            "cyberchef": self._locate_file("CyberChef_v10.5.2.html", "Анализ вредоносов/CyberChef_v10.5.2"),
        }

    def _locate_file(self, filename: str, subpath: str) -> Optional[Path]:
        for base in TOOLS_SEARCH_PATHS:
            cand = base / subpath / filename
            if cand.is_file():
                return cand
            # Рекурсивный поиск в папке base
            if base.is_dir():
                found = list(base.glob(f"**/{filename}"))
                if found:
                    return found[0]
        # Поиск в системном PATH
        sys_find = shutil.which(filename)
        return Path(sys_find) if sys_find else None

    def _locate_dir(self, subpath: str) -> Optional[Path]:
        for base in TOOLS_SEARCH_PATHS:
            cand = base / subpath
            if cand.is_dir():
                return cand
        return None

    def get_status(self) -> Dict[str, bool]:
        """Возвращает статус доступности каждого модуля"""
        return {k: (v is not None and (v.is_file() or v.is_dir())) for k, v in self.tools.items()}

    def run_command(self, cmd: List[str], timeout: int = 60, cwd: Optional[Path] = None) -> str:
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"
        env["PYTHONUTF8"] = "1"
        try:
            res = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                timeout=timeout,
                cwd=str(cwd) if cwd else None
            )
            return res.stdout + "\n" + res.stderr
        except subprocess.TimeoutExpired:
            return f"[ERROR] Время ожидания ({timeout}s) команды {' '.join(cmd)} истекло."
        except Exception as e:
            return f"[ERROR] Ошибка запуска команды: {e}"

    # --- 1. Модуль OfficeMalScanner ---
    def scan_office_malware(self, target_file: str) -> str:
        exe = self.tools.get("officemalscanner")
        if not exe or not exe.is_file():
            return "[-] OfficeMalScanner.exe не найден в каталоге Tools."
        
        target = Path(target_file).resolve()
        # OfficeMalScanner требует запуск из своей директории (зависит от Cadt.dll и Unzipper.dll)
        cmd = [str(exe), str(target), "scan", "info", "brute"]
        print(f"[*] Запуск модуля: OfficeMalScanner для {target.name}...")
        return self.run_command(cmd, timeout=90, cwd=exe.parent)

    # --- 2. Модуль RTFScan ---
    def scan_rtf(self, target_file: str) -> str:
        exe = self.tools.get("rtfscan")
        if not exe or not exe.is_file():
            return "[-] RTFScan.exe не найден в каталоге Tools."
        
        target = Path(target_file).resolve()
        cmd = [str(exe), str(target)]
        print(f"[*] Запуск модуля: RTFScan для {target.name}...")
        return self.run_command(cmd, timeout=60, cwd=exe.parent)

    # --- 3. Модуль pdf-parser ---
    def scan_pdf_deep(self, target_file: str) -> str:
        script = self.tools.get("pdf_parser")
        if not script or not script.is_file():
            return "[-] pdf-parser.py не найден в каталоге Tools."
        
        py_exe = sys.executable or "python"
        target = Path(target_file).resolve()
        
        print(f"[*] Запуск модуля: pdf-parser (статистика и скрипты) для {target.name}...")
        res_stats = self.run_command([py_exe, str(script), "--stats", str(target)])
        res_js = self.run_command([py_exe, str(script), "--search", "javascript", str(target)])
        res_openaction = self.run_command([py_exe, str(script), "--search", "openaction", str(target)])
        
        output = [
            "=== [pdf-parser] СТАТИСТИКА ОБЪЕКТОВ ===",
            res_stats.strip(),
            "\n=== [pdf-parser] ПОИСК JAVASCRIPT ===",
            res_js.strip() if res_js.strip() else "JavaScript не обнаружен.",
            "\n=== [pdf-parser] ПОИСК OPENACTION ===",
            res_openaction.strip() if res_openaction.strip() else "OpenAction не обнаружен."
        ]
        return "\n".join(output)

    # --- 4. Модуль YARA 64 ---
    def scan_yara(self, target_file: str) -> str:
        yara_exe = self.tools.get("yara64")
        if not yara_exe or not yara_exe.is_file():
            return "[-] yara64.exe не найден в каталоге Tools."
        
        target = Path(target_file).resolve()
        if not target.exists():
            return f"[-] Целевой файл не найден: {target}"

        rules_file = REPO_ROOT / "04_Detection_Rules" / "professional_threats.yar"
        if not rules_file.is_file():
            # Попробуем взять правила из Tools/Обнаружение угроз/YARA
            r_dir = self.tools.get("yara_rules_dir")
            if r_dir and r_dir.is_dir():
                found_rules = list(r_dir.glob("*.yar*"))
                if found_rules:
                    rules_file = found_rules[0]

        if not rules_file.is_file():
            return "[-] Файл правил YARA не найден."

        cmd = [str(yara_exe), "-w", "-m", "-s", str(rules_file), str(target)]
        print(f"[*] Запуск модуля: YARA64 для {target.name}...")
        return self.run_command(cmd, timeout=45)

    # --- 5. Модуль Sysinternals Strings ---
    def extract_strings(self, target_file: str, min_len: int = 6) -> str:
        exe = self.tools.get("strings64")
        target = Path(target_file).resolve()
        
        if exe and exe.is_file():
            cmd = [str(exe), "-accepteula", "-a", "-u", "-n", str(min_len), str(target)]
            raw = self.run_command(cmd, timeout=30)
        else:
            # Чистый Python-фолбэк
            try:
                with open(target, "rb") as f:
                    content = f.read(1048576) # 1 MB
                import re
                ascii_strs = re.findall(rb"[\x20-\x7E]{" + str(min_len).encode() + rb",}", content)
                raw = "\n".join(s.decode('ascii', errors='ignore') for s in ascii_strs)
            except Exception as e:
                raw = f"Ошибка чтения строк: {e}"

        # Фильтрация только ценных для форензики строк (URLs, IPs, EXE, Powershell, Base64)
        lines = raw.splitlines()
        valuable = []
        for l in lines:
            line = l.strip()
            if any(k in line.lower() for k in ("http://", "https://", "powershell", "cmd.exe", ".exe", ".dll", "rundll", "wscript", "cscript", "autoopen", "document_open")):
                valuable.append(line)
        
        header = f"=== [Strings Forensics] Извлечено подозрительных строк: {len(valuable)} ==="
        return header + "\n" + "\n".join(valuable[:100])

    # --- 6. Модуль распаковки Munpack ---
    def unpack_eml(self, eml_file: str, out_dir: str) -> str:
        exe = self.tools.get("munpack")
        target = Path(eml_file).resolve()
        dst = Path(out_dir).resolve()
        dst.mkdir(parents=True, exist_ok=True)
        
        if exe and exe.is_file():
            cmd = [str(exe), "-q", str(target)]
            print(f"[*] Запуск нативного Munpack для {target.name}...")
            return self.run_command(cmd, timeout=30, cwd=dst)
        return "[-] Munpack.exe не найден."


# Глобальный инстанс моста
bridge = ExternalToolsBridge()

if __name__ == "__main__":
    print("=== Статус подключения внешних криминалистических модулей ===")
    status = bridge.get_status()
    for name, ok in status.items():
        path = bridge.tools.get(name)
        status_icon = "✅" if ok else "❌"
        print(f"  {status_icon} {name:20}: {path or 'НЕ НАЙДЕН'}")
