# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: threat_detection_tools.py
Назначение: Интеграция базы правил YARA и сканера Nuclei для URL.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
_yara_audit = ROOT / "04_Detection_Rules" / "YARA"
_yara_direct = ROOT / "Обнаружение угроз" / "YARA"
_yara_parent = ROOT.parent / "Обнаружение угроз" / "YARA"
YARA_DIR = _yara_audit if _yara_audit.is_dir() else (_yara_direct if _yara_direct.is_dir() else _yara_parent)

_nuclei_direct = ROOT / "Обнаружение угроз" / "40k-nuclei-templates" / "aditya"
_nuclei_parent = ROOT.parent / "Обнаружение угроз" / "40k-nuclei-templates" / "aditya"
NUCLEI_TEMPLATES_DIR = _nuclei_direct if _nuclei_direct.is_dir() else _nuclei_parent
YARA_CACHE_DIR = Path(__file__).resolve().parent / ".cache" / "yara_rules"

_LOADED_YARA_RULES: list[Any] | None = None

YARA_EXTENSIONS = (".yar", ".yara", ".yara.txt")

# Безопасный поднабор nuclei для URL из писем (не вся коллекция 40k)
NUCLEI_TAGS = "phishing,malware,takeover,evilginx,credential,c2,exposure,panel,tech"
NUCLEI_SEVERITY = "medium,high,critical"
NUCLEI_RATE_LIMIT = 20
NUCLEI_CONCURRENCY = 10
NUCLEI_TIMEOUT_SEC = 180


def _is_yara_file(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(YARA_EXTENSIONS)


def _collect_yara_sources() -> list[Path]:
    if not YARA_DIR.is_dir():
        return []
    files: list[Path] = []
    for path in YARA_DIR.rglob("*"):
        if path.is_file() and _is_yara_file(path):
            files.append(path)
    seen: set[str] = set()
    deduped: list[Path] = []
    for path in sorted(files):
        key = path.name.lower()
        if key in seen:
            continue
        seen.add(key)
        deduped.append(path)
    return deduped


def _fingerprint_yara_sources(files: list[Path]) -> str:
    h = hashlib.sha256()
    for path in files:
        try:
            stat = path.stat()
            h.update(path.name.lower().encode())
            h.update(str(int(stat.st_mtime)).encode())
            h.update(str(stat.st_size).encode())
        except OSError:
            h.update(path.name.lower().encode())
    return h.hexdigest()


def build_yara_cache(force: bool = False) -> dict[str, Any]:
    """Скомпилировать правила YARA в .yarac (обход Unicode-путей на Windows)."""
    files = _collect_yara_sources()
    result: dict[str, Any] = {
        "yara_dir": str(YARA_DIR),
        "source_files": len(files),
        "compiled": 0,
        "failed": 0,
        "cache_dir": str(YARA_CACHE_DIR),
    }
    if not files:
        result["status"] = "skipped"
        result["reason"] = f"каталог правил не найден: {YARA_DIR}"
        return result

    fingerprint = _fingerprint_yara_sources(files)
    manifest_path = YARA_CACHE_DIR / "manifest.json"
    fingerprint_path = YARA_CACHE_DIR / "fingerprint.txt"
    cache_valid = (
        not force
        and manifest_path.is_file()
        and fingerprint_path.is_file()
        and fingerprint_path.read_text(encoding="utf-8").strip() == fingerprint
    )
    if cache_valid:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        result["status"] = "cached"
        result["compiled"] = len(manifest)
        result["fingerprint"] = fingerprint
        return result

    try:
        import yara
    except ImportError:
        result["status"] = "skipped"
        result["reason"] = "yara-python не установлен в текущем окружении Python"
        return result

    YARA_CACHE_DIR.mkdir(parents=True, exist_ok=True)
    for old in YARA_CACHE_DIR.glob("*.yarac"):
        old.unlink(missing_ok=True)

    manifest: list[dict[str, str]] = []
    failed = 0
    for index, path in enumerate(files):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
            rules = yara.compile(sources={f"ns{index}": source})
            yarac_path = YARA_CACHE_DIR / f"{index}.yarac"
            rules.save(str(yarac_path))
            manifest.append({"index": str(index), "name": path.name, "yarac": str(yarac_path)})
        except Exception:
            failed += 1

    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")
    (YARA_CACHE_DIR / "fingerprint.txt").write_text(fingerprint, encoding="utf-8")
    result["status"] = "built"
    result["compiled"] = len(manifest)
    result["failed"] = failed
    result["fingerprint"] = fingerprint
    return result


def _load_yara_rulesets() -> list[Any]:
    global _LOADED_YARA_RULES
    if _LOADED_YARA_RULES is not None:
        return _LOADED_YARA_RULES

    try:
        import yara
    except ImportError:
        _LOADED_YARA_RULES = []
        return _LOADED_YARA_RULES

    cache_info = build_yara_cache()
    if cache_info.get("compiled", 0) == 0:
        _LOADED_YARA_RULES = []
        return _LOADED_YARA_RULES

    manifest = json.loads((YARA_CACHE_DIR / "manifest.json").read_text(encoding="utf-8"))
    loaded = []
    for entry in manifest:
        try:
            loaded.append((entry, yara.load(entry["yarac"])))
        except Exception:
            continue
    _LOADED_YARA_RULES = loaded
    return _LOADED_YARA_RULES


def scan_bytes_yara(data: bytes, *, rebuild_cache: bool = False) -> list[dict[str, Any]]:
    """Сканировать буфер всеми закэшированными правилами YARA."""
    if rebuild_cache:
        global _LOADED_YARA_RULES
        _LOADED_YARA_RULES = None
        build_yara_cache(force=True)

    hits: list[dict[str, Any]] = []
    for entry, rules in _load_yara_rulesets():
        try:
            for match in rules.match(data=data):
                hits.append({
                    "rule": match.rule,
                    "namespace": match.namespace,
                    "source_file": entry["name"],
                    "tags": list(match.tags),
                    "meta": dict(match.meta),
                    "strings": [
                        getattr(s, "identifier", s[1] if isinstance(s, (tuple, list)) and len(s) > 1 else str(s))
                        for s in match.strings[:10]
                    ],
                })
        except Exception:
            continue
    return hits


def find_nuclei_executable() -> Path | None:
    """Найти nuclei в PATH или типичных каталогах."""
    found = shutil_which("nuclei")
    if found:
        return Path(found)
    candidates = [
        Path(os.environ.get("USERPROFILE", "")) / "go" / "bin" / "nuclei.exe",
        ROOT / "Tools" / "nuclei.exe",
        ROOT / "bin" / "nuclei.exe",
    ]
    for path in candidates:
        if path.is_file():
            return path
    return None


def shutil_which(name: str) -> str | None:
    from shutil import which
    return which(name)


def collect_urls_for_nuclei(
    email_urls: list[str],
    attachment_analyses: list[dict[str, Any]],
) -> list[str]:
    urls = list(email_urls)
    for att in attachment_analyses:
        office = att.get("analysis", {}).get("office", {})
        activation = office.get("activation_on_open", {})
        urls.extend(activation.get("external_urls", []))
        doc_threats = office.get("document_threats", {})
        urls.extend(doc_threats.get("external_urls", []))
    normalized: list[str] = []
    for url in urls:
        url = url.strip()
        if not url:
            continue
        if url.startswith("\\\\"):
            continue
        if not url.lower().startswith(("http://", "https://")):
            if url.lower().startswith("https:/") and not url.lower().startswith("https://"):
                url = "https://" + url[7:]
            elif url.lower().startswith("http:/") and not url.lower().startswith("http://"):
                url = "http://" + url[6:]
            else:
                continue
        normalized.append(url)
    return list(dict.fromkeys(normalized))


def run_nuclei_on_urls(
    urls: list[str],
    *,
    output_jsonl: Path | None = None,
    templates_dir: Path | None = None,
) -> dict[str, Any]:
    """Запустить nuclei по URL из письма (поднабор шаблонов, лимиты нагрузки)."""
    templates = templates_dir or NUCLEI_TEMPLATES_DIR
    result: dict[str, Any] = {
        "templates_dir": str(templates),
        "urls": urls,
        "tags": NUCLEI_TAGS,
        "severity": NUCLEI_SEVERITY,
    }
    if not urls:
        result["status"] = "skipped"
        result["reason"] = "нет HTTP(S) URL для сканирования"
        return result
    if not templates.is_dir():
        result["status"] = "skipped"
        result["reason"] = f"каталог шаблонов не найден: {templates}"
        return result

    nuclei = find_nuclei_executable()
    if not nuclei:
        result["status"] = "skipped"
        result["reason"] = "nuclei не установлен (см. Обнаружение угроз/40k-nuclei-templates/ИСПОЛЬЗОВАНИЕ.md)"
        return result

    targets_file = output_jsonl.parent / "nuclei_targets.txt" if output_jsonl else Path.cwd() / "nuclei_targets.txt"
    targets_file.parent.mkdir(parents=True, exist_ok=True)
    targets_file.write_text("\n".join(urls) + "\n", encoding="utf-8")

    jsonl_path = output_jsonl or (targets_file.parent / "nuclei_results.jsonl")
    cmd = [
        str(nuclei),
        "-t", str(templates),
        "-l", str(targets_file),
        "-tags", NUCLEI_TAGS,
        "-severity", NUCLEI_SEVERITY,
        "-c", str(NUCLEI_CONCURRENCY),
        "-rate-limit", str(NUCLEI_RATE_LIMIT),
        "-jsonl",
        "-o", str(jsonl_path),
        "-silent",
        "-no-color",
    ]
    started = time.time()
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=NUCLEI_TIMEOUT_SEC,
        )
        result["exit_code"] = proc.returncode
        result["duration_sec"] = round(time.time() - started, 2)
        result["stderr"] = (proc.stderr or "")[-2000:]
        if proc.returncode != 0 and proc.stderr:
            result["status"] = "error"
            result["error"] = proc.stderr.strip()[:500]
            return result
    except subprocess.TimeoutExpired:
        result["status"] = "timeout"
        result["error"] = f"превышен лимит {NUCLEI_TIMEOUT_SEC} с"
        return result
    except Exception as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    findings: list[dict[str, Any]] = []
    if jsonl_path.is_file():
        for line in jsonl_path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

    result["status"] = "ok"
    result["findings_count"] = len(findings)
    result["findings"] = findings[:50]
    result["output_jsonl"] = str(jsonl_path)
    return result


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "build-yara-cache":
        info = build_yara_cache(force="--force" in sys.argv)
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print("Usage: python threat_detection_tools.py build-yara-cache [--force]")
