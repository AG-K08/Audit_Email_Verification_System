# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block6_ioc.py
Назначение: Блок 6: Извлечение сетевых и файловых индикаторов компрометации (IoC).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import json
import logging
import re
import time
from pathlib import Path

import requests

from core.models import BlockResult, ThreatIndicator, ThreatLevel
from core.config import AnalyzerConfig

log = logging.getLogger("Block6")

BLOCK_NAME = "block6_ioc"

URL_PATTERN = re.compile(
    r'https?://[^\s"\'<>\)\(]+|ftp://[^\s"\'<>\)\(]+', re.IGNORECASE
)
UNC_PATTERN = re.compile(r'\\\\[^\s"\'<>\\][^\s"\'<>]*')
IPV4_PATTERN = re.compile(r'\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b')
REGISTRY_KEY_PATTERN = re.compile(
    r'HKEY_[A-Z_]+\\[^\s"\'<>\n]+', re.IGNORECASE
)
WIN_PATH_PATTERN = re.compile(r'[A-Za-z]:\\[^\s"\'<>\n]{4,}')
UNIX_PATH_PATTERN = re.compile(r'/(?:tmp|var|etc|usr|home|bin|sbin)/[^\s"\'<>\n]+')

VT_API_URL = "https://www.virustotal.com/api/v3/urls"
VT_RATE_LIMIT_REQUESTS = 4
VT_RATE_LIMIT_PERIOD_SEC = 60
VT_CACHE_FILENAME = "vt_cache.json"


def run(
    block2_raw: dict,
    block3_raw: dict,
    block4_raw: dict,
    block5_raw: dict,
    work_dir: Path,
    cfg: AnalyzerConfig,
) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {}

    all_text_sources = _collect_text_sources(block2_raw, block3_raw, block4_raw, block5_raw)

    urls = _extract_urls(all_text_sources)
    ips = _extract_ips(all_text_sources)
    registry_keys = _extract_registry_keys(all_text_sources)
    win_paths = _extract_win_paths(all_text_sources)
    unix_paths = _extract_unix_paths(all_text_sources)

    raw["urls"] = list(urls)
    raw["ips"] = list(ips)
    raw["registry_keys"] = list(registry_keys)
    raw["win_paths"] = list(win_paths)
    raw["unix_paths"] = list(unix_paths)

    for url in urls:
        indicators.append(ThreatIndicator(
            indicator_id=f"B6.URL.{hash(url) & 0xFFFFFF:06X}",
            level=ThreatLevel.HIGH,
            description=f"URL обнаружен в коде",
            evidence=url[:120],
            location="vba_source",
        ))

    for ip in ips:
        indicators.append(ThreatIndicator(
            indicator_id=f"B6.IP.{ip.replace('.', '_')}",
            level=ThreatLevel.MEDIUM,
            description=f"IP-адрес обнаружен в коде",
            evidence=ip,
            location="vba_source",
        ))

    if not cfg.offline_mode and cfg.vt_api_key and urls:
        vt_results = _check_urls_virustotal(
            list(urls), cfg.vt_api_key, work_dir
        )
        raw["vt_results"] = vt_results
        indicators.extend(_build_vt_indicators(vt_results))

    if cfg.yara_rules_path and cfg.yara_rules_path.exists():
        yara_indicators = _run_yara(block2_raw, cfg.yara_rules_path)
        indicators.extend(yara_indicators)
        raw["yara_hits"] = len(yara_indicators)

    return BlockResult(
        block_name=BLOCK_NAME,
        success=True,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        threat_indicators=indicators,
        raw_findings=raw,
    )


def _collect_text_sources(
    block2_raw: dict,
    block3_raw: dict,
    block4_raw: dict,
    block5_raw: dict,
) -> list[str]:
    sources: list[str] = []

    for module in block2_raw.get("modules", []):
        code = module.get("code", "")
        if code:
            sources.append(code)

    pcode_raw = block3_raw.get("pcode_raw", "")
    if pcode_raw:
        sources.append(pcode_raw)

    sources.append(json.dumps(block5_raw))

    return sources

def _extract_urls(text_sources: list[str]) -> set[str]:
    urls: set[str] = set()
    for text in text_sources:
        for match in URL_PATTERN.finditer(text):
            url = match.group(0).rstrip('.,;)')
            urls.add(url)
        for match in UNC_PATTERN.finditer(text):
            urls.add(match.group(0))
    return urls


def _extract_ips(text_sources: list[str]) -> set[str]:
    ips: set[str] = set()
    for text in text_sources:
        for match in IPV4_PATTERN.finditer(text):
            octets = [int(match.group(i)) for i in range(1, 5)]
            if all(0 <= o <= 255 for o in octets):
                ips.add(match.group(0))
    return ips


def _extract_registry_keys(text_sources: list[str]) -> set[str]:
    keys: set[str] = set()
    for text in text_sources:
        for match in REGISTRY_KEY_PATTERN.finditer(text):
            keys.add(match.group(0)[:200])
    return keys


def _extract_win_paths(text_sources: list[str]) -> set[str]:
    paths: set[str] = set()
    for text in text_sources:
        for match in WIN_PATH_PATTERN.finditer(text):
            paths.add(match.group(0)[:200])
    return paths


def _extract_unix_paths(text_sources: list[str]) -> set[str]:
    paths: set[str] = set()
    for text in text_sources:
        for match in UNIX_PATH_PATTERN.finditer(text):
            paths.add(match.group(0)[:200])
    return paths


def _load_vt_cache(cache_path: Path) -> dict:
    if not cache_path.exists():
        return {}
    try:
        with cache_path.open("r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_vt_cache(cache_path: Path, cache: dict) -> None:
    try:
        with cache_path.open("w", encoding="utf-8") as f:
            json.dump(cache, f, ensure_ascii=False, indent=2)
    except Exception as exc:
        log.warning("Не удалось сохранить VT кеш: %s", exc)


def _check_urls_virustotal(
    urls: list[str],
    api_key: str,
    work_dir: Path,
) -> dict[str, dict]:
    import base64
    import time as time_module

    cache_path = work_dir / VT_CACHE_FILENAME
    cache = _load_vt_cache(cache_path)
    results: dict[str, dict] = {}

    request_count = 0

    for url in urls:
        if url in cache:
            results[url] = cache[url]
            continue

        if request_count > 0 and request_count % VT_RATE_LIMIT_REQUESTS == 0:
            log.info("VT rate limit: ожидание %d сек", VT_RATE_LIMIT_PERIOD_SEC)
            time_module.sleep(VT_RATE_LIMIT_PERIOD_SEC)

        result = _vt_check_single_url(url, api_key)
        request_count += 1

        if result is not None:
            results[url] = result
            cache[url] = result

    _save_vt_cache(cache_path, cache)
    return results


def _vt_check_single_url(url: str, api_key: str) -> dict | None:
    import base64

    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    headers = {"x-apikey": api_key}

    backoff_sec = 5
    for attempt in range(3):
        try:
            response = requests.get(
                f"https://www.virustotal.com/api/v3/urls/{url_id}",
                headers=headers,
                timeout=15,
            )
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                return {
                    "malicious": stats.get("malicious", 0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless": stats.get("harmless", 0),
                }
            if response.status_code == 429:
                import time as time_module
                log.warning("VT 429, backoff %d сек (попытка %d)", backoff_sec, attempt + 1)
                time_module.sleep(backoff_sec)
                backoff_sec *= 2
                continue
            if response.status_code == 404:
                return {"malicious": 0, "suspicious": 0, "harmless": 0}
            log.warning("VT вернул HTTP %d для URL: %s", response.status_code, url[:60])
            return None
        except requests.RequestException as exc:
            log.warning("Ошибка VT запроса: %s", exc)
            return None

    return None


def _build_vt_indicators(vt_results: dict[str, dict]) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []
    for url, result in vt_results.items():
        if result.get("malicious", 0) > 0:
            indicators.append(ThreatIndicator(
                indicator_id=f"B6.VT_MALICIOUS.{hash(url) & 0xFFFFFF:06X}",
                level=ThreatLevel.CRITICAL,
                description=f"VirusTotal: URL помечен как вредоносный ({result['malicious']} детектов)",
                evidence=url[:120],
                location="VirusTotal",
            ))
    return indicators


def _run_yara(block2_raw: dict, yara_rules_path: Path) -> list[ThreatIndicator]:
    try:
        import yara
    except ImportError:
        log.warning("yara-python не установлен, YARA-анализ пропущен")
        return []

    indicators: list[ThreatIndicator] = []

    rules = _compile_yara_rules(yara_rules_path)
    if not rules:
        return []

    for module in block2_raw.get("modules", []):
        code = module.get("code", "")
        if not code:
            continue
        try:
            matches = rules.match(data=code.encode("utf-8", errors="replace"))
            for match in matches:
                severity = match.meta.get("severity", "HIGH")
                try:
                    level = ThreatLevel(severity.upper())
                except ValueError:
                    level = ThreatLevel.HIGH

                indicators.append(ThreatIndicator(
                    indicator_id=f"B6.YARA.{match.rule[:30]}",
                    level=level,
                    description=f"YARA правило сработало: {match.rule}",
                    evidence=match.meta.get("description", match.rule),
                    location=module.get("name", "unknown"),
                ))
        except Exception as exc:
            log.debug("YARA матч упал для модуля %s: %s", module.get("name"), exc)

    return indicators


def _compile_yara_rules(yara_rules_path: Path):
    import yara

    rule_files = list(yara_rules_path.glob("*.yar")) + list(yara_rules_path.glob("*.yara"))
    if not rule_files:
        log.warning("YARA файлы не найдены в %s", yara_rules_path)
        return None

    filepaths = {f.stem: str(f) for f in rule_files}
    try:
        return yara.compile(filepaths=filepaths)
    except Exception as exc:
        log.error("Ошибка компиляции YARA правил: %s", exc)
        return None