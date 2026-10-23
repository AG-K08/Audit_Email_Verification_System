# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: config.py
Назначение: Загрузка и валидация конфигурации OMSA (Pydantic / YAML).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import os
from pathlib import Path
import yaml
from pydantic import BaseModel, Field


CONFIG_FILE_NAME = "config.yaml"
ENV_PREFIX = "OMSA_"

DEFAULT_MAX_FILE_SIZE_MB = 100
DEFAULT_MAX_EXTRACTED_SIZE_MB = 500
DEFAULT_ENTROPY_THRESHOLD = 5.5
DEFAULT_TOP_THREATS_COUNT = 5
DEFAULT_CLEANUP_TEMP = True
DEFAULT_OFFLINE_MODE = False
DEFAULT_ALWAYS_RUN_PCODE = False
DEFAULT_MAX_RECURSION_DEPTH = 3
DEFAULT_SUBPROCESS_TIMEOUT_SEC = 60


class AnalyzerConfig(BaseModel):
    output_dir: Path = Path("./results")
    max_file_size_mb: int = DEFAULT_MAX_FILE_SIZE_MB
    max_extracted_size_mb: int = DEFAULT_MAX_EXTRACTED_SIZE_MB
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD
    top_threats_count: int = DEFAULT_TOP_THREATS_COUNT
    cleanup_temp: bool = DEFAULT_CLEANUP_TEMP
    offline_mode: bool = DEFAULT_OFFLINE_MODE
    always_run_pcode: bool = DEFAULT_ALWAYS_RUN_PCODE
    max_recursion_depth: int = DEFAULT_MAX_RECURSION_DEPTH
    subprocess_timeout_sec: int = DEFAULT_SUBPROCESS_TIMEOUT_SEC
    vt_api_key: str | None = None
    yara_rules_path: Path | None = None


def _load_yaml_config(config_path: Path) -> dict:
    if not config_path.exists():
        return {}
    with config_path.open("r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def _apply_env_overrides(config_data: dict) -> dict:
    env_map = {
        f"{ENV_PREFIX}OUTPUT_DIR": "output_dir",
        f"{ENV_PREFIX}MAX_FILE_SIZE_MB": "max_file_size_mb",
        f"{ENV_PREFIX}MAX_EXTRACTED_SIZE_MB": "max_extracted_size_mb",
        f"{ENV_PREFIX}ENTROPY_THRESHOLD": "entropy_threshold",
        f"{ENV_PREFIX}OFFLINE_MODE": "offline_mode",
        f"{ENV_PREFIX}ALWAYS_RUN_PCODE": "always_run_pcode",
        f"{ENV_PREFIX}VT_API_KEY": "vt_api_key",
        f"{ENV_PREFIX}YARA_RULES_PATH": "yara_rules_path",
        f"{ENV_PREFIX}CLEANUP_TEMP": "cleanup_temp",
        f"{ENV_PREFIX}SUBPROCESS_TIMEOUT_SEC": "subprocess_timeout_sec",
    }
    result = dict(config_data)
    for env_key, config_key in env_map.items():
        value = os.environ.get(env_key)
        if value is not None:
            result[config_key] = value
    return result


def load_config(config_path: Path | None = None) -> AnalyzerConfig:
    path = config_path or Path(CONFIG_FILE_NAME)
    config_data = _load_yaml_config(path)
    config_data = _apply_env_overrides(config_data)
    return AnalyzerConfig(**config_data)