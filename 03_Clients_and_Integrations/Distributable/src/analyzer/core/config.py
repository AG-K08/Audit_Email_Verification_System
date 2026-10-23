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
import os

# Дефолтные настройки (без секретов)
MAX_FILE_SIZE_MB = 100
MAX_EXTRACTED_SIZE_MB = 500
ENTROPY_THRESHOLD = 5.5
OFFLINE_MODE = True
CLEANUP_TEMP = True

# Уровни и веса угроз (согласно п.5 ТЗ)
THREAT_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 50,
    "MEDIUM": 20,
    "LOW": 5,
    "INFO": 0
}

# Пороги итоговой оценки
TOTAL_THRESHOLD_CRITICAL = 150
TOTAL_THRESHOLD_HIGH = 80
TOTAL_THRESHOLD_MEDIUM = 30
TOTAL_THRESHOLD_LOW = 5



