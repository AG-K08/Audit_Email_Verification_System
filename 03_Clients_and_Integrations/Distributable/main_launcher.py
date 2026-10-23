# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: main_launcher.py
Назначение: Прокси-скрипт запуска дистрибутивного пакета OMSA.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import sys
import os

# Добавляем путь к анализатору для корректных импортов
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.join(BASE_DIR, "src", "analyzer"))

try:
    from office_analyzer import main
except ImportError:
    from src.analyzer.office_analyzer import main

if __name__ == "__main__":
    main()
