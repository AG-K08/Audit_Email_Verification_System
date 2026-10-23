# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: utils.py
Назначение: Вспомогательные криминалистические утилиты и энтропия Шеннона.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import math
from collections import Counter


def calculate_entropy_bytes(data: bytes) -> float:
    """
    Вычислить энтропию Шеннона для байтовой последовательности (bytes).

    Возвращает значение в диапазоне [0.0, 8.0] бит/байт.
    Возвращает 0.0 для пустых данных.
    Используется в block0_extraction.
    """
    if not data:
        return 0.0

    counts = Counter(data)
    total = len(data)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


def calculate_entropy(text: str) -> float:
    """
    Вычислить энтропию Шеннона для строки (str).

    Возвращает значение в диапазоне [0.0, log2(N)] бит/символ.
    Возвращает 0.0 для пустых строк.
    Используется в block2_vba_source.
    """
    if not text:
        return 0.0

    counts = Counter(text)
    total = len(text)
    entropy = 0.0

    for count in counts.values():
        probability = count / total
        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy