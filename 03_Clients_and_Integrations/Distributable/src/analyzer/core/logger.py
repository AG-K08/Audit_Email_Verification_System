# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: logger.py
Назначение: Логгер и форматирование системных событий OMSA.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import logging
import os
from datetime import datetime

def setup_logger(output_dir: str, block_name: str = "ORCHESTRATOR"):
    # Создать директорию для логов, если её нет
    if not os.path.exists(output_dir):
        os.makedirs(output_dir, exist_ok=True)
    
    log_file = os.path.join(output_dir, "analysis.log")
    
    # Регулярный формат
    formatter = logging.Formatter(
        '[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s'
    )
    
    # Настройка корневого логгера
    logger = logging.getLogger(block_name)
    logger.setLevel(logging.DEBUG)
    
    # Обработчик для файла (DEBUG+)
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    
    # Обработчик для консоли (INFO+)
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    
    # Избежаем дублей, если логгер уже инициализирован
    if not logger.handlers:
        logger.addHandler(file_handler)
        logger.addHandler(console_handler)
    
    return logger



