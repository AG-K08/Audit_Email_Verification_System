# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: checks_quishing.py
Назначение: Модуль выявления Quishing (фишинг через QR-коды в изображениях и PDF).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations

import io
import re
import struct
import zlib
from pathlib import Path
from typing import List, Tuple, Dict, Any, Optional

from .scoring import Finding, Category, Severity


class QuishingChecker:
    """Детектор и анализатор атак Quishing (QR-code Phishing)."""

    def __init__(self):
        self._has_pyzbar = False
        try:
            from pyzbar.pyzbar import decode as pyzbar_decode
            self._pyzbar_decode = pyzbar_decode
            self._has_pyzbar = True
        except Exception:
            self._pyzbar_decode = None

        self._has_cv2 = False
        try:
            import cv2
            self._cv2 = cv2
            self._qr_detector = cv2.QRCodeDetector()
            self._has_cv2 = True
        except Exception:
            self._cv2 = None

        try:
            from PIL import Image
            self._image_cls = Image
        except ImportError:
            self._image_cls = None

    def scan_image(self, filename: str, data: bytes) -> Tuple[List[Finding], List[str]]:
        """
        Сканирует бинарные данные изображения на наличие QR-кода.
        Возвращает:
          - список Finding
          - список извлеченных из QR-кодов ссылок (URLs)
        """
        findings: List[Finding] = []
        extracted_urls: List[str] = []

        if not data or len(data) < 64:
            return findings, extracted_urls

        img = None
        if self._image_cls is not None:
            try:
                img = self._image_cls.open(io.BytesIO(data))
            except Exception:
                img = None

        # 1. Попытка декодирования через внешние библиотеки (pyzbar / OpenCV), если доступны
        decoded_text = self._try_external_decode(img, data)
        if decoded_text:
            url_match = re.search(r"https?://[^\s<>\"')\]]+", decoded_text)
            target_url = url_match.group(0) if url_match else decoded_text
            if url_match:
                extracted_urls.append(target_url)

            findings.append(Finding(
                id="ATT_QUISHING_DETECTED",
                category=Category.ATTACHMENT,
                severity=Severity.CRITICAL,
                weight=75,
                title="Обнаружена атака Quishing: в изображение внедрен QR-код с внешней ссылкой",
                evidence=f"Файл '{filename}' содержит QR-код: {target_url[:120]}",
                confidence=0.99
            ))
            return findings, extracted_urls

        # 2. Автономный алгоритм выявления паттернов QR Finder (1:1:3:1:1) на базе Pillow или stdlib PNG
        has_finder_pattern = (
            self._detect_qr_finder_patterns(img)
            if img is not None
            else self._detect_qr_finder_patterns_raw_png(data)
        )
        if has_finder_pattern:
            findings.append(Finding(
                id="ATT_QUISHING_SUSPECTED",
                category=Category.ATTACHMENT,
                severity=Severity.HIGH,
                weight=55,
                title="В графическом вложении обнаружен характерный шаблон QR-кода (подозрение на Quishing)",
                evidence=f"Файл '{filename}': обнаружены метки позиционирования Finder Patterns (1:1:3:1:1)",
                confidence=0.88
            ))

        return findings, extracted_urls

    def _try_external_decode(self, img: Any, raw_data: bytes) -> Optional[str]:
        if img is not None and self._has_pyzbar and self._pyzbar_decode:
            try:
                results = self._pyzbar_decode(img)
                if results:
                    return results[0].data.decode("utf-8", errors="replace")
            except Exception:
                pass

        if self._has_cv2 and self._cv2:
            try:
                import numpy as np
                nparr = np.frombuffer(raw_data, np.uint8)
                cv_img = self._cv2.imdecode(nparr, self._cv2.IMREAD_COLOR)
                if cv_img is not None:
                    decoded_info, _, _ = self._qr_detector.detectAndDecode(cv_img)
                    if decoded_info:
                        return decoded_info
            except Exception:
                pass

        return None

    @staticmethod
    def _check_rows_for_finder(rows: List[List[int]]) -> bool:
        if not rows or not rows[0]:
            return False
        sh = len(rows)
        sw = len(rows[0])
        if sw < 40 or sh < 40:
            return False
        finder_candidates = 0
        step = max(2, sh // 80)
        for y in range(0, sh, step):
            row = rows[y]
            runs = []
            current_color = 0 if row[0] < 128 else 255
            current_len = 0
            for x in range(sw):
                color = 0 if row[x] < 128 else 255
                if color == current_color:
                    current_len += 1
                else:
                    runs.append((current_color, current_len))
                    current_color = color
                    current_len = 1
            runs.append((current_color, current_len))

            for i in range(len(runs) - 4):
                c1, l1 = runs[i]
                c2, l2 = runs[i + 1]
                c3, l3 = runs[i + 2]
                c4, l4 = runs[i + 3]
                c5, l5 = runs[i + 4]
                if c1 == 0 and c2 != 0 and c3 == 0 and c4 != 0 and c5 == 0:
                    total = l1 + l2 + l3 + l4 + l5
                    if total < 14:
                        continue
                    unit = total / 7.0
                    if (abs(l1 - unit) <= unit * 0.7 and
                        abs(l2 - unit) <= unit * 0.7 and
                        abs(l3 - 3 * unit) <= unit * 1.5 and
                        abs(l4 - unit) <= unit * 0.7 and
                        abs(l5 - unit) <= unit * 0.7):
                        finder_candidates += 1
                        if finder_candidates >= 3:
                            return True
        return False

    def _detect_qr_finder_patterns_raw_png(self, data: bytes) -> bool:
        """Резервный stdlib-парсер PNG (без Pillow) для обнаружения QR Finder Patterns (1:1:3:1:1)."""
        try:
            if not data.startswith(b"\x89PNG\r\n\x1a\n"):
                return False
            pos = 8
            width = height = bit_depth = color_type = 0
            idat_chunks: List[bytes] = []
            while pos + 8 <= len(data):
                length, ctype = struct.unpack(">I4s", data[pos:pos + 8])
                chunk_data = data[pos + 8:pos + 8 + length]
                pos += 12 + length
                if ctype == b"IHDR" and len(chunk_data) >= 13:
                    width, height, bit_depth, color_type = struct.unpack(">IIBB", chunk_data[:10])
                elif ctype == b"IDAT":
                    idat_chunks.append(chunk_data)
                elif ctype == b"IEND":
                    break
            if width < 40 or height < 40 or bit_depth != 8 or not idat_chunks:
                return False
            bpp = {0: 1, 2: 3, 4: 2, 6: 4}.get(color_type, 0)
            if bpp == 0:
                return False
            raw = zlib.decompress(b"".join(idat_chunks))
            stride = width * bpp
            expected = height * (1 + stride)
            if len(raw) < expected:
                return False
            rows: List[List[int]] = []
            prev_scanline = bytearray(stride)
            offset = 0
            for _ in range(height):
                ftype = raw[offset]
                scanline = bytearray(raw[offset + 1:offset + 1 + stride])
                offset += 1 + stride
                if ftype == 1:  # Sub
                    for i in range(bpp, stride):
                        scanline[i] = (scanline[i] + scanline[i - bpp]) & 0xFF
                elif ftype == 2:  # Up
                    for i in range(stride):
                        scanline[i] = (scanline[i] + prev_scanline[i]) & 0xFF
                prev_scanline = scanline
                if bpp == 1:
                    rows.append(list(scanline))
                else:
                    rows.append([(scanline[x * bpp] + scanline[x * bpp + 1] + scanline[x * bpp + 2]) // 3 for x in range(width)])
            return self._check_rows_for_finder(rows)
        except Exception:
            return False

    def _detect_qr_finder_patterns(self, img: Any) -> bool:
        """
        Автономный детектор меток позиционирования QR-кода без внешних C-библиотек.
        Проверяет наличие контрастных чередований 1:1:3:1:1 в строках изображения.
        """
        try:
            w, h = img.size
            if w < 40 or h < 40:
                return False

            max_dim = 600
            if max(w, h) > max_dim:
                scale = max_dim / float(max(w, h))
                img_scaled = img.resize((int(w * scale), int(h * scale)))
            else:
                img_scaled = img

            gray = img_scaled.convert("L")
            bw = gray.point(lambda x: 0 if x < 128 else 255, '1')
            bw_pixels = bw.load()
            sw, sh = bw.size
            rows = [[bw_pixels[x, y] for x in range(sw)] for y in range(sh)]
            return self._check_rows_for_finder(rows)
        except Exception:
            return False
