# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block0_extraction.py
Назначение: Блок 0: Распаковка контейнеров и извлечение макросов.

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
from __future__ import annotations
import os
import hashlib
import logging
import shutil
import time
import zipfile
from pathlib import Path

try:
    import olefile
except ImportError:
    olefile = None

from core.utils import calculate_entropy_bytes
from core.models import BlockResult, ThreatIndicator, ThreatLevel

log = logging.getLogger("Block0")

OLE2_MAGIC = b"\xD0\xCF\x11\xE0"
ZIP_MAGIC = b"\x50\x4B\x03\x04"
MAX_RECURSION_DEPTH = 3
PE_MAGIC = b"\x4D\x5A"
ELF_MAGIC = b"\x7F\x45\x4C\x46"
BINARY_ENTROPY_THRESHOLD = 7.0
BINARY_MIN_SIZE_BYTES = 512
BINARY_CHECK_EXTENSIONS = {".bin", ".ole", ""}
BINARY_SKIP_NAMES = {"vbaproject.bin"}

BLOCK_NAME = "block0_extraction"


def run(
    file_path: Path,
    work_dir: Path,
    max_file_size_mb: int,
    max_extracted_size_mb: int,
    recursion_depth: int = 0,
) -> BlockResult:
    start_ms = time.monotonic()
    indicators: list[ThreatIndicator] = []
    raw: dict = {}

    try:
        _check_file_size(file_path, max_file_size_mb)
        file_format = _detect_format(file_path)
        raw["file_format"] = file_format
        raw["file_size_bytes"] = file_path.stat().st_size
        raw["hashes"] = _compute_hashes(file_path)
        raw["file_path"] = str(file_path)

        temp_dir = work_dir / f"temp_{raw['hashes']['sha256'][:12]}"
        temp_dir.mkdir(parents=True, exist_ok=True)
        raw["temp_dir"] = str(temp_dir)

        if file_format == "openxml":
            extraction_indicators = _extract_openxml(
                file_path, temp_dir, max_extracted_size_mb
            )
        elif file_format == "ole2":
            extraction_indicators = _extract_ole2(file_path, temp_dir)
        else:
            extraction_indicators = []
            log.warning("Неизвестный формат файла: %s", file_path.name)

        indicators.extend(extraction_indicators)

        vba_bin_candidates = list(temp_dir.rglob("vbaProject.bin"))
        vba_bin = vba_bin_candidates[0] if vba_bin_candidates else None
        raw["vba_project_path"] = str(vba_bin) if vba_bin else None

        if vba_bin and vba_bin.exists():
            raw["vba_project_sha256"] = _sha256_file(vba_bin)

        embedded = _find_embedded_ole_objects(temp_dir, recursion_depth, max_file_size_mb, max_extracted_size_mb, work_dir)
        raw["embedded_objects"] = embedded
        if embedded:
            file_names = [Path(p).name for p in embedded]
            indicators.append(ThreatIndicator(
                indicator_id="B0.EMBEDDED_OLE",
                level=ThreatLevel.MEDIUM,
                description=f"Обнаружено {len(embedded)} вложенных OLE-объектов с макросами",
                evidence=", ".join(file_names),
                location=file_path.name,
            ))

        _check_password_protection(file_path, file_format, indicators)
        _check_extension_mismatch(file_path, file_format, indicators)
        _check_binary_content(temp_dir, indicators)

        return BlockResult(
            block_name=BLOCK_NAME,
            success=True,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            threat_indicators=indicators,
            raw_findings=raw,
        )

    except _FileTooLargeError as exc:
        return _error_result(BLOCK_NAME, str(exc), start_ms)
    except _ZipSlipError as exc:
        indicators.append(ThreatIndicator(
            indicator_id="B0.ZIP_SLIP",
            level=ThreatLevel.CRITICAL,
            description="Обнаружена попытка zip slip в архиве",
            evidence=str(exc),
            location=file_path.name,
        ))
        return BlockResult(
            block_name=BLOCK_NAME,
            success=False,
            execution_time_ms=int((time.monotonic() - start_ms) * 1000),
            error_message=f"Zip slip: {exc}",
            threat_indicators=indicators,
            raw_findings=raw,
        )
    except Exception as exc:
        log.exception("Блок 0 упал с исключением")
        return _error_result(BLOCK_NAME, str(exc), start_ms)


def _check_file_size(file_path: Path, max_mb: int) -> None:
    size_mb = file_path.stat().st_size / (1024 * 1024)
    if size_mb > max_mb:
        raise _FileTooLargeError(
            f"Файл {size_mb:.1f} МБ превышает лимит {max_mb} МБ"
        )


def _detect_format(file_path: Path) -> str:
    with file_path.open("rb") as f:
        magic = f.read(8)
    if magic[:4] == OLE2_MAGIC:
        return "ole2"
    if magic[:4] == ZIP_MAGIC:
        return "openxml"
    return "unknown"


def _extract_openxml(
    file_path: Path,
    dest_dir: Path,
    max_extracted_mb: int,
) -> list[ThreatIndicator]:
    indicators: list[ThreatIndicator] = []
    max_bytes = max_extracted_mb * 1024 * 1024
    total_extracted = 0

    with zipfile.ZipFile(file_path, "r") as zf:
        for member in zf.infolist():
            _validate_zip_member_path(member.filename, dest_dir)

            total_extracted += member.file_size
            if total_extracted > max_bytes:
                raise _FileTooLargeError(
                    f"Суммарный размер извлечённых данных превысил {max_extracted_mb} МБ"
                )

            zf.extract(member, dest_dir)

    log.debug("OpenXML извлечён в %s", dest_dir)
    return indicators


def _validate_zip_member_path(member_path: str, dest_dir: Path | None = None) -> None:
    # Защита от Zip Slip на Linux и Windows (диски C:, обратные слеши, UNC)
    clean_p = member_path.replace("\\", "/")
    normalized = Path(clean_p)
    parts = normalized.parts
    if normalized.is_absolute() or ".." in parts or (parts and parts[0].startswith(("/", "\\"))):
        raise _ZipSlipError(member_path)
    if ":" in member_path:
        raise _ZipSlipError(member_path)
    if dest_dir is not None:
        target = (dest_dir / normalized).resolve()
        dest_resolved = dest_dir.resolve()
        if not (target == dest_resolved or str(target).startswith(str(dest_resolved) + os.sep)):
            raise _ZipSlipError(member_path)


def _extract_ole2(file_path: Path, dest_dir: Path) -> list[ThreatIndicator]:
    if not olefile.isOleFile(file_path):
        log.warning("Файл помечен как OLE2 но olefile не может его открыть")
        return []

    with olefile.OleFileIO(str(file_path)) as ole:
        for entry in ole.listdir(streams=True):
            stream_name = "/".join(entry)
            try:
                data = ole.openstream(entry).read()
                output_path = dest_dir / stream_name.replace("/", "_").replace("\\", "_")
                output_path.write_bytes(data)
            except Exception:
                log.debug("Не удалось извлечь поток: %s", stream_name)

    log.debug("OLE2 потоки извлечены в %s", dest_dir)
    return []


def _find_embedded_ole_objects(
    search_dir: Path,
    current_depth: int,
    max_file_mb: int,
    max_extracted_mb: int,
    work_dir: Path,
) -> list[str]:
    if current_depth >= MAX_RECURSION_DEPTH:
        return []

    found: list[str] = []
    for candidate in search_dir.rglob("*.bin"):
        # vbaProject.bin — стандартная часть xlsm/docm, не embedded object
        if candidate.name.lower() == "vbaproject.bin":
            continue
        if candidate.stat().st_size < 8:
            continue
        with candidate.open("rb") as f:
            magic = f.read(4)
        if magic == OLE2_MAGIC and olefile.isOleFile(candidate):
            found.append(str(candidate))
            sub_work = work_dir / f"embedded_{candidate.stem}"
            sub_work.mkdir(exist_ok=True)
            run(candidate, sub_work, max_file_mb, max_extracted_mb, current_depth + 1)

    return found


def _check_password_protection(
    file_path: Path,
    file_format: str,
    indicators: list[ThreatIndicator],
) -> None:
    if file_format == "openxml":
        try:
            with zipfile.ZipFile(file_path) as zf:
                for info in zf.infolist():
                    if info.flag_bits & 0x1:
                        indicators.append(ThreatIndicator(
                            indicator_id="B0.PASSWORD_PROTECTED",
                            level=ThreatLevel.HIGH,
                            description="Файл защищён паролем",
                            evidence="ZIP flag_bits & 0x1",
                            location=file_path.name,
                        ))
                        return
        except Exception:
            pass
    elif file_format == "ole2":
        try:
            with olefile.OleFileIO(str(file_path)) as ole:
                if ole.exists("\x05DocumentSummaryInformation"):
                    props = ole.getproperties("\x05DocumentSummaryInformation")
                    if props.get(0x13):
                        indicators.append(ThreatIndicator(
                            indicator_id="B0.PASSWORD_PROTECTED",
                            level=ThreatLevel.HIGH,
                            description="Файл защищён паролем (OLE2)",
                            evidence="DocumentSummaryInformation property 0x13",
                            location=file_path.name,
                        ))
        except Exception:
            pass


def _check_extension_mismatch(
    file_path: Path,
    detected_format: str,
    indicators: list[ThreatIndicator],
) -> None:
    extension = file_path.suffix.lower()
    ole2_extensions = {".xls", ".doc", ".xlt", ".dot", ".ppt", ".pot", ".pps"}
    openxml_extensions = {
        ".xlsx", ".xlsm", ".xlsb", ".docx", ".docm", ".dotx", ".dotm",
        ".pptx", ".pptm", ".xltx", ".xltm", ".potx", ".potm", ".ppsx", ".ppsm",
    }

    expected_format = None
    if extension in ole2_extensions:
        expected_format = "ole2"
    elif extension in openxml_extensions:
        expected_format = "openxml"

    if expected_format and expected_format != detected_format:
        indicators.append(ThreatIndicator(
            indicator_id="B0.EXTENSION_MISMATCH",
            level=ThreatLevel.MEDIUM,
            description=f"Расширение {extension} не соответствует реальному формату {detected_format}",
            evidence=f"magic bytes указывают на {detected_format}",
            location=file_path.name,
        ))

def _check_binary_content(
    temp_dir: Path,
    indicators: list[ThreatIndicator],
) -> None:
    for candidate in temp_dir.rglob("*"):
        if not candidate.is_file():
            continue
        if candidate.name.lower() in BINARY_SKIP_NAMES:
            continue
        if candidate.suffix.lower() not in BINARY_CHECK_EXTENSIONS:
            continue
        if candidate.stat().st_size < BINARY_MIN_SIZE_BYTES:
            continue

        try:
            data = candidate.read_bytes()
        except Exception:
            continue

        if data[:2] == PE_MAGIC:
            indicators.append(ThreatIndicator(
                indicator_id="B0.PE_MAGIC",
                level=ThreatLevel.HIGH,
                description="PE-исполняемый файл (MZ magic) обнаружен в OLE-потоке",
                evidence=f"{candidate.name} — первые байты: {data[:8].hex()}",
                location=str(candidate.relative_to(temp_dir)),
            ))
            continue

        if data[:4] == ELF_MAGIC:
            indicators.append(ThreatIndicator(
                indicator_id="B0.ELF_MAGIC",
                level=ThreatLevel.HIGH,
                description="ELF-исполняемый файл обнаружен в OLE-потоке",
                evidence=f"{candidate.name} — первые байты: {data[:8].hex()}",
                location=str(candidate.relative_to(temp_dir)),
            ))
            continue

        entropy = calculate_entropy_bytes(data)
        if entropy >= BINARY_ENTROPY_THRESHOLD:
            indicators.append(ThreatIndicator(
                indicator_id="B0.HIGH_ENTROPY_BINARY",
                level=ThreatLevel.MEDIUM,
                description=f"Высокая энтропия бинарного потока: {entropy:.2f} бит/байт — возможен упакованный shellcode",
                evidence=f"{candidate.name}, entropy={entropy:.2f}, size={len(data)} байт",
                location=str(candidate.relative_to(temp_dir)),
            ))


def _compute_hashes(file_path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    result = {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }

    try:
        try:
            import ppdeep as _ssdeep_impl
        except ImportError:
            import ssdeep as _ssdeep_impl
        result["ssdeep"] = _ssdeep_impl.hash_from_file(str(file_path))
    except ImportError:
        log.debug("ssdeep недоступен, fuzzy hash пропущен")

    return result


def _sha256_file(file_path: Path) -> str:
    sha256 = hashlib.sha256()
    with file_path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


def _error_result(block_name: str, message: str, start_ms: float) -> BlockResult:
    return BlockResult(
        block_name=block_name,
        success=False,
        execution_time_ms=int((time.monotonic() - start_ms) * 1000),
        error_message=message,
    )


class _FileTooLargeError(Exception):
    pass


class _ZipSlipError(Exception):
    pass