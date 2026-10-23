# -*- coding: utf-8 -*-
"""
Комплекс статического анализа и форензики электронной почты (OMSA v1.0 / Red Edition).
Модуль: block7_document_threats.py
Назначение: Блок 7: Детектирование угроз Office без кода VBA (Template Injection, DDE).

__author__ = "AG-K08 (@And_8)"
__email__ = "mznxncbv888@gmail.com"
__version__ = "4.0 (Red Edition / OMSA v1.0)"
__year__ = "2026"
__license__ = "Proprietary / Internal Security Audit"
"""
import re
import xml.etree.ElementTree as ET
from pathlib import Path

# ---------------------------------------------------------------------------
# Константы
# ---------------------------------------------------------------------------

# Пространства имён OOXML, используемые при парсинге
_NS_W = "http://schemas.openxmlformats.org/wordprocessingml/2006/main"
_NS_R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
_NS_RELS = "http://schemas.openxmlformats.org/package/2006/relationships"
# Namespace Excel spreadsheet — для детекта DDE в формулах ячеек
_NS_SS = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"

# Allowlist доменов для внешних связей — не генерировать индикаторы
_ALLOWLIST_DOMAINS = (
    "microsoft.com",
    "schemas.openxmlformats.org",
    "schemas.microsoft.com",
    "sharepoint.com",
    "office.com",
)

# Суффиксы Type для Relationship
_TYPE_ATTACHED_TEMPLATE = "attachedTemplate"
_TYPE_OLE_OBJECT = "oleObject"
_TYPE_EXTERNAL_LINK = "externalLink"
_TYPE_HYPERLINK = "hyperlink"

# ---------------------------------------------------------------------------
# Вспомогательные функции
# ---------------------------------------------------------------------------


def _is_allowlisted(target: str) -> bool:
    """Проверить, попадает ли Target в allowlist доменов."""
    target_lower = target.lower()
    return any(domain in target_lower for domain in _ALLOWLIST_DOMAINS)


def _is_external_http(target: str) -> bool:
    """Проверить, является ли Target внешним http(s) URL."""
    t = target.lower()
    return t.startswith("http://") or t.startswith("https://")


def _is_unc_path(target: str) -> bool:
    """Проверить, является ли Target UNC-путём."""
    return target.startswith("\\\\") or target.startswith("//")


def _truncate(text: str, max_len: int = 200) -> str:
    """Обрезать строку до max_len символов с маркером."""
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...[truncated]"


def _type_suffix(rel_type: str) -> str:
    """Извлечь суффикс из полного URI типа Relationship."""
    return rel_type.split("/")[-1] if "/" in rel_type else rel_type


# ---------------------------------------------------------------------------
# _check_dde — DDE в OpenXML
# ---------------------------------------------------------------------------


def _check_dde(temp_dir: Path) -> list:
    """
    Поиск DDE-инъекций в XML-файлах OpenXML-документа.

    Проверяет word/document.xml и xl/worksheets/*.xml.
    Использует ElementTree для структурного поиска и re для сырого текста.

    Возвращает список индикаторов (dict).
    """
    indicators = []

    candidate_files = []

    word_doc = temp_dir / "word" / "document.xml"
    if word_doc.is_file():
        candidate_files.append(word_doc)

    worksheets_dir = temp_dir / "xl" / "worksheets"
    if worksheets_dir.is_dir():
        candidate_files.extend(worksheets_dir.glob("*.xml"))
    macrosheets_dir = temp_dir / "xl" / "macrosheets"
    if macrosheets_dir.is_dir():
        candidate_files.extend(macrosheets_dir.glob("*.xml"))

    for xml_file in candidate_files:
        try:
            raw_text = xml_file.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        relative_name = str(xml_file.relative_to(temp_dir))

        # --- Поиск через ElementTree (структурный) ---
        try:
            tree = ET.fromstring(raw_text)
            _search_dde_in_tree(tree, relative_name, indicators)
        except ET.ParseError:
            pass

        # --- Дополнительный поиск через re (нестандартные места) ---
        _search_dde_raw(raw_text, relative_name, indicators)

    return indicators


def _search_dde_in_tree(root: ET.Element, source_name: str, indicators: list) -> None:
    """
    Структурный поиск DDE через ElementTree.

    Ищет <w:instrText> (Word) и <f> формулы с DDE(...) (Excel worksheets).
    """
    # --- Word: поля instrText ---
    instr_texts = []
    for elem in root.iter(f"{{{_NS_W}}}instrText"):
        if elem.text:
            instr_texts.append(elem.text)
    combined = " ".join(instr_texts)
    if combined:
        _classify_dde_text(combined, source_name, f"instrText в {source_name}", indicators)

    # --- Excel: формулы ячеек <f> с паттерном DDE( ---
    for cell in root.iter(f"{{{_NS_SS}}}c"):
        formula_elem = cell.find(f"{{{_NS_SS}}}f")
        if formula_elem is None or not formula_elem.text:
            continue
        formula_text = formula_elem.text
        if re.search(r"\bDDE\s*\(", formula_text, re.IGNORECASE):
            cell_ref = cell.get("r", "?")
            _classify_dde_text(
                formula_text,
                source_name,
                f"Excel формула cell={cell_ref} formula={formula_text[:120]}",
                indicators,
            )


def _search_dde_raw(raw_text: str, source_name: str, indicators: list) -> None:
    """
    Сырой поиск DDE через регулярные выражения.

    Дополняет структурный поиск — находит DDE в атрибутах и нестандартных местах.
    """
    # Найти все вхождения DDE/DDEAUTO с контекстом
    for match in re.finditer(r"DDEAUTO|DDE", raw_text, re.IGNORECASE):
        start = max(0, match.start() - 100)
        end = min(len(raw_text), match.end() + 100)
        fragment = raw_text[start:end]
        _classify_dde_text(match.group(0), source_name, fragment, indicators)


def _classify_dde_text(
    text: str, source_name: str, evidence_fragment: str, indicators: list
) -> None:
    """
    Классифицировать найденный DDE-текст и добавить индикатор.

    Избегает дублирования: проверяет существующие индикаторы по коду + source.
    """
    upper = text.upper()

    if "DDEAUTO" in upper:
        code = "B7.DDE_AUTO"
        level = "CRITICAL"
    elif "DDE" in upper:
        code = "B7.DDE_MANUAL"
        level = "HIGH"
    else:
        return

    # Проверить дубликат по коду и источнику
    for existing in indicators:
        if existing.get("code") == code and existing.get("source") == source_name:
            return

    indicators.append(
        {
            "code": code,
            "level": level,
            "source": source_name,
            "evidence": _truncate(evidence_fragment),
        }
    )


# ---------------------------------------------------------------------------
# _check_ole2_dde — DDE в OLE2
# ---------------------------------------------------------------------------


def _check_ole2_dde(file_path: Path) -> list:
    """
    Поиск DDE в OLE2-файле через поток WordDocument.

    Ищет байтовые паттерны field marker + DDE.
    Возвращает список индикаторов (dict).
    """
    indicators = []

    try:
        import olefile
    except ImportError:
        return indicators

    if not olefile.isOleFile(str(file_path)):
        return indicators

    try:
        ole = olefile.OleFileIO(str(file_path))
    except Exception:
        return indicators

    try:
        if not ole.exists("WordDocument"):
            return indicators

        stream_data = ole.openstream("WordDocument").read()

        # Field marker (0x13) предшествует тексту поля в Word binary format
        field_marker = b"\x13"

        # Поиск DDEAUTO
        pattern_auto = re.compile(rb"\x13\s*DDEAUTO", re.IGNORECASE)
        for match in pattern_auto.finditer(stream_data):
            start = match.start()
            end = min(len(stream_data), start + 200)
            fragment = stream_data[start:end]
            evidence = fragment.decode("latin-1", errors="replace")

            _add_if_not_duplicate(
                indicators,
                {
                    "code": "B7.DDE_AUTO",
                    "level": "CRITICAL",
                    "source": "WordDocument stream",
                    "evidence": _truncate(evidence),
                },
            )

        # Поиск DDE (без AUTO)
        pattern_dde = re.compile(rb"\x13\s*DDE(?!AUTO)", re.IGNORECASE)
        for match in pattern_dde.finditer(stream_data):
            start = match.start()
            end = min(len(stream_data), start + 200)
            fragment = stream_data[start:end]
            evidence = fragment.decode("latin-1", errors="replace")

            _add_if_not_duplicate(
                indicators,
                {
                    "code": "B7.DDE_MANUAL",
                    "level": "HIGH",
                    "source": "WordDocument stream",
                    "evidence": _truncate(evidence),
                },
            )

    finally:
        ole.close()

    return indicators


def _add_if_not_duplicate(indicators: list, new_item: dict) -> None:
    """Добавить индикатор, если такой код+source ещё не присутствует."""
    for existing in indicators:
        if (
            existing.get("code") == new_item["code"]
            and existing.get("source") == new_item["source"]
        ):
            return
    indicators.append(new_item)


# ---------------------------------------------------------------------------
# _check_external_rels — внешние связи в .rels
# ---------------------------------------------------------------------------


def _check_external_rels(temp_dir: Path) -> list:
    """
    Поиск опасных внешних связей во всех .rels файлах документа.

    Итерирует temp_dir рекурсивно, парсит каждый .rels через ElementTree.
    Возвращает список индикаторов (dict).
    """
    indicators = []

    for rels_file in temp_dir.rglob("*.rels"):
        try:
            tree = ET.parse(str(rels_file))
            root = tree.getroot()
        except ET.ParseError:
            continue
        except OSError:
            continue

        relative_rels = str(rels_file.relative_to(temp_dir))

        for rel in root.iter(f"{{{_NS_RELS}}}Relationship"):
            rel_type = rel.get("Type", "")
            target = rel.get("Target", "")
            type_suffix = _type_suffix(rel_type)

            if not target:
                continue

            # TargetMode="External" без http и без UNC — внешняя ссылка
            # без явной схемы (редкий случай, но реальный)
            target_mode = rel.get("TargetMode", "")
            if (
                target_mode == "External"
                and not _is_external_http(target)
                and not _is_unc_path(target)
                and not _is_allowlisted(target)
            ):
                indicators.append({
                    "code": "B7.EXTERNAL_TARGET_MODE",
                    "level": "MEDIUM",
                    "source": relative_rels,
                    "evidence": _truncate(f"TargetMode=External Target={target}"),
                })
                continue

            # UNC-путь — проверяется независимо от типа
            if _is_unc_path(target):
                indicators.append(
                    {
                        "code": "B7.UNC_PATH",
                        "level": "HIGH",
                        "source": relative_rels,
                        "evidence": _truncate(f"Target={target}"),
                    }
                )
                continue

            if not _is_external_http(target):
                continue

            # attachedTemplate
            if type_suffix == _TYPE_ATTACHED_TEMPLATE:
                if _is_allowlisted(target):
                    # Allowlist — не создавать индикатор
                    continue
                indicators.append(
                    {
                        "code": "B7.TEMPLATE_INJECTION",
                        "level": "CRITICAL",
                        "source": relative_rels,
                        "evidence": _truncate(f"Target={target}"),
                    }
                )
                continue

            # oleObject
            if type_suffix == _TYPE_OLE_OBJECT:
                indicators.append(
                    {
                        "code": "B7.OLE_EXTERNAL",
                        "level": "HIGH",
                        "source": relative_rels,
                        "evidence": _truncate(f"Target={target}"),
                    }
                )
                continue

            # externalLink
            if type_suffix == _TYPE_EXTERNAL_LINK:
                indicators.append(
                    {
                        "code": "B7.EXTERNAL_LINK",
                        "level": "HIGH",
                        "source": relative_rels,
                        "evidence": _truncate(f"Target={target}"),
                    }
                )
                continue

            # hyperlink
            if type_suffix == _TYPE_HYPERLINK:
                if not _is_allowlisted(target):
                    indicators.append(
                        {
                            "code": "B7.HYPERLINK_EXTERNAL",
                            "level": "MEDIUM",
                            "source": relative_rels,
                            "evidence": _truncate(f"Target={target}"),
                        }
                    )
                continue

    return indicators


# ---------------------------------------------------------------------------
# Публичный интерфейс
# ---------------------------------------------------------------------------


def run(block0_raw: dict) -> object:
    """
    Точка входа Block7.

    Принимает block0_raw (raw_findings из Block0).
    Возвращает BlockResult-совместимый объект.
    """
    # Импортировать BlockResult из существующей инфраструктуры
    try:
        from core.models import BlockResult, ThreatIndicator, ThreatLevel
        _use_models = True
    except ImportError:
        _use_models = False

    raw = {}
    indicators = []

    doc_format = block0_raw.get("file_format", "unknown")
    temp_dir_str = block0_raw.get("temp_dir", "")
    file_path_str = block0_raw.get("file_path", "")

    temp_dir = Path(temp_dir_str) if temp_dir_str else None
    file_path = Path(file_path_str) if file_path_str else None

    is_openxml = doc_format == "openxml"
    is_ole2 = doc_format == "ole2"

    # --- DDE в OLE2 ---
    if is_ole2 and file_path and file_path.is_file():
        ole2_dde = _check_ole2_dde(file_path)
        raw["ole2_dde"] = ole2_dde
        indicators.extend(ole2_dde)
    elif is_ole2:
        raw["ole2_dde"] = []
        raw["ole2_dde_note"] = "file_path недоступен для OLE2 DDE анализа"

    if not is_openxml:
        raw["skipped"] = f"Block7 OpenXML-анализ пропущен: формат={doc_format}"
        return _build_result(
            block_name="Block7_DocumentThreats",
            raw=raw,
            indicators=indicators,
            use_models=_use_models,
        )

    # --- OpenXML: требуется temp_dir ---
    if not temp_dir or not temp_dir.is_dir():
        raw["error"] = "temp_dir недоступен или не является директорией"
        return _build_result(
            block_name="Block7_DocumentThreats",
            raw=raw,
            indicators=indicators,
            use_models=_use_models,
        )

    # --- DDE в OpenXML ---
    dde_results = _check_dde(temp_dir)
    raw["dde_analysis"] = dde_results
    indicators.extend(dde_results)

    # --- Внешние связи ---
    rels_results = _check_external_rels(temp_dir)
    raw["external_rels"] = rels_results
    indicators.extend(rels_results)

    return _build_result(
        block_name="Block7_DocumentThreats",
        raw=raw,
        indicators=indicators,
        use_models=_use_models,
    )


# ---------------------------------------------------------------------------
# Построение результата
# ---------------------------------------------------------------------------

# Весовая модель
_LEVEL_WEIGHTS = {
    "CRITICAL": 100,
    "HIGH": 50,
    "MEDIUM": 20,
    "LOW": 5,
    "INFO": 0,
}


def _build_result(
    block_name: str, raw: dict, indicators: list, use_models: bool
) -> object:
    """
    Построить BlockResult или совместимый SimpleResult.

    Если core.models недоступен — возвращает SimpleResult с тем же интерфейсом.
    """
    score = sum(_LEVEL_WEIGHTS.get(ind.get("level", "INFO"), 0) for ind in indicators)

    if use_models:
        try:
            from core.models import BlockResult, ThreatIndicator, ThreatLevel

            _level_map = {
                "CRITICAL": ThreatLevel.CRITICAL,
                "HIGH":     ThreatLevel.HIGH,
                "MEDIUM":   ThreatLevel.MEDIUM,
                "LOW":      ThreatLevel.LOW,
                "INFO":     ThreatLevel.INFO,
            }
            _descriptions = {
                "B7.DDE_AUTO":              "DDE: автозапуск DDEAUTO в документе",
                "B7.DDE_MANUAL":            "DDE: ручное поле DDE в документе",
                "B7.TEMPLATE_INJECTION":    "Template Injection: внешний шаблон по http(s)",
                "B7.OLE_EXTERNAL":          "OLE-объект с внешней http(s) ссылкой",
                "B7.EXTERNAL_LINK":         "Внешняя ссылка (externalLink) по http(s)",
                "B7.HYPERLINK_EXTERNAL":    "Внешний гиперлинк по http(s)",
                "B7.UNC_PATH":              "UNC-путь в связях документа",
                "B7.EXTERNAL_TARGET_MODE":  "Relationship с TargetMode=External",
            }

            indicator_objects = []
            for ind in indicators:
                code = ind["code"]
                indicator_objects.append(
                    ThreatIndicator(
                        indicator_id=code,
                        level=_level_map.get(ind.get("level", "INFO"), ThreatLevel.INFO),
                        description=_descriptions.get(code, f"Block7: {code}"),
                        evidence=ind.get("evidence", ""),
                        location=ind.get("source", ""),
                    )
                )
            return BlockResult(
                block_name=block_name,
                success=True,
                execution_time_ms=0,
                threat_indicators=indicator_objects,
                raw_findings=raw,
            )
        except Exception:
            pass

    # Fallback — простой объект с атрибутами
    return _SimpleResult(
        block_name=block_name,
        score=score,
        indicators=indicators,
        raw_findings=raw,
    )


class _SimpleResult:
    """
    Минимальный результат блока для случаев когда core.models недоступен.
    Совместим с ожидаемым интерфейсом оркестратора.
    """

    def __init__(
        self,
        block_name: str,
        score: int,
        indicators: list,
        raw_findings: dict,
    ):
        self.block_name = block_name
        self.score = score
        self.indicators = indicators
        self.threat_indicators = indicators
        self.success = True
        self.execution_time_ms = 0
        self.error_message = None
        self.raw_findings = raw_findings

    def __repr__(self) -> str:
        return (
            f"_SimpleResult(block={self.block_name!r}, "
            f"score={self.score}, indicators={len(self.indicators)})"
        )