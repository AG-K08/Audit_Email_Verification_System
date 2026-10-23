# Каталог `modules/` (корень репозитория)

Пайплайн **Office Macro Security Analyzer** для корневого CLI `office_analyzer.py`: каждый `block*.py` экспортирует функцию `run(...)` (сигнатуры см. в коде) и задаёт константу `BLOCK_NAME`.

| Файл | Роль |
|------|--------|
| **`block0_extraction.py`** | Извлечение и подготовка: OLE/OOXML, вложенные архивы, энтропия бинарных фрагментов, рабочий каталог артефактов. |
| **`block1_triage.py`** | Triage макросов: `oletools` (VBA_Parser, MacroRaptor), XLM-листы и опасные функции, триггеры авто-запуска. |
| **`block2_vba_source.py`** | Анализ исходного VBA (макросы, obfuscation, подозрительные конструкции). |
| **`block3_pcode.py`** | P-code / VBA compiled слой, где применимо. |
| **`block4_activex.py`** | ActiveX, CLSID, опасные элементы управления. |
| **`block5_metadata.py`** | Метаданные документа и связанные индикаторы. |
| **`block6_ioc.py`** | Сбор IOC (URL, пути, хэши и т.д.) для отчёта и внешних проверок. |
| **`block7_document_threats.py`** | Угрозы в разметке: DDE в OpenXML/OLE2, опасные внешние связи в `.rels`. |
| **`oledump.py`** | Утилита **Didier Stevens** (public domain) для разбора OLE (CFB). В проекте вызывается из **`block1_triage.py`** как fallback (`python oledump.py …`), путь: рядом с модулем или `oledump` в `PATH`. Версия указана в шапке файла. |
