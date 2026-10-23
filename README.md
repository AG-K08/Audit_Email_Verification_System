# 🛡️ ПАСПОРТ СИСТЕМЫ ПРОВЕРКИ И ФОРЕНЗИКИ ЭЛЕКТРОННОЙ ПОЧТЫ
## Комплекс статического криминалистического анализа писем и вложений (Email & Document Forensics Suite)

[![Audit CI](https://img.shields.io/badge/Audit_CI-passing-10B981.svg)](https://github.com/AG-K08/Audit_Email_Verification_System/actions/workflows/audit_ci.yml)
[![Release](https://img.shields.io/badge/Release-v4.1_Red_Edition-E11D48.svg)](https://github.com/AG-K08/Audit_Email_Verification_System/releases)
[![Tests](https://img.shields.io/badge/pytest-56%20passed%20(100%25)-10B981.svg)](https://github.com/AG-K08/Audit_Email_Verification_System/tree/main/06_Audit_Tests_and_Samples)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13%20%7C%203.14-blue.svg)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Proprietary%20Audit-gray.svg)](./README.md)

**Версия системы:** 4.1 (Red Edition / OMSA v1.0)  
**Назначение:** Многоуровневая система статического криминалистического анализа электронной почты (`.eml`, `.msg`), документов MS Office, PDF, архивов и медиафайлов для выявления фишинга, вредоносных макросов, эксплойтов и скрытых полезных нагрузок без их запуска в операционной системе.

> 📢 **Руководство по установке и использованию:**
> - 🚀 **[QUICKSTART_GUIDE.md](./QUICKSTART_GUIDE.md)** — подробная инструкция по развертыванию (онлайн и в изолированном контуре Air-Gap), запуску CLI/GUI-инструментов, плагина Thunderbird и автотестов.

---

## 📑 1. Архитектурная карта системы проверки

Система построена по многоуровневому эшелонированному принципу (Defense-in-Depth) и разделена на 6 взаимосвязанных функциональных блоков:

```
Audit_Email_Verification_System/
├── 01_Core_Engines/                  # Аналитические движки и конвейеры проверки
│   ├── phish_engine/                 # Модульный масштабируемый движок проверки
│   │   ├── engine.py                 # Фасад PhishingEngine (.eml / .msg / вложенные message/rfc822)
│   │   ├── checks_headers.py         # Аутентификация (SPF, DKIM, DMARC), spoofing, цепочка Received
│   │   ├── checks_body.py            # Поиск фишинговых ссылок, гомоглифов, скрытого HTML, триггеров
│   │   ├── checks_attachments.py     # Анализ вложений, архивов, LNK, кластеров, фрагментированных нагрузок
│   │   ├── checks_quishing.py        # Автономное распознавание QR-кодов (Quishing)
│   │   └── scoring.py                # Взвешенный скоринг рисков и категоризация (CLEAN / SUSPICIOUS / MALICIOUS)
│   ├── analyze_email_full.py         # Автономный сквозной анализатор письма (.eml / .msg, этапы 0–9)
│   ├── analyze_threats.py            # 7-уровневый мастер-конвейер угроз (PhishingOrchestrator)
│   ├── robust_analyzer.py            # Отказоустойчивый анализатор бинарных объектов и метаданных
│   ├── threat_detection_tools.py     # Интеграция локальной базы YARA и движка Nuclei для URL
│   ├── safe_office_deep_scan.py      # Безопасный in-memory разбор структуры документов Office
│   ├── office_document_threats.py    # Детектирование Remote Template Injection, OLE-пакетов, DDE, RTF
│   ├── full_doc_scan.py              # 7-этапный углубленный сканер документов MS Office
│   ├── metadata_hex_scanner.py       # Карвинг метаданных PDF, скрытых HEX-инъекций и GPS-координат
│   ├── carve_images.py               # Извлечение встроенных изображений и анализ хвостовых оверлеев
│   ├── analyze_attachments.py        # Пакетный скрининг архивов и вложений
│   ├── extract_attachments.py        # Утилита безопасного извлечения MIME/TNEF вложений
│   ├── parse_eml_detailed.py         # Низкоуровневый RFC822/MIME парсер
│   ├── grep_eml.py                   # Массовый поиск индикаторов по базе писем
│   └── analyze_email.bat             # Скрипт быстрого запуска для аналитика (Drag & Drop)
│
├── 02_Office_Macro_Analyzer_OMSA/    # Подсистема OMSA (Office Macro Security Analyzer)
│   ├── office_analyzer.py            # CLI точка входа (.doc/.docx/.docm/.xls/.xlsx/.xlsm/.ppt/.pptx/.rtf и др.)
│   ├── report_generator.py           # Генератор структурированных отчетов (JSON/TXT/MD)
│   ├── report_generator_verbose.py   # Детализированный отчет с дампом псевдокода
│   ├── core/                         # Ядро OMSA (config, clsid_db.json, threat_evaluator, logger)
│   └── modules/                      # Блоки анализа 0–7:
│       ├── block0_extraction.py      # Распаковка контейнеров OLE2/OOXML/RTF и макросов
│       ├── block1_triage.py          # Быстрый сигнатурный триаж (olevba / mraptor / XLM)
│       ├── block2_vba_source.py      # Декомпиляция исходного кода VBA
│       ├── block3_pcode.py           # Анализ P-code и выявление VBA Stomping
│       ├── block4_activex.py         # Проверка небезопасных ActiveX и форм
│       ├── block5_metadata.py        # Метаданные, авторство, временные аномалии
│       ├── block6_ioc.py             # Извлечение сетевых и файловых IoC
│       ├── block7_document_threats.py# Векторы атак без VBA-кода (DDE, внешние связи .rels)
│       └── oledump.py                # Низкоуровневый разбор потоков OLE2
│
├── 03_Clients_and_Integrations/      # Интерфейсы взаимодействия и интеграции
│   ├── Analyzer_App/                 # GUI-приложение «Mail Forensic Pro» (Python / TkinterDnD)
│   │   ├── mail_forensic_pro.py
│   │   └── MailForensicPro.spec
│   ├── ThunderbirdPhishingGuard/     # Расширение для Mozilla Thunderbird + Native Messaging Host
│   │   ├── manifest.json             # Манифест расширения
│   │   ├── background.js             # Клиентский экспресс-анализ (заголовки, spoofing, ссылки)
│   │   ├── thunderbird_phishing_host.py # Серверный Native Messaging bridge к Python-оркестратору
│   │   └── register_native_host.ps1  # Скрипт регистрации хоста в реестре Windows
│   └── Distributable/                # Автономная портативная поставка OMSA v1.0 + утилиты (main_launcher.py)
│
├── 04_Detection_Rules/               # Правила детекции и базы сигнатур
│   ├── professional_threats.yar      # Профессиональный набор YARA для почтовых угроз
│   └── YARA/                         # Локальная база правил (макросы, шеллкоды, эксплойты)
│
├── 05_Methodology_and_Docs/          # Нормативная и методологическая база
│   ├── ИНСТРУКЦИЯ_АНАЛИЗ_ПИСЕМ.md    # Полный регламент 7-уровневого анализа
│   ├── ИНСТРУКЦИЯ_ПРОВЕРКА_ПИСЕМ_НА_ФИШИНГ.docx # Документированная инструкция
│   ├── ТЗ_Office_Macro_Security_Analyzer.md # Официальное ТЗ на систему OMSA
│   ├── METHODOLOGY.md                # Методология расследования
│   └── SKILL_multi_document_payload_assembly.md # Алгоритмы выявления композитных/распределенных атак
│
└── 06_Audit_Tests_and_Samples/       # Модульные тесты и контрольные образцы для аудита (56 автотестов)
    ├── test_phish_engine.py          # Автотесты базовой логики PhishingEngine (14 тестов)
    ├── test_analyze_email_full.py    # Автотесты сквозного анализатора (14 тестов)
    ├── test_advanced_phish.py        # Автотесты новых эшелонов детекции (Quishing, LNK, Cloud Phishing, 13 тестов)
    ├── test_release_readiness_matrix.py # Матричный предрелизный пакет по всем форматам писем и вложений (15 тестов)
    ├── test.eml                      # Контрольный тестовый образец письма
    └── test_document.docx            # Контрольный тестовый образец документа Office
```

---

## 🔍 2. Семь уровней эшелонированной проверки (Forensic Pipeline)

1. **Уровень 1: Анализ транспортных заголовков и аутентификации (Email Forensics):**
   - Верификация SPF (`Received-SPF`, `Authentication-Results`).
   - Верификация DKIM (`dkim=pass/fail`).
   - Верификация DMARC политики отправителя.
   - Сверка адреса отправителя `From`, `Reply-To` и `Return-Path`.
   - Детектирование спуфинга отображаемого имени (Display Name Spoofing): проверка известных брендов и должностей при отправке с публичных почтовых серверов (`@mail.ru`, `@gmail.com`, `@yandex.ru` и т.д.).
   - Детектирование тайпосквоттинга и гомоглифических атак в доменах отправителя (IDN/Cyrillic substitution).
   - Трассировка цепочки `Received` (выявление динамических/бытовых пулов провайдеров, аномалий `Message-ID` и спам-инструментов в `X-Mailer`).

2. **Уровень 2: Анализ тела письма и URL:**
   - Извлечение всех гиперссылок из HTML и Plain-Text (включая письма в кодировках `UTF-8`, `Windows-1251`, `KOI8-R` и вложенные `message/rfc822`).
   - Поиск несоответствия якорного текста и реального URL (`<a href="phish.com">bank.ru</a>`), прямых IP-ссылок, сокращателей URL (`bit.ly`, `clck.ru`), Open Redirect и зон повышенного риска (`.top`, `.xyz`).
   - Детектирование облачного Credential Harvesting (`web.core.windows.net`, `workers.dev`, `firebaseapp.com` с параметрами `#user@domain`).
   - Проверка скрытых элементов, стилей `display:none`, нулевых шрифтов, прозрачных пикселей трекинга и HTML-форм сбора паролей.
   - Сканирование URL шаблонами Nuclei на признаки фишинговых панелей и Evilginx C2.
   - Поиск признаков социальной инженерии (на русском, белорусском и английском языках).

3. **Уровень 3: Извлечение и триаж вложений:**
   - Декодирование MIME-вложений всех уровней вложенности, включая вложенные письма `message/rfc822` и контейнеры MS Outlook `.msg` / TNEF (`winmail.dat`).
   - Проверка файлов на двойные расширения (`invoice.pdf.exe`) и спуфинг имен через символ разворота строки Unicode RTLO (`\u202e`).
   - Идентификация реального MIME-типа по Magic Bytes, а не только по расширению.
   - Безопасная распаковка архивов (`ZIP`, `TAR`, `TAR.GZ`, `TGZ` нативно в Python + `RAR`, `7Z`, `ISO`, `IMG`, `VHD` через 7-Zip) с защитой от Zip-Slip / Tar-Slip и Zip-Bomb.
   - Детектирование защищенных паролем архивов и HTML Smuggling (`Blob`, `atob`, `Uint8Array`).

4. **Уровень 4: Глубокий статический анализ документов:**
   - **MS Office (`DOC`, `DOCX`, `XLS`, `XLSX`, `PPT`, `PPTX`, `DOCM`, `XLSM`, `DOTM`, `XLTM`, `RTF`, `XML`, `MHT`):**
     - Декомпиляция VBA-макросов (`olevba`) и XLM 4.0 макросов.
     - Анализ несоответствия исходного текста и P-code (детектирование атаки **VBA Stomping**).
     - Поиск триггеров автозапуска (`AutoOpen`, `Workbook_Open`, `Document_Close`).
     - Поиск подозрительных API-функций (`Shell`, `CreateObject("WScript.Shell")`, `VirtualAlloc`).
     - Детектирование Remote Template Injection (внешние связи в `_rels/*.rels` и UTF-16LE URL в бинарных потоках OLE2).
     - Детектирование атак через поля `DDE` / `DDEAUTO`, объекты `OLE2` (`Ole10Native`, `Package`, `Equation.3` CVE-2017-11882) и эксплойты в `RTF` (`\objdata`).
   - **PDF:**
     - Поиск элементов `/JavaScript`, `/JS`, действий `/OpenAction`, `/AA`, `/Launch`, внедренных файлов `/EmbeddedFiles` и сжатых объектных потоков `/ObjStm`.
   - **Скрипты и LNK:**
     - Деобфускация PowerShell, VBScript, JScript, HTA, WSF, BAT, CMD.
     - Бинарный разбор ярлыков `.lnk` на предмет скрытых вызовов `powershell.exe -enc`, `mshta`, `bitsadmin`, `certutil`.

5. **Уровень 5: Анализ распределенных полезных нагрузок (Multi-Document Staged Assembly):**
   - Кластерный анализ нескольких вложений в одном письме.
   - Поиск перекрестных ссылок между документами (например, файл A обращается к файлу B).
   - Выявление команд склейки и конкатенации (`copy /b`, `ADODB.Stream`, `WriteAllBytes`).
   - Проверка хвостовых оверлеев (Trailing Data) после `%%EOF` в PDF и после End of Central Directory в ZIP/OOXML.

6. **Уровень 6: Медиа-форензика, Quishing и карвинг изображений:**
   - Автономное выявление и декодирование QR-кодов в картинках (**Quishing**) с проверкой зашитых в них фишинговых URL.
   - Извлечение всех графических объектов (`JPEG`, `PNG`, `GIF`, `BMP`, `EMF`).
   - Анализ оверлеев и байтов за маркером конца изображения (`EOI \xFF\xD9`, `IEND`) и карвинг скрытых в метаданных HEX-инъекций и GPS-координат (`metadata_hex_scanner.py`).
   - Поиск скрытых сетевых ссылок UNC (`\\server\share`) для сбора NTLM-хешей.

7. **Уровень 7: Оценка рисков и формирование структурированного отчета:**
   - Расчет агрегированного скоринга по взвешенной модели (0–100).
   - Классификация: **CLEAN** (0–24), **LOW_RISK** (25–49), **SUSPICIOUS** (50–74), **MALICIOUS** (75–100).
   - Фиксация перечня непроверенных областей (Uninspected Scope): указание на ограничения статического анализа без динамической песочницы.
   - Выгрузка отчетов в форматах JSON, TXT и Markdown.

---

## 🚀 3. Руководство по установке, тестированию и использованию

Подробные пошаговые инструкции и примеры для всех сценариев собраны в **[QUICKSTART_GUIDE.md](./QUICKSTART_GUIDE.md)**.

### 3.1. Установка и развертывание на новом ПК:
```cmd
:: Автоматическое создание .venv, установка библиотек (онлайн или офлайн из vendor_wheels/) и запуск 56 тестов:
setup_environment.bat

:: Либо через PowerShell:
powershell -ExecutionPolicy Bypass -File setup_environment.ps1

:: Для ручной офлайн-установки в изолированном контуре (Air-Gap):
pip install --no-index --find-links=vendor_wheels -r requirements.txt

:: Для ручной онлайн-установки:
pip install -r requirements.txt
```

### 3.2. Запуск автотестов (56 тестов, включая матрицу форматов):
```bash
python -m pytest 06_Audit_Tests_and_Samples/ -v
```

### 3.3. Примеры запуска проверки писем (`.eml` / `.msg`):
```bash
# 1. Полный сквозной анализ письма (этапы 0–9, генерация JSON и TXT отчета рядом с письмом):
python 01_Core_Engines/analyze_email_full.py 06_Audit_Tests_and_Samples/test.eml

# 2. Сквозной анализ с дополнительным сохранением копии JSON-отчета по заданному пути:
python 01_Core_Engines/analyze_email_full.py "C:\Path\To\Suspicious_Email.eml" --output "C:\Reports\report.json"

# 3. Мастер-оркестратор угроз (генерирует FINAL_REPORT.md и ОТЧЕТ_АНАЛИЗА.txt):
python 01_Core_Engines/analyze_threats.py 06_Audit_Tests_and_Samples/test.eml

# 4. Запуск через пакетный файл аналитика (поддерживает перетаскивание Drag & Drop):
01_Core_Engines\analyze_email.bat "C:\Path\To\Suspicious_Email.eml"
```

### 3.4. Примеры запуска проверки документов Office, PDF и медиафайлов:
```bash
# 1. Комплексный аудит документа в OMSA v1.0 (VBA, P-code Stomping, ActiveX, DDE, внешние шаблоны):
python 02_Office_Macro_Analyzer_OMSA/office_analyzer.py 06_Audit_Tests_and_Samples/test_document.docx --output "C:\Reports\OMSA_Out"

# 2. Запуск автономной портативной сборки OMSA (Distributable):
python 03_Clients_and_Integrations/Distributable/main_launcher.py 06_Audit_Tests_and_Samples/test_document.docx --offline -o "C:\Reports\Dist_Out"

# 3. Безопасный in-memory разбор контейнера Office без системных парсеров:
python 01_Core_Engines/safe_office_deep_scan.py 06_Audit_Tests_and_Samples/test_document.docx

# 4. Детектирование Remote Template Injection, DDE, OLE-пакетов и RTF-угроз:
python 01_Core_Engines/office_document_threats.py 06_Audit_Tests_and_Samples/test_document.docx

# 5. Карвинг метаданных PDF, скрытых HEX-инъекций, GPS-координат и подозрительных строк:
python 01_Core_Engines/metadata_hex_scanner.py "C:\Path\To\Suspicious.pdf"
```

### 3.5. Запуск графического интерфейса (GUI) и интеграции с Thunderbird:
```bash
# Аналитическое десктопное приложение Mail Forensic Pro:
python 03_Clients_and_Integrations/Analyzer_App/mail_forensic_pro.py

# Регистрация Native Messaging Host для Mozilla Thunderbird:
powershell -ExecutionPolicy Bypass -File 03_Clients_and_Integrations/ThunderbirdPhishingGuard/register_native_host.ps1
```

---

## 👤 4. Сведения об авторстве и лицензии
- **Автор разработки:** AG-K08 (@And_8)
- **Контактный Email:** mznxncbv888@gmail.com
- **Релизная версия:** 4.1 Red Edition / OMSA v1.0 (2026)
- **Статус релиза:** Релиз v4.1 верифицирован, 56 из 56 модульных и интеграционных тестов пройдены (100% PASS).
