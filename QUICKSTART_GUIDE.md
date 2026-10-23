# РУКОВОДСТВО ПО УСТАНОВКЕ И БЫСТРОМУ ЗАПУСКУ (QUICKSTART GUIDE)
## Комплекс статического анализа и форензики писем и документов «Audit_Email_Verification_System»
**Версия:** 4.0 Red Edition / OMSA v1.0  
**Автор:** AG-K08 (@And_8)  
**Email:** mznxncbv888@gmail.com  
**Год релиза:** 2026  

---

## 1. УСТАНОВКА И РАЗВЕРТЫВАНИЕ СИСТЕМЫ НА НОВОМ ПК

Система спроектирована с учетом полной автономности и портативности: все пути вычисляются динамически относительно корня репозитория, жестко заданные пути отсутствуют, а при работе в минимальном окружении включаются механизмы отказоустойчивости (graceful degradation).

### Вариант А: Автоматическая установка в 1 клик (Рекомендуется)
1. Откройте папку проекта на целевом компьютере.
2. Запустите установочный сценарий:
   - В **Windows CMD**: двойной клик или команда `setup_environment.bat`
   - В **PowerShell**: `powershell -ExecutionPolicy Bypass -File setup_environment.ps1`
3. Скрипт автоматически:
   - Проверит наличие интерпретатора Python (поддерживаются Python **3.10 – 3.14**);
   - Создаст изолированное виртуальное окружение `.venv`;
   - **Автономный режим (Air-Gap):** если в корне присутствует каталог `vendor_wheels/`, выполнит 100% офлайн-установку без доступа в Интернет (`--no-index --find-links=vendor_wheels`);
   - Если каталога `vendor_wheels/` нет — установит зависимости из `requirements.txt` через PyPI;
   - Запустит полный верификационный пакет из **56 автотестов (`pytest`)** и подтвердит готовность всех подсистем.

### Вариант Б: Ручная установка (Офлайн Air-Gap / Онлайн)
```powershell
# 1. Перейдите в корень проекта
cd Audit_Email_Verification_System

# 2. Создайте и активируйте виртуальное окружение
python -m venv .venv
# Windows CMD:
.venv\Scripts\activate.bat
# Windows PowerShell:
.venv\Scripts\Activate.ps1

# 3. Установите зависимости:
# А) В закрытом контуре без интернета (из локального каталога vendor_wheels):
pip install --no-index --find-links=vendor_wheels -r requirements.txt

# Б) При наличии интернета (через PyPI):
pip install --upgrade pip
pip install -r requirements.txt

# 4. Проверьте работоспособность запуском всех 56 автотестов
python -m pytest 06_Audit_Tests_and_Samples/ -v
```

> **Примечание по внешним утилитам:**
> - Архивы `.zip`, `.tar`, `.tar.gz`, `.tgz` распаковываются нативно встроенными средствами Python (с защитой от Zip-Slip / Tar-Slip).
> - Для автоматической распаковки контейнеров `.rar`, `.7z` и `.iso` рекомендуется наличие установленного архиватора **7-Zip** (`C:\Program Files\7-Zip\7z.exe` или в системном `PATH`).

---

## 2. АНАЛИЗ ПОЧТОВЫХ СООБЩЕНИЙ (`.EML` / `.MSG` / ВЛОЖЕННЫЕ `message/rfc822`)

Система поддерживает стандартные письма `.eml` (RFC 5322, любые кодировки включая `UTF-8`, `Windows-1251`, `KOI8-R`), бинарные сообщения MS Outlook `.msg` (OLE2), контейнеры `winmail.dat` (TNEF) и рекурсивно вложенные пересланные письма (`message/rfc822`).

### 2.1. Полный 9-этапный сквозной аудит письма (`analyze_email_full.py`)
Выполняет разбор заголовков (`SPF`/`DKIM`/`DMARC`, `Received`), тела, ссылок, Quishing (QR-кодов), извлечение вложений и архивов, анализ Office/PDF/RTF/LNK/HTML-Smuggling, сканирование YARA и Nuclei.
- **Проверка тестового образца:**
  ```powershell
  python 01_Core_Engines/analyze_email_full.py 06_Audit_Tests_and_Samples/test.eml
  ```
- **Проверка внешнего письма с сохранением копии JSON-отчета в указанный файл:**
  ```powershell
  python 01_Core_Engines/analyze_email_full.py "C:\Cases\Suspicious_Invoice.eml" --output "C:\Reports\invoice_verdict.json"
  ```
- **Быстрый запуск через Batch-скрипт (поддерживает перетаскивание файла мышкой Drag & Drop):**
  ```cmd
  01_Core_Engines\analyze_email.bat "C:\Cases\Suspicious_Invoice.eml"
  ```

### 2.2. Мастер-конвейер угроз с генерацией Markdown-отчета (`analyze_threats.py`)
Запускает `PhishingEngine v4.0`, извлекает вложения из `.eml` / `.msg`, прогоняет YARA-сигнатуры и углубленные сканеры, формируя итоговые файлы `FINAL_REPORT.md` и `ОТЧЕТ_АНАЛИЗА.txt`:
```powershell
python 01_Core_Engines/analyze_threats.py 06_Audit_Tests_and_Samples/test.eml
```

### 2.3. Отказоустойчивый JSON-анализатор (`robust_analyzer.py`)
Возвращает структурированный JSON-отчет по письму (`.eml`/`.msg`) или произвольному бинарному файлу и сохраняет копию в папку `Reports/`:
```powershell
python 01_Core_Engines/robust_analyzer.py 06_Audit_Tests_and_Samples/test.eml
```

### 2.4. Массовый поиск индикаторов по базе писем (`grep_eml.py`)
```powershell
python 01_Core_Engines/grep_eml.py "06_Audit_Tests_and_Samples"
```

---

## 3. АНАЛИЗ ДОКУМЕНТОВ OFFICE, PDF, АРХИВОВ И МЕДИАФАЙЛОВ

### 3.1. Подсистема OMSA v1.0 (`office_analyzer.py`)
8-блочный статический анализатор документов MS Office (`.docx`, `.docm`, `.doc`, `.xlsx`, `.xlsm`, `.xls`, `.pptx`, `.pptm`, `.ppt`, `.dotx`, `.dotm`, `.xltx`, `.xltm`, `.rtf`, `.xml`, `.mht`). Выявляет VBA/XLM-макросы, **VBA P-Code Stomping**, опасные элементы ActiveX, DDE и внешние шаблоны.
- **Базовый запуск:**
  ```powershell
  python 02_Office_Macro_Analyzer_OMSA/office_analyzer.py "06_Audit_Tests_and_Samples/test_document.docx"
  ```
- **Офлайн-запуск с принудительным анализом P-Code и сохранением отчетов в заданную папку (`--output` или `--output-dir`):**
  ```powershell
  python 02_Office_Macro_Analyzer_OMSA/office_analyzer.py "06_Audit_Tests_and_Samples/test_document.docx" --offline --pcode --output "C:\Reports\OMSA_Report"
  ```

### 3.2. Автономная портативная сборка OMSA (`Distributable/main_launcher.py`)
Самодостаточный дистрибутивный пакет для переноса на изолированные рабочие станции:
```powershell
python 03_Clients_and_Integrations/Distributable/main_launcher.py "06_Audit_Tests_and_Samples/test_document.docx" --offline -o "C:\Reports\Dist_Report"
```

### 3.3. Безопасный in-memory разбор структуры Office (`safe_office_deep_scan.py`)
Анализирует внутреннюю структуру ZIP/OOXML и потоки OLE2 в оперативной памяти без вызова системных библиотек Office:
```powershell
python 01_Core_Engines/safe_office_deep_scan.py "06_Audit_Tests_and_Samples/test_document.docx"
```

### 3.4. Детектор безмакросных угроз Office: Remote Template Injection, DDE, OLE, RTF (`office_document_threats.py`)
```powershell
python 01_Core_Engines/office_document_threats.py "06_Audit_Tests_and_Samples/test_document.docx"
```

### 3.5. Сканер метаданных PDF, скрытых HEX-инъекций и GPS-координат (`metadata_hex_scanner.py`)
Ищет скрытые в метаданных HEX-инъекции (`4d5a9000...`, `0xFF, 0xD8`), скрытые GPS-координаты и подозрительные строки в PDF, документах и изображениях:
```powershell
python 01_Core_Engines/metadata_hex_scanner.py "C:\Cases\Suspicious_Document.pdf"
```

### 3.6. Карвинг встроенных изображений и проверка хвостовых оверлеев (`carve_images.py`)
Извлекает встроенные графические объекты (`JPEG`, `PNG`, `GIF`, `BMP`, `EMF`) из документов/писем в папку `carved_output/`:
```powershell
python 01_Core_Engines/carve_images.py "06_Audit_Tests_and_Samples/test_document.docx"
```

---

## 4. ГРАФИЧЕСКИЙ ИНТЕРФЕЙС ANALYZER APP («Mail Forensic Pro»)

Настольное GUI-приложение для аналитиков SOC L1/L2 с поддержкой перетаскивания файлов (Drag-and-Drop) и визуализацией дерева угроз.

- **Запуск приложения:**
  ```powershell
  python 03_Clients_and_Integrations/Analyzer_App/mail_forensic_pro.py
  ```
- **Сборка автономного `.exe` через PyInstaller (опционально):**
  ```powershell
  cd 03_Clients_and_Integrations/Analyzer_App
  pyinstaller --clean MailForensicPro.spec
  ```

---

## 5. ИНТЕГРАЦИЯ С ПОЧТОВЫМ КЛИЕНТОМ MOZILLA THUNDERBIRD

Каталог `03_Clients_and_Integrations/ThunderbirdPhishingGuard/` содержит расширение Thunderbird и серверный мост Native Messaging:
1. **Регистрация Native Messaging Host в реестре Windows:**
   ```powershell
   powershell -ExecutionPolicy Bypass -File 03_Clients_and_Integrations/ThunderbirdPhishingGuard/register_native_host.ps1
   ```
2. **Подключение расширения в Thunderbird:**
   Откройте `Инструменты -> Дополнения и темы -> ⚙️ Отладка дополнений -> Загрузить временное дополнение...` и выберите файл `03_Clients_and_Integrations/ThunderbirdPhishingGuard/manifest.json`.

---

## 6. АВТОМАТИЗИРОВАННОЕ ТЕСТИРОВАНИЕ (PYTEST)

Комплекс включает **56 автоматизированных тестов**, проверяющих все модули, точки входа и матрицу форматов писем и вложений:

```powershell
# Полный прогон всех 56 тестов:
python -m pytest 06_Audit_Tests_and_Samples/ -v

# 1. Тесты ядра PhishingEngine (заголовки, ссылки, скоринг):
python -m pytest 06_Audit_Tests_and_Samples/test_phish_engine.py -v

# 2. Тесты сквозного анализатора analyze_email_full.py:
python -m pytest 06_Audit_Tests_and_Samples/test_analyze_email_full.py -v

# 3. Тесты расширенных эшелонов (Quishing QR, LNK, Cloud Phishing, TAR/GZ):
python -m pytest 06_Audit_Tests_and_Samples/test_advanced_phish.py -v

# 4. Матричный предрелизный пакет (все форматы писем, кодировки, вложения и CLI/NativeHost точки входа):
python -m pytest 06_Audit_Tests_and_Samples/test_release_readiness_matrix.py -v
```
