# 🛡️ Автономный дистрибутивный пакет форензики и анализа фишинга (OMSA v1.0 + Utils)

**Разработчик:** AG-K08 (@And_8)  
**Версия:** 4.0 (Red Edition / OMSA v1.0)

Данный каталог представляет собой портативную сборку инструментов для статического анализа вредоносных писем и вложений (MS Office, PDF, архивы, изображения) без их запуска в операционной системе.

## 📁 Структура пакета
- `main_launcher.py` — единая точка входа для запуска анализатора документов OMSA v1.0.
- `src/analyzer/` — **Office Macro Security Analyzer (OMSA)**: декомпиляция VBA, выявление VBA P-Code Stomping, анализ ActiveX/OLE и извлечение сетевых IoC.
- `src/utils/` — вспомогательные криминалистические утилиты:
  - `phishing_orchestrator.py` — мастер-скрипт комплексной проверки писем (`.eml`, `.msg`) и вложений.
  - `pdf_scanner.py` — глубокий аудит структуры PDF (`/JavaScript`, `/OpenAction`, `/Launch`, YARA).
  - `media_scanner.py` — проверка изображений на хвостовые оверлеи (Trailing Data) и стеганографию.
  - `archive_extractor.py` — безопасная распаковка архивов и контейнеров TNEF/`winmail.dat`/`.msg`.
  - `string_extractor.py` — поиск закодированных строк, GPS-координат и HEX-полезной нагрузки.
  - `image_carver.py` — вырезание встроенных изображений по бинарным сигнатурам.
- `docs/` — эксплуатационная документация, методология и техническая спецификация.

## 🚀 Установка и использование

1. **Установка зависимостей:**
   ```powershell
   pip install -r requirements.txt
   ```

2. **Запуск анализа документа Office (CLI):**
   ```powershell
   # Передача пути позиционным аргументом или через флаг --file:
   python main_launcher.py "path/to/suspect_file.docx" --offline -o "./results"
   python main_launcher.py --file "path/to/suspect_file.docm" --offline --output-dir "./results"
   ```

3. **Запуск полного анализа письма (`.eml` / `.msg`) или вложения через оркестратор:**
   ```powershell
   python src/utils/phishing_orchestrator.py "path/to/suspicious_email.eml"
   ```

4. **Результаты анализа:**
   Отчеты сохраняются в указанной директории вывода (`./results/` по умолчанию) в форматах JSON (машиночитаемый) и TXT/MD (для аналитика ИБ).
