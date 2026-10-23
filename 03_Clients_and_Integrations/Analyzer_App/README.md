# Mail Forensic Pro (GUI)

Точка входа: **`03_Clients_and_Integrations/Analyzer_App/mail_forensic_pro.py`**.

## Зависимости

- Python 3.10 – 3.14  
- `tkinterdnd2` (поддержка Drag-and-Drop, опционально): `pip install tkinterdnd2`  
- Зависимости из корневого `requirements.txt` (аналитические движки подключаются автоматически из каталога `01_Core_Engines/`).

## Запуск из исходного кода

Из корня проекта `Audit_Email_Verification_System`:

```powershell
python 03_Clients_and_Integrations/Analyzer_App/mail_forensic_pro.py
```

## Сборка автономного EXE (PyInstaller)

Из каталога `03_Clients_and_Integrations/Analyzer_App`:

```powershell
cd 03_Clients_and_Integrations/Analyzer_App
pyinstaller --clean MailForensicPro.spec
```

Артефакты сборки (`build/`, `dist/`) создаются локально при компиляции.
