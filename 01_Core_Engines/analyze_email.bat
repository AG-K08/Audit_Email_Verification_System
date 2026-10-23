@echo off
setlocal EnableExtensions
chcp 65001 >nul 2>&1

set "SCRIPT_DIR=%~dp0"
set "PYTHON=python"

if not "%~1"=="" (
    set "EMAIL_PATH=%~1"
    goto run
)

echo.
echo  Анализ письма на фишинг
echo  -----------------------
echo  Укажите полный путь к файлу .eml или .msg
echo  (можно перетащить файл на этот bat-файл)
echo.
set /p "EMAIL_PATH=Путь: "

if not defined EMAIL_PATH (
    echo [Ошибка] Путь не указан.
    pause
    exit /b 1
)

:run
set "EMAIL_PATH=%EMAIL_PATH:"=%"

if not exist "%EMAIL_PATH%" (
    echo [Ошибка] Файл не найден: %EMAIL_PATH%
    pause
    exit /b 1
)

echo.
echo [*] Запуск анализа: %EMAIL_PATH%
echo.

"%PYTHON%" "%SCRIPT_DIR%analyze_email_full.py" "%EMAIL_PATH%"
set "EXIT_CODE=%ERRORLEVEL%"

echo.
if %EXIT_CODE% equ 0 (
    echo [Готово] См. папку Extracted_* и файлы analysis_* рядом с письмом.
) else (
    echo [Ошибка] Код выхода: %EXIT_CODE%
)
echo.
pause
exit /b %EXIT_CODE%
