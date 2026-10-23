@echo off
chcp 65001 >nul
setlocal EnableDelayedExpansion

title Audit_Email_Verification_System v4.0 - Environment Setup
echo ==============================================================================
echo [INFO] Инициализация окружения: Audit_Email_Verification_System v4.0 (Red Edition)
echo [INFO] Автор: AG-K08 (@And_8) ^<mznxncbv888@gmail.com^> (2026)
echo ==============================================================================

cd /d "%~dp0"

REM 1. Проверка наличия Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [CRITICAL] Python не обнаружен в PATH! Пожалуйста, установите Python 3.10-3.14.
    pause
    exit /b 1
)

for /f "tokens=*" %%i in ('python --version') do set PYTHON_VER=%%i
echo [OK] Обнаружен интерпретатор: %PYTHON_VER%

REM 2. Создание виртуального окружения .venv
set VENV_PY=%~dp0.venv\Scripts\python.exe

if not exist "%VENV_PY%" (
    echo [INFO] Создание виртуального окружения .venv...
    python -m venv .venv
    if errorlevel 1 (
        echo [ERROR] Не удалось создать виртуальное окружение!
        pause
        exit /b 1
    )
    echo [OK] Виртуальное окружение .venv успешно создано.
) else (
    echo [INFO] Виртуальное окружение .venv уже существует.
)

REM 3. Установка зависимостей напрямую через venv python
if exist vendor_wheels (
    echo [INFO] Обнаружен локальный архив пакетов: vendor_wheels (Режим автономной установки Air-Gap).
    echo [INFO] Обновление инструментов упаковки из локального архива...
    "%VENV_PY%" -m pip install --no-index --find-links=vendor_wheels --upgrade pip setuptools wheel --quiet
    echo [INFO] Установка зависимостей в офлайн-режиме (без доступа в Интернет)...
    "%VENV_PY%" -m pip install --no-index --find-links=vendor_wheels -r requirements.txt
) else (
    echo [INFO] Обновление базовых инструментов упаковки (pip, setuptools, wheel)...
    "%VENV_PY%" -m pip install --upgrade pip setuptools wheel --quiet
    echo [INFO] Установка зависимостей из requirements.txt (онлайн через PyPI)...
    "%VENV_PY%" -m pip install -r requirements.txt
)

if errorlevel 1 (
    echo [WARN] Некоторые зависимости вызвали предупреждения при установке.
) else (
    echo [OK] Все основные зависимости успешно установлены.
)

REM 4. Валидационный прогон тестов
echo ==============================================================================
echo [INFO] Запуск верификационных тестов ядра (pytest)...
echo ==============================================================================
"%VENV_PY%" -m pytest 06_Audit_Tests_and_Samples\ -v --tb=short
if errorlevel 1 (
    echo [ALERT] Обнаружены ошибки при выполнении тестов! Проверьте логи выше.
) else (
    echo ==============================================================================
    echo [OK] Все тесты успешно пройдены (100%% GREEN).
    echo [OK] Система полностью готова к автономной работе на данном ПК.
    echo ==============================================================================
)

echo.
echo Нажмите любую клавишу для завершения...
pause >nul
