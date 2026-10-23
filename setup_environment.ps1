# ==============================================================================
# Audit_Email_Verification_System v4.0 (Red Edition / OMSA v1.0)
# PowerShell Environment Setup & Validation Automation
# Author: AG-K08 (@And_8) <mznxncbv888@gmail.com> (2026)
# ==============================================================================

[Console]::OutputEncoding = [System.Text.Encoding]::UTF8
$Host.UI.RawUI.WindowTitle = "Audit_Email_Verification_System - Environment Setup"

Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[INFO] Инициализация окружения: Audit_Email_Verification_System v4.0" -ForegroundColor Cyan
Write-Host "[INFO] Автор: AG-K08 (@And_8) <mznxncbv888@gmail.com> (2026)" -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

# 1. Проверка Python
try {
    $pythonVersion = python --version 2>&1
    Write-Host "[OK] Обнаружен интерпретатор: $pythonVersion" -ForegroundColor Green
} catch {
    Write-Host "[CRITICAL] Python не обнаружен в PATH! Установите Python 3.10-3.14." -ForegroundColor Red
    Read-Host "Нажмите Enter для выхода..."
    exit 1
}

# 2. Создание .venv
$VenvPython = Join-Path $ScriptDir ".venv\Scripts\python.exe"
if (-not (Test-Path $VenvPython)) {
    Write-Host "[INFO] Создание изолированного виртуального окружения .venv..." -ForegroundColor Yellow
    python -m venv .venv
    if ($LASTEXITCODE -ne 0) {
        Write-Host "[ERROR] Ошибка создания виртуального окружения." -ForegroundColor Red
        exit 1
    }
    Write-Host "[OK] Виртуальное окружение .venv успешно создано." -ForegroundColor Green
} else {
    Write-Host "[INFO] Виртуальное окружение .venv уже существует." -ForegroundColor Yellow
}

# 3. Установка зависимостей (автоопределение Air-Gap / Offline режима)
$VendorDir = Join-Path $ScriptDir "vendor_wheels"
$ReqFile = Join-Path $ScriptDir "requirements.txt"

if (Test-Path $VendorDir) {
    Write-Host "[INFO] Обнаружен локальный архив пакетов: vendor_wheels (Режим Air-Gap)." -ForegroundColor Yellow
    Write-Host "[INFO] Обновление инструментов упаковки из локального архива..." -ForegroundColor Yellow
    & $VenvPython -m pip install --no-index --find-links=$VendorDir --upgrade pip setuptools wheel --quiet
    Write-Host "[INFO] Автономная установка зависимостей без доступа в Интернет..." -ForegroundColor Yellow
    & $VenvPython -m pip install --no-index --find-links=$VendorDir -r $ReqFile
} else {
    Write-Host "[INFO] Обновление базовых инструментов упаковки..." -ForegroundColor Yellow
    & $VenvPython -m pip install --upgrade pip setuptools wheel --quiet
    Write-Host "[INFO] Установка зависимостей из requirements.txt (онлайн через PyPI)..." -ForegroundColor Yellow
    & $VenvPython -m pip install -r $ReqFile
}

# 4. Валидация через pytest
Write-Host "==============================================================================" -ForegroundColor Cyan
Write-Host "[INFO] Запуск регрессионного аудита тестов (pytest)..." -ForegroundColor Cyan
Write-Host "==============================================================================" -ForegroundColor Cyan
& $VenvPython -m pytest (Join-Path $ScriptDir "06_Audit_Tests_and_Samples") -v --tb=short

if ($LASTEXITCODE -eq 0) {
    Write-Host "==============================================================================" -ForegroundColor Green
    Write-Host "[OK] Все тесты успешно пройдены (100% GREEN). Система готова к работе!" -ForegroundColor Green
    Write-Host "==============================================================================" -ForegroundColor Green
} else {
    Write-Host "[ALERT] Часть тестов завершилась с ошибками. Проверьте вывод консоли." -ForegroundColor Red
}

Write-Host ""
Read-Host "Нажмите Enter для завершения..."
