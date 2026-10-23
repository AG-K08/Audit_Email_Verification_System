rule Insider_Threat_Advanced_Detection
{
    meta:
        description = "Detects potential insider threat activities based on a combination of high-risk factors."
        author = "And (improved by Gemini)"
        category = "insider threat"
        created = "2024-09-17"
        updated = "2025-07-23"

    strings:
        // --- Высокий риск (High Risk) ---
        // Использование средств анонимизации и несанкционированного удаленного доступа
        $high_risk_tools = /(TeamViewer|AnyDesk|AeroAdmin|Tor Browser|I2P)/ ascii wide nocase
        // Команды для массового копирования или архивации
        $high_risk_commands = /(xcopy|robocopy|7z\.exe a|zip\.exe -r)/ ascii wide nocase

        // --- Средний риск (Medium Risk) ---
        // Подключение внешних накопителей
        $medium_risk_device = "USBSTOR\\Disk" ascii wide
        // Использование стандартных утилит передачи файлов
        $medium_risk_transfer = /(ftp|sftp|scp|rsync|POST \/upload)/ ascii wide
        // Повышение привилегий
        $medium_risk_privs = "SeDebugPrivilege" ascii wide

        // --- Контекст: Конфиденциальные данные ---
        // Ключевые слова в именах файлов или документах
        $context_sensitive_keywords = /(секретно|конфиденциально|ДСП|для служебного пользования|commercial secret)/ ascii wide nocase

    condition:
        // Сценарий 1: Явный инструмент высокого риска + контекст утечки данных
        (1 of ($high_risk*)) and ($medium_risk_device or $context_sensitive_keywords)
        or
        // Сценарий 2: Комбинация нескольких событий среднего риска с контекстом
        (2 of ($medium_risk*)) and $context_sensitive_keywords
        or
        // Сценарий 3: Массовое копирование на внешний носитель
        $high_risk_commands and $medium_risk_device
}