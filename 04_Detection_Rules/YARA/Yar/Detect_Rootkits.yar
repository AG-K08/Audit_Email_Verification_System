rule Detect_Rootkits
{
    meta:
        description = "Обнаружение руткитов на основе известных паттернов и сигнатур"
        author = "Информационная безопасность"
        date = "2025-01-28"
        reference = "MITRE ATT&CK T1561.002"
    
    strings:
        // Подозрительные функции и ключевые строки
        $hook1 = "NtQuerySystemInformation" nocase
        $hook2 = "NtSetInformationProcess" nocase
        $hook3 = "NtReadVirtualMemory" nocase
        $hook4 = "NtWriteVirtualMemory" nocase
        $rootkit1 = "Rootkit" nocase
        $hidden_file = "Hidden file detected" nocase

        // Подозрительные драйверы или модули
        $driver1 = "rkdrv.sys" nocase
        $driver2 = "malicious.sys" nocase
        $driver3 = "vboxdrv.sys" nocase

        // Шаблоны кода (HEX для перехвата функций)
        $code1 = { 8B FF 55 8B EC 83 EC 10 53 56 57 }
        $code2 = { 64 A1 24 01 00 00 8B 40 30 FF 50 }

        // Строка, связанная с изменением MBR (если необходимо)
        $mbr = "MBR modified" nocase

    condition:
        any of ($hook*) or any of ($driver*) or any of ($code*) or $mbr
}
