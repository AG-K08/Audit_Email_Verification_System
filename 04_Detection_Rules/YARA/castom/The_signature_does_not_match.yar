rule Phishing_Attachment
{
    meta:
        description = "Detects potential phishing attachments with hidden executables or malicious payloads"
        author = "And"
        date = "2024-10-19"
        category = "phishing detection"

    strings:
        // Заголовки PE-файлов
        $mz_header = { 4D 5A }  // "MZ"
        $pe_header = { 50 45 00 00 }  // "PE\0\0"

        // Подозрительное содержимое фишинговых писем
        // $macro = "AutoOpen" ascii
        $powershell = "powershell.exe" ascii
        // $url_link = /(https?:\/\/[^\s]+)/ ascii wide
        $suspicious_ext = /(\.pdf\.exe|\.docx\.exe|\.xlsx\.exe|\.jpg\.exe)/ ascii nocase

    condition:
        (
            // Проверка на PE-файл (исполняемый файл)
            $mz_header at 0 and $pe_header at (uint32(0x3C))
        ) or 
        (
            // Поиск подозрительных строк или расширений
            any of ($powershell, $suspicious_ext)
        )
}
