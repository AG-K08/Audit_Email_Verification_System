rule Qakbot_Malware_Detection
{
    meta:
        description = "YARA rule to detect Qakbot (aka Qbot, Pinkslipbot, QuackBot) malware"
        author = "Ваше имя"
        date = "2024-10-19"
        version = "1.0"
        reference = "https://securelist.com/qakbot-technical-analysis/103931/"

    strings:
        $str1 = "Mimikatz" nocase
        $str2 = "schtasks.exe" nocase
        $str3 = "regsvr32.exe -s" nocase
        $str4 = "net config workstation" nocase
        $str5 = "ipconfig /all" nocase
        // $str6 = { 50 4B 03 04 14 00 06 00 }  // Начало ZIP-файлов
        // $str7 = { 68 74 74 70 3A 2F 2F }      // "http://"
        $c2_patterns = /https?:\/\/[a-z0-9\-\.]+\.[a-z]{2,}/ nocase  // C2-адреса

    condition:
        uint16(0) == 0x5A4D and ((
            // Проверяем наличие ключевых строк в файле
            any of ($str1, $str2, $str3, $str4, $str5) 
            or 
            // Смотрим, есть ли подозрительные ссылки
            #c2_patterns > 5
        )
        and 
        // Проверяем размер файла (например, не менее 10 КБ и не более 10 МБ)
        filesize > 10KB and filesize < 10MB
)
}
