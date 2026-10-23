rule APT_CloudAtlas_InitialAccess_DOC_v2
{
    meta:
        author = "Threat Intelligence Analyst"
        date = "2024-07-23"
        description = "Обнаруживает вредоносные документы Microsoft Word, используемые APT-группировкой Cloud Atlas (Inception). Правило сфокусировано на их специфической технике внедрения URL-адресов удаленных шаблонов в потоки OLE '1Table' или '0Table'."
        reference_pt = "https://global.ptsecurity.com/en/research/pt-esc-threat-intelligence/apt-cloud-atlas-unbroken-threat/"
        reference_kaspersky = "https://securelist.com/cloud-atlas-attacks-with-new-backdoor-vbcloud/115103/"
        apt_group = "Cloud Atlas, Inception, Oxygen, Red October"
        mitre_tactic = "Initial Access"
        mitre_technique = "T1566.001, T1221"
        cve = "CVE-2017-11882, CVE-2018-0802"
        hash1 = "8df0d05c36a64b13869343917076ba8f65604ea1ecde50292f361ad4e34b4b09"
        version = "2.0"

    strings:
        // --- Основная сигнатура: Внедрение шаблона через поток 1Table/0Table ---
        // Заголовок OLE-файла (магическое число)
        $ole_header = { D0 CF 11 E0 A1 B1 1A E1 }

        // Имена потоков OLE "1Table" или "0Table"
        // $stream_1Table = "1Table" wide
        // $stream_0Table = "0Table" wide

        // Строка HTTP/HTTPS ссылки
        // $http_link = "http" ascii

        // --- Вспомогательные сигнатуры: Имена файлов и артефакты ---
        // Имена файлов полезной нагрузки из конфигураций вредоносного ПО
        $payload_name1 = "callicrates" ascii
        $payload_name2 = "tinh" ascii
        $payload_name3 = "amianthium" ascii
        $payload_name4 = "mandarinduck" ascii
        $payload_name5 = "cushioning" ascii
        $payload_name6 = "kingsclover" ascii

        // Уникальное имя объекта из RTF-эксплойта (CVE-2017-11882)
        $rtf_obj1 = "weaseoijsd" ascii

        // Строки из бэкдора PowerShower
        $ps_func1 = "HttpRequestG" ascii
        $ps_func2 = "HttpRequestP" ascii

    condition:
        // --- Логика обнаружения ---

        // Основная логика (высокая точность):
        // Файл считается вредоносным, если это OLE-файл И
        // он содержит И имя потока ('1Table' или '0Table'), И строку 'http'.
        // Эта комбинация является ключевой и очень надежной "визитной карточкой" Cloud Atlas.
        /* (
            $ole_header at 0 and
            ( $stream_1Table or $stream_0Table ) and
            $http_link
        ) or */

        // Вторичная логика (для обнаружения вариантов):
        // Файл также считается подозрительным, если это OLE-файл И
        // он содержит как минимум два из вспомогательных индикаторов.
        // Это помогает выявлять другие компоненты атаки или их варианты.
        (
            $ole_header at 0 and
            2 of ( $payload_name*, $rtf_obj*, $ps_func* )
        )
}
