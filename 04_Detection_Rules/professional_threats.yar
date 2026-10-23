/* ПРАВИЛО 1: Выявление скрытых и обфусцированных объектов в PDF */
rule PDF_Suspicious_Obfuscation {
    meta:
        description = "Обнаружение обфусцированных тегов и скрытых вложений в PDF"
        author = "Критик"
        severity = "High"
    strings:
        $js1 = "/JavaScript" ascii nocase
        $js2 = "/JS" ascii nocase
        $launch = "/Launch" ascii nocase
        $emb = "/EmbeddedFiles" ascii nocase
        $hex_obs = /\#[0-9A-Fa-f]{2}/ 
        $flt_obs = "/Filter [/FlateDecode /ASCIIHexDecode]" ascii nocase
    condition:
        uint32(0) == 0x46445025 // "%PDF"
        and (
            1 of ($js*, $launch, $emb) 
            or #hex_obs > 5 
            or $flt_obs
        )
}

/* ПРАВИЛО 2: Эвристика VBA-дропперов в документах Office */
rule Office_VBA_Dropper_Heuristics {
    meta:
        description = "Детектирование логики автоматического запуска и загрузки (Dropper)"
        author = "Критик"
        severity = "Critical"
    strings:
        $auto1 = "AutoOpen" ascii nocase
        $auto2 = "Workbook_Open" ascii nocase
        $auto3 = "Document_Open" ascii nocase
        $exec1 = "Shell" fullword ascii nocase
        $exec2 = "WScript.Shell" ascii nocase
        $exec3 = "CreateObject" ascii nocase
        $susp1 = "powershell" ascii nocase
        $susp2 = "-enc" ascii nocase
        $susp3 = "XMLHTTP" ascii nocase
    condition:
        uint32(0) == 0xE011CFD0 
        and (1 of ($auto*))
        and (1 of ($exec*))
        and (1 of ($susp*))
}

/* ПРАВИЛО 3: Целевой B2B Фишинг (BEC) */
rule BEC_Phishing_Russian_B2B {
    meta:
        description = "Детектирование паттернов социальной инженерии (Тендеры, Счета) с бесплатной почты"
        author = "Критик"
        severity = "Medium"
    strings:
        $urgency1 = "срочно" ascii nocase wide
        $urgency2 = "до конца дня" ascii nocase wide
        $lure1 = "коммерческое предложение" ascii nocase wide
        $lure2 = "тендер" ascii nocase wide
        $lure3 = "запрос кп" ascii nocase wide
        $lure4 = "оплат" ascii nocase wide
        $free_mail1 = "@yandex." ascii nocase
        $free_mail2 = "@gmail." ascii nocase
        $free_mail3 = "@mail.ru" ascii nocase
    condition:
        (2 of ($lure*)) and (1 of ($urgency*) or 1 of ($free_mail*))
}

import "pe"

/* ПРАВИЛО 4: Выявление известных пакеров и протекторов */
rule PE_Suspicious_Packer_Sections {
    meta:
        description = "Обнаружение секций популярных крипторов и пакеров (UPX, VMProtect, Themida)"
        author = "Критик"
        severity = "High"
    condition:
        uint16(0) == 0x5A4D and 
        for any i in (0..pe.number_of_sections - 1): (
            pe.sections[i].name == ".vmp0" or 
            pe.sections[i].name == ".vmp1" or 
            pe.sections[i].name == ".themida" or 
            pe.sections[i].name == "UPX0" or 
            pe.sections[i].name == ".enigma"
        )
}

/* ПРАВИЛО 5: Паттерны инъекции кода (Process Injection) */
rule PE_Process_Injection_APIs {
    meta:
        description = "Детектирование классической триады инъекции (VirtualAllocEx -> WriteProcessMemory -> CreateRemoteThread)"
        author = "Критик"
        severity = "Critical"
    condition:
        uint16(0) == 0x5A4D and
        pe.imports("kernel32.dll", "VirtualAllocEx") and
        pe.imports("kernel32.dll", "WriteProcessMemory") and
        (
            pe.imports("kernel32.dll", "CreateRemoteThread") or
            pe.imports("ntdll.dll", "NtCreateThreadEx") or
            pe.imports("kernel32.dll", "QueueUserAPC")
        )
}

/* ПРАВИЛО 6: Артефакты инфостилеров (Infostealers) */
rule PE_Infostealer_Artifacts {
    meta:
        description = "Обнаружение строк, характерных для стилеров (AgentTesla, RedLine, Raccoon)"
        author = "Критик"
        severity = "High"
    strings:
        $target1 = "Login Data" ascii wide
        $target2 = "Web Data" ascii wide
        $target3 = "Cookies" fullword ascii wide
        $target4 = "wallet.dat" ascii wide
        $sql1 = "SELECT action_url, username_value, password_value FROM logins" ascii wide
    condition:
        uint16(0) == 0x5A4D and 
        2 of ($target*) and any of ($sql*)
}
