rule CloudAtlas_Indicators {
    meta:
        description = "Indicators for Cloud Atlas APT activities"
        author = "Generated"
        date = "2024-12-18"
        reference = "APT Cloud Atlas: Unbroken Threat"
        tc_detection_type = "APT"
        tc_detection_name = "CloudAtlas"
        tc_detection_factor = 3

    strings:
        // MITRE ATT&CK TTPs
        $ttp_T1583 = "officeconfirm.technoguides.org"
        $ttp_T1585 = "pe9ov.sem@yandex.ru"
        $ttp_T1587_001 = "PowerShower"
        $ttp_T1587_002 = "CloudAtlas Loader"
        $ttp_T1587_003 = "VBShower"
        $ttp_T1566_001 = "internet.ru"
        $ttp_T1059_001 = "PowerShell"
        $ttp_T1059_005 = "Visual Basic"
        $ttp_T1203 = "Microsoft Office"
        $ttp_T1547_001 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
        $ttp_T1053_005 = "CiscoMngr"
        $ttp_T1070_004 = "File Deletion"
        $ttp_T1564_004 = "NTFS File Attributes"
        $ttp_T1574_002 = "DLL Side-Loading"
        $ttp_T1036_005 = "Match Legitimate Name or Location"
        $ttp_T1012 = "HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings"

        // File Indicators
        $file_1 = "9943fee873c0642216d1578fc4373648b670b5bc47a8bf37366063041518f8b2"
        $file_2 = "e09f90563be00fc947a80bb1902a1b05c9e9aa8c86d01a34204717d68eb1684f"
        $file_3 = "c985309140500090ad457c4e380b461b7548cf837ddd45415edd4653e2ef50b2"
        $file_4 = "89d56295bc8571334aa6916587d3ca6be01934b97f5fdf1cf895d1beda1d73bf"
        $file_5 = "650409dc7ba6e4565e7ba598d9a21fa422cdc0404ab188d368faced929d634cf"
        $file_6 = "27f77e73e1b1ce12b098362019266f5acb64f4bc34752ca0e3a16229880d300d"

        // Network Indicators
        $domain_1 = "mehafon.com"
        $domain_2 = "officeconfirm.technoguides.org"
        $domain_3 = "technoguides.org"
        $domain_4 = "mirconnect.info"
        $domain_5 = "jhsdshdkajdhgfyhsfhjshh.cfd"
        $domain_6 = "web-whatapp.net"
        $ip_1 = "79.143.87.233"
        $ip_2 = "188.127.235.216"
        $ip_3 = "185.99.2.168"
        $ip_4 = "176.124.33.86"
        $ip_5 = "80.85.153.195"
        $ua_1 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20200201 Firefox/132.0"
        $ua_2 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.2535.93"

        // Legitimate Services
        $legit_service_1 = "webdav.yandex.ru"
        $legit_service_2 = "oauth2.googleapis.com"
        $legit_service_3 = "sheets.googleapis.com"
        $legit_service_4 = "googleusercontent.com"

        // Decoded PowerShell code
        $decoded_ps_code = "$la = net accounts;[io.file]::WriteAllText($env:temp+\"\\sapp.xtx\", $la);;;"

        // VBScript actions
        $vbscript_actions = "HKCU:\\Volatile Environment"

        // HTA file functionality
        $hta_create_file = "%APPDATA%\\Microsoft\\Windows\\khaki.xml"
        $hta_create_ads_1 = "khaki.xml:khakiing.vbs"
        $hta_create_ads_2 = "khaki.xml:khaki.vbs"
        $hta_create_ads_3 = "khaki.xml:khaki.hxn"
        $hta_create_ads_4 = "khaki.xml:khakiinit.vbs"
        $hta_autorun = "wscript /B \"%APPDATA%\\Microsoft\\Windows\\khaki.xml:khaki.vbs\""
        $hta_execute_ads_1 = "wscript /B \"%APPDATA%\\Microsoft\\Windows\\khaki.xml:khakiing.vbs\""
        $hta_execute_ads_2 = "wscript /B \"%APPDATA%\\Microsoft\\Windows\\khaki.xml:khakiinit.vbs\""

        // Additional Indicators
        // Email addresses used by the attackers
        $email_1 = "infocentre.gov@mail.ru"
        $email_2 = "middleeasteye@asia.com"
        $email_3 = "simbf2019@mail.ru"
        $email_4 = "world_overview@politician.com"
        $email_5 = "infocentre.gov@bk.ru"

        // VBShower registry key pattern
        $vbshower_registry_key = /HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[a-f0-9A-F]{8}/
        $vbshower_registry_value = /wscript \/\/B \"%APPDATA%\\[A-Za-z]{5}.vbs\"/

        // VBS file paths
        $vbs_file_1 = "%APPDATA%\\[A-Za-z]{5}.vbs.dat"
        $vbs_file_2 = "%APPDATA%\\[A-Za-z]{5}.vbs"
        $vbs_file_3 = "%APPDATA%\\[A-Za-z]{5}.mds"

        // VBShower C2 servers
        $vbshower_c2_1 = "176.31.59.232"
        $vbshower_c2_2 = "144.217.174.57"

    condition:
        // Совпадение хотя бы одного индикатора из каждой группы
        ($file_1 or $file_2 or $file_3 or $file_4 or $file_5 or $file_6) and
        ($domain_1 or $domain_2 or $domain_3 or $domain_4 or $domain_5 or $domain_6) and
        ($ip_1 or $ip_2 or $ip_3 or $ip_4 or $ip_5) and
        ($ua_1 or $ua_2) and
        ($legit_service_1 or $legit_service_2 or $legit_service_3 or $legit_service_4) and
        ($email_1 or $email_2 or $email_3 or $email_4 or $email_5) and
        ($vbshower_registry_key or $vbshower_registry_value) and
        ($vbs_file_1 or $vbs_file_2 or $vbs_file_3) and
        ($vbshower_c2_1 or $vbshower_c2_2)
}