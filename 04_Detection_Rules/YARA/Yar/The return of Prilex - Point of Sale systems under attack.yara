rule  crimeware_BR_Prilex_POS {
meta:
        description = "Prilex POS malware"
        filetype = "Win32"
        author = "Kaspersky Lab"
        date = "2017-05-11"
        version = "1.0"
strings:
        $sitef = "clisitef" wide nocase
        $str1 = "tmrPing" ascii
        $str2 = "StopRegiao" wide
        $str3 = "SetConfig" wide
        $str4 = "ScanProcessStart" wide
        $str5 = "oldtmpsys.dat" wide
        $str6 = "tmrInject" ascii
        $str7 = "tmrUpdate" ascii
        $str8 = "lPosByteDeCrypt" wide
        $str9 = "sReceive Crypt" wide
condition:
        uint16(0) == 0x5A4D and
        $sitef and
        4 of ($str*) and
        filesize < 5000000
}
