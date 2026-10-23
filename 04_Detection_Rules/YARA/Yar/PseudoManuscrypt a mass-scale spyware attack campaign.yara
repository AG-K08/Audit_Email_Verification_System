rule Malware_CN_DllLoader {
meta:
    author = "Kaspersky ICS CERT"
    filetype = "Win32 EXE"
    date = "2021-08-25"
    version = "1.1"
strings:
    $a1 = "Loader.dll" fullword
    $a2 = "ServiceMain" fullword
    $b1 = "{G657YS06-016D" xor
    $b2 = "_kasssperskdy"
condition:
    (uint16(0) == 0x5A4D) and ((all of ($a*)) or (any of ($b*)))
}
