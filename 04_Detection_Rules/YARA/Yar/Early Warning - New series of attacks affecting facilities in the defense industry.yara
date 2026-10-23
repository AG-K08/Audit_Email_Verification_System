import "pe"

rule Malware_UNK_DllLoader {
meta:
    author = "Kaspersky ICS CERT"
    filetype = "Win32 EXE"
    date = "2021-06-20"
    version = "1.1"

strings:
    $a1 = "Loader.dll" fullword
    $a2 = "ServiceMain" fullword
    $b1 = "{G657YS06-016D" xor

condition:
    (uint16(0) == 0x5A4D) and ((all of ($a*)) or (any of ($b*)) or
    ((pe.version_info["ProductName"] == "Microsoft? Windows? Operating System") and (pe.version_info["OriginalFilename"] == "Scms.dll")))
}   	
