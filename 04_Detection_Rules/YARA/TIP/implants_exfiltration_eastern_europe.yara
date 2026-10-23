rule malware_air_gap_worm_2023_fourth_stage
{
meta:
    hash = "3A532B8481F22B78ABC718AC5CDB3F06"
    hash = "4D5963B7D931A02265EA5231961935E9"
    author = "Kaspersky ICS CERT"
    copyright = "Kaspersky"
    description = "Rule to detect a worm used for exfiltration of air-gapped networks"
    version = "1.0"
    last_modified = "2023-03-27"

strings:
    $a1 = "VolumeName : %ws"
    $a2 = "FileSystem : %ws"
    $a3 = "SerialNumber : %u"
    $a4 = "ComponentLength : %u"
    $a5 = "FileSystemFlag : %u"
    $a6 = "%ws\\log.db"
    $a7 = "info.db"	
	
    $b1 = "[Back]"
    $b2 = "[Tab]"
    $b3 = "[Ctrl]"
    $b4 = "[Alt]"
    $b5 = "[Esc]"
    $b6 = "[Del]"
    $b7 = "Title:[%s]"
	
    $c1 = "err.db"
    $c2 = "[Time:%02d-%02d %02d:%02d] : %ws"
    $c3 = "$RECYCLE.BIN" wide
    $c4 = "S-1-5-21-963258" wide  
    $c5 = "c:\\windows\\tasks\\" wide
    $c6 = "\\*.*" wide
    $c7 = ".rar" wide
    $c8 = ".pdf" wide
    $c9 = ".dir" wide
    $c10 = ".docx" wide
    $c11 = ".lnk" wide
    $c12 = "url.dll,FileProtocolHandler"
	
condition:
    (all of ($a*) and (any of ($b*) or any of ($c*)))
}

rule malware_air_gap_worm_2023_first_stage
{
meta:
    hash = "3E22E7F5A6EE0A7D3D9A5CBFA7939C98"
    hash = "9F402F0B2C84ED577E9EE76DCF640B70"
    author = "Kaspersky ICS CERT"
    copyright = "Kaspersky"
    description = "Rule to detect a worm used for exfiltration of air-gapped networks"
    version = "1.0"
    last_modified = "2023-03-27"

strings:
    $a1 = "S-1-5-21-963258"
    $a2 = "\\$RECYCLE.BIN\\"
    $a3 = "del %tmp%\\*.exe"
    $a4 = "dir f:\\ >>"
    $a5 = "dir e:\\ >>"
    $a6 = "dir c:\\ >>"
    $a7 = "dir d:\\ >>"
    $a8 = "netstat -ano -p tcp >>"
    $a9 = "ipconfig /all >>"
    $a10 = "net group /do >>"
    $a11 = "net group administrators /do >>"
    $a12 = "net localgroup administrators >>"
	
condition:
    uint16(0) == 0x5a4d and all of ($a*)
}
