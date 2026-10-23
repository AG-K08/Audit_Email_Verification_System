import "pe"

rule apt_cn_TA428_cTrojan
{
meta:
    hash = "6dfc3bdd2b70670bf29506e5828f627e"
    hash = "bb504dad120d665fa3dd48b000806e33"
    hash = "dc744cbaf088b0918457aa47b0594f13"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect cTrojan"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "CreateProcessAsUser wrong."
    $a2 = "open file error:" ascii wide
    $a3 = "read file error:" ascii wide
    $a4 = "CONNECT %s:%d HTTP/1.1"
    $a5 = "%s|#|%s|#|%s|#|%s|#|*|#|%s|#|%s"
    $a7 = "|File Folder|n|" ascii wide
    $a8 = "taskkill /f /pid %d" ascii wide
    $a9 = "rd /s/q \"%s\\*\""  ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 2000000 and 5 of them
}

rule apt_cn_IronHusky_cTrojan
{
meta:
    hash = "5654acf2c8a734b42b27606495f958019f3429ec05fd32864e543d725623f11d"
    hash = "3f641ebdce1f87e0906b732c43d047b1d357db433ae0a1cfed7c72cb20f0ba00"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect IronHusky CTrojan"
    version = "1.1"
    last_modified = "2022-04-07"

strings:
    $a1 = "Process open failed" 
    $a2 = "hProcessSnapshot == INVALID_HANDLE_VALUE"  
    $a3 = "CONNECT %s:%d HTTP/1.1" fullword ascii 
    $a4 = "Process kill failed"
    $a5 = "%02X%02X%02X%02X%02X%02X"
    $a6 = "cTrojan"
    $a7 = "None|#|"

condition:
    ((uint16(0) == 0x8b55 or uint16(0) == 0x5a4d) and filesize < 400KB and 5 of them)
}

rule apt_cn_IronHusky_PivyLoaders 
{
meta:
    hash = "4c22eb33aa1d10511eaf8d13098e2687e44eaebc5af8112473e28acedac34bea"
    hash = "640bc06fcce5fb33f19656a24de864c52cd7a00648f529f7f397352c019a29aa"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect IronHusky Poison loaders"
    version = "1.1"
    last_modified = "2022-04-07"

strings:
    $a1 = "Process kill failed." fullword ascii 
    $a2 = "Process open failed." fullword ascii 
    $a3 = "hProcessSnapshot == INVALID_HANDLE_VALUE" fullword ascii
    $a4 = "Delete Failed." fullword ascii 
    $a5 = "</supportedOS><supportedOS Id=\"{e2" ascii 
    $a6 = "1Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings" fullword wide 
    $a7 = "Aadvapi32" fullword wide 
    $a8 = "Windows 10 Update 1" fullword ascii 
    $a9 = "None|#|" fullword ascii 
    $a10 = "ion></compatibility></assembly>" fullword ascii
    
    $op0 = { 83 3d 20 34 42 00 00 0f 85 c0 10 00 00 8d 0d 80 }
    $op1 = { e8 78 ff ff ff 33 c0 eb 79 33 c0 39 45 0c 0f 9d }
    $op2 = { e8 db 50 ff ff be ff ff ff 7f eb 68 be ff ff ff }
    $op3 = { 39 5d e4 75 08 53 57 ff 15 34 20 40 00 39 1d 10 }
    $op4 = { f7 f9 80 c2 30 eb 1c ff d7 99 b9 1a }
    $op5 = { 8d 64 24 00 8a 88 18 31 40 00 80 f1 3c 88 88 d8 }
    
    $op6 = { e8 f6 ef ff ff 59 59 8b 75 08 8d 34 f5 10 a2 40 }
    $op7 = { e8 ce d3 ff ff ff b6 e0 }
    $op8 = { e8 29 d4 ff ff ff b6 c0 }

condition:
    (uint16(0) == 0x5a4d and filesize < 400KB and
    (6 of ($a*)) or (3 of ($op*))) or
    (all of them)
}

rule apt_CN_TA428_APosT
{
meta:
    hash  = "4ad1ad14044bd2c5a5c5e7e7dd954b23"
    hash  = "3953eb8f7825e756515be79ef45655b0"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect Trojan.Win32.APosT"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "SHFileOperationW"
    $a2 = "CloseWindowStation" 
    $a3 = "Software\\VS" ascii wide
    $a4 = "explorer.exe" ascii wide
    $a5 = "HTTP/1.0 200"
    $a6 = "%s;%s;%s;%s;%s;%I64d" ascii wide
    $a7 = "www.microsoft.com" 
    $a8 = "%s;%s;%s;%d;%d|"  ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and all of them
}

rule apt_CN_TA428_nccTrojan_dll
{
meta:
    hash = "180ee3e469bfcfc079e1a46d16440467"
    hash = "7101fe9e82e9b0e727b64608c9fd5df1"
    hash = "413fa4ad3afe00b34102c520a91f031c"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect nccTrojan dll"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "Client.dll"
    $a2 = "CloseWindowStation" 
    $a3 = "%s;%s;%I64d;%I64d;%s;%I64d" ascii wide
    $a4 = "%s;%s;%s;%d;%d|"  ascii wide
    $a5 = "cmd.exe" ascii wide
    $a6 = "VZLOG-" ascii wide
    $a7 = "Software\\CLASSES\\SS" ascii wide 
    $a8 = "ZFrameHelperSrv"  ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and all of them
}

rule apt_CN_TA428_nccTrojan_launcher
{
meta:
    hash = "180ee3e469bfcfc079e1a46d16440467"
    hash = "6b0f91a1a438788b2d80f3449882300e"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect nccTrojan launcher"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "ZFrameHelperSrv"
    $a2 = "ZFrameHelperSrv" ascii wide
    $b1 = "software" nocase
    $b2 = "microsoft" nocase
    $c1 = "Svchost" nocase
    $c2 = "svchost" ascii wide
    $d1 = "Client.dll"	
    $d2 = "Client.dll" ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and
    (any of ($a*)) and (all of ($b*)) and (any of ($c*)) and (any of ($d*))    
}

rule apt_CN_TA428_CotX
{
meta:
    hash = "6038583b155f73faf1b5ef8135154278"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect CotX"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "%s;%s;%s;%d;%s"
    $a2 = "reg delete \"HKEY_CURRENT_USER\\Environment\" /v UserInitMprLogonScript /f" 
    $a3 = "\\cmd.exe" ascii wide
    $a4 = "DRIVE_REMOVABLE" ascii wide
    $a5 = "%s;%s;%s;%.2f GB;%.2f GB|"
    $a6 = "del /f /s /q %s" ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and all of them
}

rule apt_CN_TA428_CotX_2
{
meta:
    hash = "da765e4e6b0d2544fe3f71e384812c40"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect CotX"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "log10"
    $a2 = "RtlDecompressBuffer" 
    $a3 = "\\system32\\powerc"
    $a4 = "GetThreadContext"
    $a5 = "ntdll.dll" ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and (all of them) and (pe.number_of_resources > 1)
    and (pe.resources[0].type_string == "D\x00A\x00T\x00") and (pe.resources[0].id == 101)
}

rule apt_CN_TA428_APosT_2
{
meta:
    hash = "7c383c9ca29f78fcc815eaea9373b4bb"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect Trojan.Win32.APosT"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "log10"
    $a2 = "RtlDecompressBuffer" 
    $a3 = "DAT"
    $a4 = "ntdll.dll" ascii wide
    $a5 = "UserInitMprLogon"
    $a6 = "COMSPEC" ascii wide

condition:
    uint16(0) == 0x5A4D and filesize < 400000 and (all of them) and (pe.number_of_resources > 1) 
    and (pe.resources[0].type_string == "D\x00A\x00T\x00") and (pe.resources[0].id == 101)
}

rule apt_CN_TA428_Injector
{
meta:
    hash = "10818f47aa4dc2b39a7b5eef652f3c68"
    hash = "40EB08F151859C1FE4DC8E6BC466B06F"
    hash = "AB26F4C877A7357CABF95FB5033A5BEF"
    hash = "C6D6CFFD56638A68A0DE11035B9C9097"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 injector"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "file.tmp" fullword ascii
    $a2 = "files.tmp" fullword ascii
    $a3 = "type.tmp" fullword wide
    $b1 = "Send.exe" fullword ascii
    $b2 = "c:\\windows\\system32\\mspaint.exe" fullword wide
    $b3 = "conhost.exe" fullword ascii
    $b4 = "7za.exe" fullword wide
    $c1 = "VWuBh" fullword ascii
    $c2 = "^Vh"ascii
    $c3 = "[Sh" ascii

condition:
    uint16(0) == 0x5a4d and filesize < 70KB and
    (any of ($a*)) and (any of ($b*)) and (all of ($c*))
}

rule apt_CN_TA428_Injector_2
{
meta:
    hash = "E8800D59C411A948EE966FF745FBD5C9"
    hash = "EBCFFECE1B1AF517743D3DFFDE72CB43"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 injector"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "Send.EXE" fullword wide
    $a2 = "c:\\windows\\system32\\xcopy.exe" fullword wide
    $a3 = "file.tmp" fullword ascii
    $b1 = "%2\\CLSID" fullword ascii 
    $b2 = "%2\\Insertable" fullword ascii 
    $b3 = "%2\\protocol\\StdFileEditing\\verb\\0" fullword ascii 
    $b4 = "&Edit" fullword ascii
    $b5 = "%2\\protocol\\StdFileEditing\\server" fullword ascii 
    $b6 = "Send Microsoft " fullword wide
    $b7 = "%2\\DocObject" fullword ascii 

condition:
    uint16(0) == 0x5a4d and filesize < 600KB and 2 of ($a*) and (all of ($b*))
}

rule apt_CN_TA428_nccTrojan_2
{
meta:
    hash = "1157132504be3bf556a80db8a2ff9395"
    hash = "51367dc409a7a7e5521c2f700c56a452"
    author = "Kaspersky"
    copyright = "Kaspersky"
    version = "1.0"
    last_modified = "2022-04-04"
    description = "Rule to detect TA428 nccTrojan"

strings:
    $a1 = "C:\\Users\\abc\\Desktop\\ncc-4.0\\x64\\Release\\icmp.pdb" fullword ascii
    $a2 = "%ws\\cmd.exe" fullword wide
    $a3 = "taskkill /f /pid %d" fullword wide
    $a4 = " /k chcp 65001 & ver" fullword wide  
    $a5 = "%s;%s;%s;%s;*;%s;%s;%s;%s|%s|%s" fullword ascii
    $a6 = "ServiceMain" fullword ascii
    $a7 = "password" fullword ascii

condition:
    uint16(0) == 0x5a4d and filesize < 300KB and pe.DLL and (pe.exports("ServiceMain")) and (4 of them)      
}

rule apt_CN_TA428_Dllhijacker
{
meta:
    hash = "11BA5665EC1DBA660401AFDE64C2B125"
    hash = "51BEFD74AC3B8943DA58C841017A57A8"
    hash = "84DF335EBC10633DA1524C7DBB836994"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 Dllhijacker"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "c:\\windows\\system32\\svchost.exe" fullword ascii
    $a2 = "MSCOREE.dll" fullword ascii
    $a3 = "applaunch.log" fullword ascii      

condition:
    uint16(0) == 0x5a4d and filesize < 300KB and pe.DLL and (pe.exports("IEE2")) 
    and (pe.exports("GetRequestedRuntimeInfo2")) and (pe.exports("LoadLibraryShim2")) and (all of them)   
}

rule apt_CN_TA428_Hollowing
{
meta:
    hash = "87AA0BEDF293E9B16A93E4411353F367"
    hash = "AA7231904A125273F5E5EE55A1441BA4"
    hash = "E8A16193BCD477D8231E6FC1A484DC8A"
    hash = "5EA338D71D2A49E7B3259BC52F424303"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 process hollowing"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "SKEYE\\Release\\HOLLOWING.pdb" fullword ascii
    $a2 = ".exe"  wide                     
    $a3 = ".cfg"  wide 
    $a4 = "ReadProcessMemory" fullword ascii                             

condition:
    uint16(0) == 0x5a4d and filesize < 150KB and pe.DLL and (all of them)  
}

rule apt_CN_TA428_Hollowing_2
{
meta:
    hash = "11955356232DCF6834515BF111BB5138"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 process hollowing"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "c:\\windows\\system32\\dllhost.exe" fullword ascii
    $a2 = "Creating target process failed!" fullword ascii
    $a3 = "%SystemRoot%\\system32\\calc.exe" fullword ascii
    $a4 = "avpinit.dll" fullword ascii
    $a5 = "?[ERROR] CreateProcess failed, Error = %x" fullword ascii
    $a6 = "\\mcsync.log" fullword ascii
    $a7 = "Incompatibile payload architecture!" fullword ascii
    $a8 = "Failed getting remote PEB address!" fullword ascii
    $a9 = "Only 32 bit payloads can be injected from 32bit loader!" fullword ascii
    $a10 = "Invalid payload: " fullword ascii
    $a11 = "[-] Not supported relocations format at %d: %d" fullword ascii
    $a12 = "[-] VirtualAddress of section is out ouf bounds: " fullword ascii
    $a13 = "Could not allocate memory in the remote process" fullword ascii
    $a14 = "Could not allocate memory in the current process" fullword ascii
    $a15 = "[-] Raw section size is out ouf bounds: " fullword ascii
    $a16 = "[-] Malformed field: %lx" fullword ascii
    $a17 = "[-] Section " fullword ascii
    $a18 = "Loading failed!" fullword ascii
    $a19 = ":$:,:D:L:\\:p:|:" fullword ascii
    $a20 = "[-] Invalid address of relocations" fullword ascii

condition:
    uint16(0) == 0x5a4d and filesize < 700KB and (10 of them)
}

rule apt_CN_TA428_nccTrojan_3
{
meta:
    hash = "17FA7898D040FA647AFA4467921A66CF"
    hash = "1EA58FF469F5EE0FDCF5B30FC19E4CB8"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect TA428 nccTrojan"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "%SystemRoot%\\System32\\svchost.exe -k " fullword ascii
    $a2 = "C:\\Users\\abc\\Desktop" ascii	
    $a3 = "\\x64\\Release\\Install.pdb" ascii
    $a4 = ".dll" 
    $a5 = "\\Parameters" fullword ascii
    $a6 = "SYSTEM\\CurrentControlSet\\Services" 
    $a7 = "api-ms-win-appmodel-runtime-l1-1" wide

condition:
    uint16(0) == 0x5a4d and filesize < 300KB and (all of them)
}

rule apt_CN_TA428_vbs
{
meta:
    hash = "216D9F82BA2B9289E68F9778E1E40AC9"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detects TA428 wmi console written on VBS"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "strNetUse = \"cmd.exe /c net use \\\\\" & host & \" \"\"\" & pass & \"\"\" \" & \"/user:\" & user" fullword ascii
    $a2 = "strExec = \"cmd.exe /c \" & cmd & \" > \" & file & \" 2>&1\"  '2>&1 err" fullword ascii
    $a3 = "vbNewLine & vbTab & \"wmiexec.vbs  /cmd  host  user  pass  command\" & vbNewLine & _" fullword ascii
    $a4 = "strNetUse = \"cmd.exe /c net use \\\\\" & host & \" /del\"" fullword ascii
    $a5 = "vbNewLine & vbTab & \"wmiexec.vbs  /cmd  host  command\" & _" fullword ascii
    $a6 = "vbNewLine & vbTab & \"wmiexec.vbs  /shell  host  user  pass\" & _" fullword ascii
    $a7 = "WScript.Echo \"WMIEXEC : Target -> \" & host" fullword ascii
    $a8 = "vbTab & \"wmiexec.vbs  /shell  host\" & _" fullword ascii
    $a9 = "vbNewLine & vbTab & \"  command\" & vbTab & \"the command to execute on remote host\" & _" fullword ascii
    $a10 = "WScript.Echo \"WMIEXEC : Login -> OK\"" fullword ascii
    $a11 = "WScript.Echo \"WMIEXEC ERROR: Process could not be created.\" & _" fullword ascii
    $a12 = "Set Matches = regEx.Execute(cmd)" fullword ascii
    $a13 = "'process 'cd' command-------->>>>" fullword ascii
    $a14 = "WScript.Echo vbNewLine & vbTab & host & \"  >>  \" & command" fullword ascii
    $a15 = "        vbNewLine & \"WMIEXEC ERROR: Command -> \" & cmd & _" fullword ascii
    $a16 = "If boolShellMode = False Then command = objArgs.Item(intArgCount - 1)" fullword ascii
    $a17 = "WScript.Echo \"WMIEXEC ERROR: Insufficient Privilege!\"" fullword ascii
    $a18 = " vbTab & vbTab &\"eg. 'systeminfo -wait5000' 'ping google.com -wait2000'\" & _" fullword ascii
    $a19 = "Exec command,\"nul\"" fullword ascii
    $a20 = "WScript.Echo \" Usage:\" & _" fullword ascii

condition:
    uint16(0) == 0x6e4f and filesize < 30KB and (10 of them)
}

rule apt_CN_TA428_fileio
{
meta:
    hash = "4D42C314FF4341F2D1315D7810BD4E15"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detects TA428 file IO tool"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "C:\\Users\\abc\\Desktop\\" ascii
    $a2 = "FileIO\\Release\\FileIO.pdb" ascii
    $a3 = "file.io" wide ascii
    $a4 = {74 2D 44 69}
    $a5 = {73 70 6F 73}
    $a6 = "%s, GetStatusCode error" fullword ascii
    $a7 = "%s, WinHttpAddRequestHeaders error" fullword ascii
    $a8 = "%s, WinHttpReadData error" fullword ascii
    $a9 = "%s, WinHttpSetOption" fullword ascii
    $a10 = "%s, WinHttpWriteData2 error" fullword ascii
    $a11 = "log file path is %s" fullword ascii              

condition:
    uint16(0) == 0x5a4d and filesize < 500KB and (8 of them)
}

rule apt_CN_TA428_PortDoor
{
meta:
    hash = "70DA6872B6B2DA9DDC94D14B02302917"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect PortDoor backdoor"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "%s:%s:%d.%d.%d:%rundll32.exe %s,H" fullword ascii
    $a2 = "liburl.dll" fullword ascii
    $a3 = "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.102 Safari/537.36 " ascii
    $a4 = "HOST: %s" fullword ascii
    $a5 = "cmd.exe" wide ascii
    $a6 = "explorer.exe" wide ascii       

condition:
    uint16(0) == 0x5a4d and filesize < 400KB and (pe.characteristics & pe.DLL) and (all of them)
}

rule apt_CN_TA428_scanner_ladon
{
meta:
    hash = "AB55A08ED77736CE6D26874187169BC9"
    author = "Kaspersky"
    copyright = "Kaspersky"
    description = "Rule to detect Ladon network scanner"
    version = "1.0"
    last_modified = "2022-04-04"

strings:
    $a1 = "C:\\Windows\\System32\\cmd.exe" fullword wide
    $a2 = "Error: Not Found Ladon.ini or DllMoudle or scan.exe" fullword wide
    $a3 = "vcscan.dll" fullword wide
    $a4 = "descan.dll" fullword wide
    $a5 = "netscan.dll" fullword wide
    $a6 = "host.txt" wide
    $a7 = "VncSharp.dll" fullword wide
    $a8 = "MySql.Data.dll" fullword wide
    $a9 = "DDTek.Oracle.dll" fullword wide
    $a10 = "Renci.SshNet.dll" fullword wide
    $a11 = "netscan.exe" fullword wide
    $a12 = "scan.exe" fullword wide
    $a13 = "Ladon.exe" fullword wide
    $a14 = "Example: Ladon 192.168.1.8/24 *.dll(c#)" fullword wide
    $a15 = "File Not Found SharpCifs.dll" fullword wide
    $a16 = "File Not Found VncSharp.dll" fullword wide
    $a17 = "File Not Found MySql.Data.dll" fullword wide
    $a18 = "File Not Found DDTek.Oracle.dll" fullword wide
    $a19 = "File Not Found Renci.SshNet.dll" fullword wide
    $a20 = "netscan.dll > netscan.exe > psscan.ps1 > vcscan.dll > descan.dll > Ladon.ini" fullword wide

condition:
    uint16(0) == 0x5a4d and filesize < 1000KB and (8 of them)
}
