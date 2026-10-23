import "pe"

rule APT_PinkLama_VMprotect_ChromeSetup_Dropper
{
meta:
description = "Rule for detecting PinkLama APT VMprotect ChromeSetup Dropper malware file"
author = "Kaspersky"
copyright = "Kaspersky"
distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
version = "1.0"
last_modified = "2023-03-21"
hash = "528CB89DA2B9847627D17575AE3C70DA"

strings:
$a1 = "GetUserObjectInformationW" fullword
$a2 = "GetProcessAffinityMask" fullword
$a3 = "SHGetSpecialFolderLocation" fullword
$b1 = "Adobe Download Manager" wide
$b2 = "Google Chrome Install Tools" wide
condition:
uint16(0) == 0x5A4D and filesize < 6MB and (all of ($a*)) and (1 of ($b*)) and (not for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Google"
         ) or not for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Adobe"
         )) and pe.number_of_sections > 7
         
}

rule APT_PinkLama_Goopdate_Launcher

{
meta:
description = "Rule for detecting PinkLama APT Goopdate.dll Launcher"
author = "Kaspersky"
copyright = "Kaspersky"
distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
version = "1.0"
last_modified = "2023-03-21"
hash = "7f13049c038614c0361d85743530161e"

strings:
$string1 = "goopdate.dll" fullword
$string2 = "WriteFile" fullword
$string3 = "SHGetPathFromIDListA" fullword
condition:
uint16(0) == 0x5A4D and filesize < 3MB and all of them and not for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Google"
         )
}

rule APT_PinkLama_ChromeSetup_Backdoor
{
meta:
description = "Rule for detecting PinkLama APT Backdoor malware file"
author = "Kaspersky"
copyright = "Kaspersky"
distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
version = "1.0"
last_modified = "2023-03-21"
hash = "7BEDA5022018F829245CCC1FA7877257"

strings:
$string1 = "TCP_Clinet_Test" fullword
$string2 = "request_cmd_command" fullword
$string3 = "request_powershell_command" fullword
$string4 = "request_uploadfile_command" fullword
$string5 = "request_downloadfile_command" fullword
condition:
uint16(0) == 0x5A4D and filesize < 3MB and all of them
}

rule unknown_dotNET_ToolKit_Dropper
{
meta:
description = "Rule for detecting .NET ToolKit Dropper malware file"
author = "Kaspersky"
copyright = "Kaspersky"
distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
version = "1.0"
last_modified = "2023-03-21"
hash = "FFF21684DF37FA7203EBE3116E5301C1"

strings:
$string1 = "Copyright 2023 Google LLC" fullword
$string2 = "ToolKit.exe" fullword
$string3 = "_CorExeMain" fullword
$string4 = "mscoree.dll" fullword
condition:
uint16(0) == 0x5A4D and filesize < 3MB and all of them and not for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].subject contains "Google"
         )
}


rule unknown_dotNET_ChromeTools_Backdoor
{
meta:
description = "Rule for detecting .NET ChromeTools Backdoor malware file"
author = "Kaspersky"
copyright = "Kaspersky"
distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
version = "1.0"
last_modified = "2023-03-21"
hash = "1341E507F31FB247C07BEEB14F583F4F"

strings:
$string1 = "&task_id" wide
$string2 = "&bid=" wide
$string3 = "task_type" wide
$string4 = "task_data" wide
$string5 = "act=ret" wide
condition:
uint16(0) == 0x5A4D and filesize < 3MB and all of them
}