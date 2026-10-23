import "pe"

rule apt_PryingKomodo_shadowpad_iviewers_dll_variant
{
meta:
    description = "Rule for detecting Shadowpad iviewers.dll variant used during the PryingKomodo campaign"
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.1"
    last_modified = "2022-07-08"
    hash = "011BEAF3E9CD2896479313772CD591DE"
    hash = "A7F3BF89F0B41704F185545C784B8457"
    hash = "35912C914BD84F23203C8FADAC6D0548"
    hash = "299980C914250BAC7522DE849F6DF24F"

strings:
    $viewers = "VIEWER.dll" fullword
    $Iviewers = "IVIEWERS.dll"
    $oleview = "OLEViewer"
    $comapi = "viewer Copyright" wide
condition:
    uint16(0) == 0x5A4D and filesize < 2MB and pe.is_dll() and ($Iviewers or $comapi or $viewers) and
    (
    not for any i in (0 .. pe.number_of_signatures) : (pe.signatures[0].subject contains "O=Microsoft Corporation")
    and not $oleview
    )
}
rule apt_PryingKomodo_Webshell {
meta:
    description = "Rule for detecting backdoor webshell used during the PryingKomodo campaign"
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.0"
    last_modified = "2022-02-11"
    hash = "134609a4e2ff86e562a8b63d6350e5c8"
    hash = "3de85f25ba23e38b013443bc775484c7"
strings:
   $exec = {65 00 78 00 65 00 63 00 5F 00 63 00 6F 00 64 00 65}
   $JScriptEvaluate = "JScriptEvaluate"
   $JScriptImport = "JScriptImport"
   $JScriptPackage = "JScriptPackage"
   $CreateEngineWithType = "CreateEngineWithType"

condition:
   uint16(0) == 0x5A4D and filesize < 1MB and $exec and $JScriptEvaluate and $JScriptImport and $JScriptPackage and $CreateEngineWithType
}
