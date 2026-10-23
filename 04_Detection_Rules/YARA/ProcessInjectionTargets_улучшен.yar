rule ProcessInjectionTargets : suspicious {
    meta:
        category    = "evasion"
        description = "Detects commonly targeted processes for injection on Windows"
        author      = "malcat"
        reliability = 40
        tlp         = "TLP:white"

    strings:
        $svchost       = "svchost.exe" ascii wide
        $vbc           = "vbc.exe" ascii wide fullword
        $explorer      = "explorer.exe" ascii wide fullword
        $wmihost       = "wmihost.exe" ascii wide fullword
        $iexplore      = "iexplore.exe" ascii wide fullword
        $regsvr32      = "regsvr32.exe" ascii wide fullword
        $rundll32      = "rundll32.exe" ascii wide fullword
        $regasm        = "Regasm" ascii wide fullword
        $powershell    = "powershell.exe" ascii wide fullword
        $taskeng       = "taskeng.exe" ascii wide fullword
        $dllhost       = "dllhost.exe" ascii wide fullword
        $winlogon      = "winlogon.exe" ascii wide fullword
        $notepad       = "notepad.exe" ascii wide fullword
        $cmd           = "cmd.exe" ascii wide fullword
        $services      = "services.exe" ascii wide fullword
        $lsass         = "lsass.exe" ascii wide fullword
        $conhost       = "conhost.exe" ascii wide fullword
        $mmc           = "mmc.exe" ascii wide fullword
        $msiexec       = "msiexec.exe" ascii wide fullword
        $wscript       = "wscript.exe" ascii wide fullword
        $cscript       = "cscript.exe" ascii wide fullword
        $dwm           = "dwm.exe" ascii wide fullword
        $taskmgr       = "taskmgr.exe" ascii wide fullword
        $mspmsnsv      = "mspmsnsv.exe" ascii wide fullword
        $rtvscan       = "rtvscan.exe" ascii wide fullword
        $nmap          = "nmap.exe" ascii wide fullword
        $firefox       = "firefox.exe" ascii wide fullword
        $chrome        = "chrome.exe" ascii wide fullword

    condition:
        4 of ($svchost, $vbc, $explorer, $wmihost, $iexplore, $regsvr32, $rundll32, $regasm, $powershell, $taskeng, $dllhost, $winlogon, $notepad, $cmd, $services, $lsass, $conhost, $mmc, $msiexec, $wscript, $cscript, $dwm, $taskmgr, $mspmsnsv, $rtvscan, $nmap, $firefox, $chrome)
}
