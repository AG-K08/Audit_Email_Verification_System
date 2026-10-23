rule FingerprintHardware : odd {
    meta:
        category = "fingerprint"
        description = "tries to enumerate installed hardware"
        author = "malcat"
        reliability = 50

    strings:
        $wmi1 = "root\\CIMV2" ascii wide fullword nocase
        $wmi2 = "ROOT\\SecurityCenter2" ascii wide fullword nocase
        $wmi3 = "SELECT * FROM Win32_Processor" ascii wide nocase
        $wmi4 = "SELECT * FROM Win32_VideoController" ascii wide nocase
        $wmi5 = "SELECT * FROM Win32_NetworkAdapter" ascii wide nocase
        $wmi6 = "SELECT * FROM Win32_process" ascii wide nocase
        $wmi7 = "SELECT * FROM FirewallProduct" ascii wide nocase
        $wmi8 = "SELECT * FROM AntiVirusProduct" ascii wide nocase
        $pci = "ControlSet001\\ENUM\\PCI" ascii wide fullword nocase
        $mssmbios = "ControlSet001\\SERVICES\\MSSMBIOS\\DATA" ascii wide fullword nocase
        $disk = "ControlSet001\\SERVICES\\DISK\\ENUM" ascii wide fullword nocase
        $cpu = "System\\CentralProcessor\\0" ascii wide fullword nocase
        $ide = "SYSTEM\\ControlSet001\\Enum\\IDE" ascii wide fullword nocase
        $ipconfig = /ipconfig .{0,25}\/all/ ascii wide fullword nocase
        $systeminfo = "systeminfo" ascii wide fullword nocase
        $processorid = "processorid" ascii wide fullword nocase
        $volume = "GetVolumeInformation" ascii wide
        $wnet = "WNetGetConnectionA" ascii fullword
        $wnetw = "WNetGetConnectionW" ascii fullword
        $drives = "GetLogicalDrives" ascii fullword
        $procname = "ProcessorNameString" ascii wide fullword
        $memory = "get_TotalPhysicalMemory" ascii fullword
        $monitor = "EnumDisplayMonitors" ascii wide
        $machineid = "github.com/denisbrodbeck/machineid.machineID" ascii fullword
        $hardware = "HARDWARE\\Description\\System" ascii fullword nocase
        $displayconfig = /(SELECT|select|Select) .{1,64} (FROM|from|From) +Win32_DisplayConfiguration/ ascii wide fullword
        $computersystem = /(SELECT|select|Select) .{1,64} (FROM|from|From) +Win32_ComputerSystem/ ascii wide fullword
        $bios = /(SELECT|select|Select) .{1,64} (FROM|from|From) +Win32_Bios/ ascii wide fullword
        $videocontroller = /(SELECT|select|Select) .{1,64} (FROM|from|From) +Win32_VideoController/ ascii wide fullword
        $processor = /(SELECT|select|Select) .{1,64} (FROM|from|From) +Win32_Processor/ ascii wide fullword
        $memorysize = "SELECT TotalVisibleMemorySize FROM Win32_OperatingSystem" ascii wide fullword

    condition:
        2 of them or any of ($wmi*)
}
