rule cw_CUEMiner {
meta:
        description = "Rule to detect CUEMiner Cryptojacking Bot"
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2023-01-12"
        hash = "64c546d7eb1a4298d5a4bae04a749844"
        hash = "3881bd29a8075f5b164cfcfef2362a85"

strings:
        $HWCheck1 = {1C 8D 31 00 00 01 25 16 72 09 04 00 70 A2 25 17  72 1B 04 00 70 A2 25 18 72 31 04 00 70 A2 25 19 72 47 04 00 70 A2 25 1A 72 59 04 00 70 A2 25 1B 72 71 04 00 70 A2 13 05}
        $HWCheck2 = {00 11 15 72 03 05 00 70 6F 45 00 00 0A 28 46 00 00 0A 12 16 28 47 00 00 0A 13 17}
        $HWCheck3 = {72 75 03 00 70 73 3B 00 00 0A 0D}

condition:
        uint16(0) == 0x5A4D and
        all of ($HW*)
}

rule cw_CUEMiner_Packed {
meta:
        description = "Rule to detect packed CUEMiner Cryptojacking Bot"
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2023-01-12"
        hash = "ddd629995106be2266b038e7faf5fd01"
        hash = "4b926c9b5d3d4b3538e6df82c76735b0"
        hash = "d5fed1a4738753a0c0b4fd7a259c262b"
        hash = "d24c9a36751a462e203bf6c17b9948ae"
        hash = "b0e8a2cc2dbcf64d86324bca98e72cfe"
        hash = "55c37445d312c77f534f4797f1034248"

strings:
        $CUEdotNET = "NETFramework" ascii wide 

        $CUETask1 = "Task32Main" ascii wide
        $CUETask2 = "Task32Watch" ascii wide
        $CUETask3 = "Task24Main" ascii wide
        $CUETask4 = "Task24Watch" ascii wide
        $CUETask5 = "Task29Main" ascii wide
        $CUETask6 = "Task29Watch" ascii wide
        $CUETask7 = "Task31" ascii wide
        $CUETask8 = "Task34" ascii wide
     
        $CUEpacked1 = "CheckSystemHardware" ascii wide
        $CUEpacked2 = "ProcessHacker" ascii wide
        $CUEpacked3 = "Cyberpunk2077" ascii wide
        $CUEpacked4 = "Clipboard" ascii wide
        $CUEpacked5 = "DLL Host Service" ascii wide
        $CUEpacked6 = "RegSvcs.exe" ascii wide
        $CUEpacked7 = "WinRing0x64.sys" ascii wide
        $CUEpacked8 = "winlogson" ascii wide
        $CUEpacked9 = "SecureFiles" ascii wide
        $CUEpacked10 = "Programs Engine" ascii wide
        $CUEpacked11 = "AbortPro" ascii wide
        $CUEpacked12 = "ASUSTeK Computer Inc" ascii wide

        $CUEpacker1 = "Dendalion" ascii wide
        $CUEpacker2 = "Crypter" ascii wide
        $CUEpacker3 = "DAF" ascii wide
        $CUEpacker4 = "LDR" ascii wide
        $CUEpacker5 = "Sadax" ascii wide
        $CUEpacker6 = "Bestiary" ascii wide
        $CUEpacker7 = "Benedict" ascii wide
        $CUEpacker8 = "Galileo" ascii wide
        $CUEpacker9 = "Fregat" ascii wide
        $CUEpacker10 = "APU|COMPUTE CORES" ascii wide
        $CUEpacker11 = "Confuser.Core" ascii wide 

condition:
        uint16(0) == 0x5A4D and
        filesize > 12KB and filesize < 1MB and
        (
                $CUEdotNET and any of ($CUETask*) and 2 of ($CUEpacked*) and any of ($CUEpacker*)
        )
}

rule cw_CUEMiner_downloader {
meta:
  description = "Rule to detect CUEMiner Downloader"
  author = "Kaspersky"
  copyright = "Kaspersky"
  distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
  version = "1.0"
  last_modified = "2022-09-14"

strings:
    $obfuscate = { 89 45 F0 8B 45 F0 8B 4D 0C 39 C8 0F 8D 44 00 00 00 E9 09 00 00 00 8B 45 F0 40 89 45 F0 EB E4 8B 45 F0 8B 4D F4 01 C1 8B 45 F0 8B 55 08 01 C2 8B 45 F0 89 4D EC 8B 4D F8 89 55 E8 99 F7 F9 8B 45 FC 01 D0 8B 4D E8 0F BE 09 0F BE 10 31 D1 8B 45 EC 88 08 EB C1 8B 45 F4 C9 C3 55 89 E5 81 EC 54 00 00 00 90 B8 44 00 00 00 50 B8 }

condition:
  uint16(0) == 0x5A4D and
    filesize < 12MB and
    filesize > 2KB and
    $obfuscate
}
