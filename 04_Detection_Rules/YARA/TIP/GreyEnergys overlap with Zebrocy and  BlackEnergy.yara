import "pe"

rule APT_RU_GreyEnergy_mini_32: BlackEnergy
{
meta:

    report        = "GreyEnergy’s overlap with Zebrocy and BlackEnergy"
    description   = "Rule to detect GreyEnergy mini backdoor 32-bit"
    hash          = "5f58059d894e8aaf58b2da6be6f97aa8"
    hash          = "c9bf1c6bdcfacc273cb531e5eb6e59ef"
    hash          = "2bae641c403286277e3ce89d02d6ede6"
    author        = "Kaspersky Lab"
    copyright     = "Kaspersky Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2018-11-16"
    last_modified = "-"

strings:

    $a1 = {C7 45 ?? 4C 6F 61 64} 
    $a2 = {C7 45 ?? 4C 69 62 72} 
    $a3 = {C7 45 ?? 61 72 79 41} 
    $a4 = {C7 45 ?? 56 69 72 74} 
    $a5 = {C7 45 ?? 75 61 6C 41} 
    $a6 = {C7 45 ?? 6C 6C 6F 63} 
    $a7 = {C7 45 ?? 4C 6F 63 61} 
    $a8 = {C7 45 ?? 6C 41 6C 6C} 
    $a9 = {C7 45 ?? 52 65 61 64} 
    $a10 = {C7 45 ?? 46 69 6C 65} 
    $a11 = {C7 45 ?? 43 72 65 61} 
    $a12 = {C7 45 ?? 74 65 46 69} 
    $a13 = {C7 45 ?? 47 65 74 46} 
    $a14 = {C7 45 ?? 69 6C 65 53} 
    $a15 = {C7 45 ?? 69 7A 65 00} 
    $a16 = {C7 45 ?? 43 6C 6F 73} 
    $a17 = {C7 45 ?? 65 48 61 6E}
    $a18 = {C7 45 ?? 47 65 74 50} 
    $a19 = {C7 45 ?? 72 6F 63 41} 
    $a20 = {C7 45 ?? 64 64 72 65}
    $a21 = {C7 45 ?? 75 61 6C 50} 
    $a22 = {C7 45 ?? 72 6F 74 65} 
    
    $b1 = { C6 85 ?? FE FF FF 4C }
    $b2 = { C6 85 ?? FE FF FF 6F }
    $b3 = { C6 85 ?? FE FF FF 63 }
    $b4 = { C6 85 ?? FE FF FF 61 }
    $b5 = { C6 85 ?? FE FF FF 6C }
    $b6 = { C6 85 ?? FE FF FF 41 }

condition:

    uint16(0) == 0x5A4D
    and 9 of ($a*)
    and all of ($b*)
    and filesize<200000
}

rule APT_RU_GreyEnergy_mini_64: BlackEnergy
{
meta:

    report        = "GreyEnergy’s overlap with Zebrocy and BlackEnergy"
    description   = "Rule to detect GreyEnergy mini backdoor 64-bit"
    hash          = "4a586da7043b9a044d9ed4b544d994b5"
    hash          = "f40d6192b14c6e1cdcc0462553ee5dd1"
    author        = "Kaspersky Lab"
    copyright     = "Kaspersky Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2018-11-16"
    last_modified = "-"

strings:

    $a1 = {48 C7 44 24 ?? 4C 6F 61 64} 
    $a2 = {48 C7 44 24 ?? 4C 69 62 72} 
    $a3 = {48 C7 44 24 ?? 61 72 79 41} 
    $a4 = {48 C7 44 24 ?? 56 69 72 74} 
    $a5 = {48 C7 44 24 ?? 75 61 6C 41}
    $a6 = {48 C7 44 24 ?? 6C 6C 6F 63} 
    $a7 = {48 C7 44 24 ?? 4C 6F 63 61} 
    $a8 = {48 C7 44 24 ?? 6C 41 6C 6C} 
    $a9 = {48 C7 44 24 ?? 52 65 61 64} 
    $a10 = {48 C7 44 24 ?? 46 69 6C 65} 
    $a11 = {48 C7 44 24 ?? 43 72 65 61} 
    $a12 = {48 C7 44 24 ?? 74 65 46 69} 
    $a13 = {48 C7 44 24 ?? 47 65 74 46} 
    $a14 = {48 C7 44 24 ?? 69 6C 65 53} 
    $a15 = {48 C7 44 24 ?? 69 7A 65 00} 
    $a16 = {48 C7 44 24 ?? 43 6C 6F 73} 
    $a17 = {48 C7 44 24 ?? 65 48 61 6E} 
    $a18 = {48 C7 44 24 ?? 47 65 74 50} 
    $a19 = {48 C7 44 24 ?? 72 6F 63 41} 
    $a20 = {48 C7 44 24 ?? 64 64 72 65} 
    $a21 = {48 C7 44 24 ?? 75 61 6C 50} 
    $a22 = {48 C7 44 24 ?? 72 6F 74 65} 

condition:

    uint16(0) == 0x5A4D
    and 9 of ($a*)	
    and pe.machine == pe.MACHINE_AMD64
}

rule APT_RU_GreyEnergy_dropper_backdoor: BlackEnergy
{
meta:

    report        = "GreyEnergy’s overlap with Zebrocy and BlackEnergy"
    description   = "Rule to detect GreyEnergy dropper and backdoor"
    hash          = "7552b4c677048caeb0112d9b8225459b"
    hash          = "7a7103a5fc1cf7c4b6eef1a6935554b7"
    hash          = "16bb9def4fabfa2ccb3efc1ca5bfc2fa"
    hash          = "275f821b328c06a2ef7b5ebb22af9cb6"
    author        = "Kaspersky Lab"
    copyright     = "Kaspersky Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2018-11-16"
    last_modified = "-"

strings:

    $a1={ 8B 45 E0 8B 78 28 03 7D E4 8B 45 78 64 A3 00 00 00 00 [0-20] 83 C4 30 5D 81 C4 88 00 00 00 [0-30] FF E7 }
    $b1 = {
            03 C0 85 C0 79 09 03 C0 35 B7 0D C1 04 EB 02 03 
            C0 85 C0 79 09 03 C0 35 B7 0D C1 04 EB 02 03 C0 
            85 C0 79 09 03 C0 35 B7 0D C1 04 EB 02 03 C0 85 
            C0 79 09 03 C0 35 B7 0D C1 04 EB 02 03 C0 85 C0 
            79 09 03 C0 35 B7 0D C1 04 EB 02 03 C0 85 C0 79 
            09 03 C0 35 B7 0D C1 04 EB 02 03 C0 85 C0 79 09 
            03 C0 35 B7 0D C1 04 EB 02 03
          }
    $b2 = {68 01 00 ?? ?? FF 75 08 FF D3}

condition:

    uint16(0) == 0x5A4D
    and (all of ($a*))	
    or (all of ($b*))
}

