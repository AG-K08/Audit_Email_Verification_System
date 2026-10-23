rule apt_Equation_NewDSZ_check_builds {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "feebb505b90eea142af91625955820cd"

strings:
	$a = { 3d 5d 58 00 00 72 07 b8 04 00 00 00 eb 3e 3d 7c 4f 00 00 72 07 b8 03 00 00 00 eb 30 3d 61 4a 00 00 72 07 b8 02 00 00 00 eb 22 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	$a
}

rule apt_Equation_NewDSZ_DiskDiag {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "635d556797131bf92911b8e5d12c3d09"

strings:
	$a = "Microsoft-Windows-DiskDiagnosticDataCollector" wide
	$TskSrv = { C7 A4 AB 2F A9 4D 13 40 96 97 20 CC 3F D4 0F 85 }
	$evt = { 44 8D 88 61 A5 24 00 8D 56 3F 48 8B CD 41 81 F1 F5 AC 00 00 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	all of them
}

rule apt_Equation_NewDSZ_newPC {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "1c404eae376ed2d0bd85a79f2c28f639"

strings:
	$chkIp = { 0F B6 17 83 E2 0F C1 E2 02 0F B6 4F 09 83 E9 01 0F 84 ?? ?? 00 00 83 E9 05 0F 84 ?? ?? 00 00 83 F9 0B 0F 85 ?? ?? 00 00 8B CA 48 03 CF 44 0F B7 49 02 41 0F B7 C1 66 C1 C8 08 66 83 F8 35 74 ?? 0F B7 01 66 C1 C8 08 66 83 F8 35 }
$decrCfg = { B9 4F 00 00 00 FF 15 ?? ?? ?? ?? 48 8D 7D 08 BE CA 07 00 00 BB 01 00 00 00 FF 15 ?? ?? ?? ?? 30 07 48 03 FB 48 2B F3 75 F0 }
$cfg = { 8D 84 F6 69 92 CC 9B FA }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	any of them
}

rule apt_Equation_NewDSZ_pipe {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "0b9f6ceaface4ea176fd11e6155bfd45"

strings:
	$fmt = "%s%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x"
	$pipe = { C7 45 ?? 5C 5C 2E 5C C7 45 ?? 70 69 70 65 66 C7 45 ?? 5C 00 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	all of them
}

rule apt_Equation_NewDSZ_PL {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "59e65defc9556c474c0105665e955682"

strings:
	$a = { 02 02 00 00 24 9F 93 B6 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	$a
}

rule apt_Equation_NewDSZ_RsaMod {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "fbe5b3b0d720c83cc3b88ae86f46112a"

strings:
	$a = { C2 51 66 EC B0 99 38 66 84 9B 14 32 7F 9F 07 E2 4B CF AC A5 F3 2C 81 D0 D6 58 8C 2D 71 C3 08 57 D9 D9 63 E3 EE CD 89 45 30 F3 49 8E FF 04 63 BF 3D 56 77 77 54 4B 08 A5 00 1E 3F 84 C2 F5 EC B3 15 F3 15 B3 8A 98 7E A6 07 EC AA E3 C6 14 FE CB 09 35 1B 48 36 FF FC 7A E6 5A 4D D5 FE 13 2F C3 62 CA 63 B6 40 7D 66 22 87 85 34 E0 99 54 80 B4 41 22 54 A7 D8 96 70 A1 08 08 85 23 59 36 F4 8A 5C ED A8 02 E6 07 F8 47 A7 CF 6B 96 98 A3 D3 C3 60 F9 98 5A D7 01 65 C9 00 F2 59 B2 9D 35 E2 88 DC FD 6B FB C4 F9 13 29 A9 81 9F 3A B0 7E D8 10 FD D2 A7 5B AF DC 18 10 CC 0E AC 8F 7F 2C 50 B0 5F 96 56 E6 19 20 FA 2C 74 A5 2C 6C 64 91 F2 61 1E 31 05 F7 10 BD 98 BC B1 1E 61 10 05 99 F0 97 CF 86 8C F5 50 B7 CE 46 B9 41 E8 A9 68 2E 50 78 BF FA E9 5F BF 32 BA 31 89 8D 3C 22 A9 95 39 BD }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	$a
}

rule apt_Equation_NewDSZ_shlcd {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "7e0b261045aa067d2c9e1cf0a5e9669f"

strings:
	$start = { E8 00 00 00 00 59 56 48 8B F4 48 83 E4 F0 48 81 C1 ?? ?? 00 00 BA ?? 00 00 00 52 51 48 83 EC 20 48 81 C1 ?? ?? 00 00 49 89 C8 BA ?? 00 00 00 49 81 C0 ?? ?? ?? ?? 41 B9 ?? ?? 00 00 E8 ?? ?? 00 00 48 8B E6 5E C3 }

condition:
	filesize < 1000000 and
	$start
}

rule apt_Equation_NewDSZ_decrypt_string {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "dc6a0159282a9c57b52061f5da0def8f"

strings:
	$a = { 8d 0c 40 b8 ff 00 00 00 d3 e0 48 63 d0 48 b8 ?? ?? ?? ?? ?? ?? ?? ?? 48 23 d0 48 d3 ea 32 16 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	$a
}

rule apt_Equation_NewDSZ_apihash {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "0b9f6ceaface4ea176fd11e6155bfd45"

strings:
	$a = { 48 b9 c4 43 8a 6f c8 32 0a 72 }
	$b = { 48 b9 d6 96 00 2c ae 00 4c e4 }

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	all of them
}

rule  apt_Equation_NewDSZ_soundmtr {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "6D404826F5CBBBD226C0D31D8154ADEF"
	hash = "75D9C1E2E4980E9E0F9B80E8A69713CC"
	hash = "C5CC98C7342A9760B4B07C0679070801"

strings:
	$a1 = "Measures the sound and media metrics of this system" fullword wide  
	$a2 = "Global\\{1CEE258F-2432-7D92-AA1D-F70D27D3E622}" fullword wide   
	$a3 = "IBiT_Z1p4AT2tB>=gNZRFT9p_6]EmzbG" fullword wide 
	$a4 = "\\Microsoft\\Windows\\MultiMedia" fullword wide  
	$a8 = "soundmtr.dll" fullword ascii wide
	$a10 = "flowfc.tmp" fullword wide
	$a11 = "flowfr.tmp" fullword wide

condition:
	uint16(0) == 0x5A4D and
	filesize < 1600000 and
	2 of them
}

rule apt_Equation_NewDSZ_perfd {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "98E99FE54A72A27622203A1BF70DD447"
	hash = "C24CFAF623E3081F904E2D8CCD0E8A04"

strings:
	$a1 = ".?AV?$StringSinkTemplate@V?$vector@EV?$allocator@E@std@@@std@@@CryptoPP@@" fullword ascii    
	$a2 = "Dlsse_simd.cpp" fullword ascii

condition:
	uint16(0) == 0x5A4D and
	filesize < 1600000 and
	2 of them
}

rule apt_Equation_NewDSZ_ehix {
meta:
	description = "Rule to detect Equation NewDSZ APT samples"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-09-20"
	hash = "FC4C3A98CE862FD05509AFF88661303D"

strings:
	$a1 = "ehix.dll" fullword ascii

condition:
	uint16(0) == 0x5A4D and
	filesize < 1600000 and
	1 of them
}

