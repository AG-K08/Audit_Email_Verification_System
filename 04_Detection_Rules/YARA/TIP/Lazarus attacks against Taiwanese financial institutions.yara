import "pe"

rule apt_NK_Lazarus_Hermes_ransomloader {
meta:

  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
  decription   = "The loader module"
  hash         = "d08f1211fe0138134e822e31a47ec5d4"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

  $win2k_login_acc = "FEIB\\SPUSER14" nocase ascii wide
  $win2k_login_adm = "FEIB\\scomadmin" nocase ascii wide
  $netbios_addomain_slash = "FEIB\\" ascii wide
  $file_newpath = "c:\\windows\\temp\\bitsran.exe" nocase ascii wide
  $run_remote_task = "schtasks /create /tn \"BITSRAN\" /tr %s /s \"%s\" /u %s /p %s /st 00:00 /et 23:59 /sc minute /mo 1 /ru system /f"

condition:

  uint16(0)==0x5A4D and
	filesize < 5000000 and
  ( $win2k_login_acc or $win2k_login_adm or ( #netbios_addomain_slash >=2 and uint32(@netbios_addomain_slash-4) == 0x00000000 ) )
  or
  ( $file_newpath and $run_remote_task and
  ( pe.imports("kernel32.DLL","FindResourceA") and pe.imports("kernel32.DLL","LockResource") and pe.imports("kernel32.DLL","LoadResource") )
  )

}

rule apt_NK_Lazarus_Hermes_ransommodule {
meta:

  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
  decription   = "The Hermes Ransomware module"
  hash         = "b27881f59c8d8cc529fa80a58709db36"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

  $syspolicy_regkey = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\" nocase ascii wide
  $str_hermes = "HERMES" ascii wide
  $unique_id_file = "UNIQUE_ID_DO_NOT_REMOVE" ascii wide
  $batch_xor_routine = { 1C 5F 8A 84 [4-6] 30 ?? [2-4] 4? 3B [1-2] 7? [1-2] 8A [4-6] 30 ?? [2-4] 4? 3B [1-2] 7C [1-2] 57 }
  $decrypt_msg_routine_1 = {33 F6 85 ?? 74 ?? 3? ?? 8B [1-2] F7 ?? [4-6] 8? ?? [4-6] 3? ?? [4-6] 4? 3? [1-2] 7? ?? C6 ?? [4-6] 5E }
  $decrypt_msg_routine_2 = {33 C0 8A 8C [4-6] 3? 4? [2-4] 4? 8? [2] 7? ?? 33 C0 8A 8C [4-6] 3? 4? [2-4] 4? 8? [2] 7? ?? 6A }

condition:

  uint16(0)==0x5A4D and
	filesize < 5000000 and
  ($syspolicy_regkey and #str_hermes>=2 and $unique_id_file) or
  ($batch_xor_routine or $decrypt_msg_routine_1 or $decrypt_msg_routine_2 )

}

rule apt_NK_Lazarus_Hermes_loader64 {
meta:

  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
  decription   = "The Hermes loader"
  hash         = "0edbad9e6041d43f97c7369439a40138"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

  $enc_rc4 = { 66 66 66 66 [4-6]  00 00 00 00 4? 0? [2-4] 4? 0? [2-4] 4? [2] 0F B? [2-4] 0? [1-2] 4? 0? [1-2] 4? 8? [2-4] 4? 0F B? [1-5] 0F B? [2-4] 4? 8? [1-4] 4? 0F B? [1-4] 8? [1-6] 4? 0F [1-4] 4? F? [1-2] 4? F? [1-2] 0F B? [1-2] 7? [1-2] 4? 0F }	 //at 0x1800010D0
  $str_netsvcs = {B9 6E 00 00 00 [4-12] B9 65 00 00 00 [4-12] B9 76 00 00 00 [4] 74 00 73 00 [4-12] C? [3] 63 00 73 00 66}

condition:

  uint16(0)==0x5A4D and
	filesize < 5000000 and
  ( ( pe.imports("advapi32.dll","CryptAcquireContextW") or pe.imports("advapi32.dll","CryptAcquireContextA") ) and
  pe.imports("advapi32.dll","CryptReleaseContext") and pe.imports("advapi32.dll","CryptCreateHash") and
  pe.imports("advapi32.dll","CryptGetHashParam") and pe.imports("advapi32.dll","CryptHashData") and
  pe.imports("kernel32.dll","ReadFile") and pe.imports("kernel32.dll","CreateThread") and pe.imports("shlwapi.dll","StrStrIW") and
  $str_netsvcs ) or
  ( $enc_rc4  )

}

rule apt_NK_Lazarus_Hermes_key {
meta:

  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
  decription   = "Unique key found in Hermes sample"
  hash         = "5abd1242e1b6d862ba609766959211ca"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

  //unique key: A6 EB 96 00 61 B2 E2 EF 0D CB E8 C4 5A F1 66 9C A4 80 CD 9A F1 2F 46 25 2F DB 16 26 4B C4 3F 3C
  $key_lump = {A6 EB 96 00 61 B2 E2 EF 0D CB E8 C4 5A F1 66 9C A4 80 CD 9A F1 2F 46 25 2F DB 16 26 4B C4 3F 3C }
  $key_dw = { A6 EB 96 00 [2-6] 61 B2 E2 EF [2-6] 0D CB E8 C4 [2-6] 5A F1 66 9C [2-6] A4 80 CD 9A [2-6] F1 2F 46 25 [2-6] 2F DB 16 26 [2-6] 4B C4 3F 3C }
  //$key_wd = { A6 EB [2-6] 96 00 [2-6] 61 B2 [2-6] E2 EF [2-6] 0D CB [2-6] E8 C4 [2-6] 5A F1 [2-6] 66 9C [2-6] A4 80 [2-6] CD 9A [2-6] F1 2F [2-6] 46 25 [2-6] 2F DB [2-6] 16 26 [2-6] 4B C4 [2-6] 3F 3C }

condition:

  uint16(0)==0x5A4D and
	filesize < 5000000 and
  ( 1 of ($key_*) )

}

rule apt_NK_Lazarus_commandline_loader {
meta:

  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
  description  = "BlueNoroff commandline loader"
  hash = "9914075cc687bdc352ee136ac6579707"
  hash = "5abd1242e1b6d862ba609766959211ca"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

	$a1={C7 4? [1-2] A6 EB 96 00 C7 4? [1-2] 61 B2 E2 EF C7 4? [1-2] 0D CB E8 C4 C7 4? [1-2] 5A F1 66 9C C7 4? [1-2] A4 80 CD 9A}

condition:

  (uint16(0) == 0x5a4d) and
  filesize < 500KB and
  $a1
}

rule apt_NK_Lazarus_Backdoor {
meta:
  author       = "Kaspersky Lab"
  tlp          = "AMBER"
  copyright    = "Kaspersky Lab"
  type         = "APT"
	description  = "Lazarus backdoor"
	hash = "97aaf130cfa251e5207ea74b2558293d"
  report = "Lazarus attacks against Taiwanese financial institutions"
  distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:

	$a2 = "ssylka" fullword ascii
	$a3 = "ustanavlivat" fullword ascii
	$a4 = "poluchit" fullword ascii
	$a5 = "pereslat" fullword ascii
	$a6 = "derzhat" fullword ascii
	$a7 = "vykhodit" fullword ascii
	$a8 = "Nachalo" fullword ascii

	$b = "kliyent2podklyuchit" fullword ascii

condition:

	uint16(0) == 0x5A4D and
	filesize < 2000000 and
	(4 of ($a*) or $b)
}
