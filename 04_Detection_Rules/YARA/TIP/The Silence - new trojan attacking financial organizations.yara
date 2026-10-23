rule apt_ZZ_Silence1 {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Unknown samples"
	last_modified = "2017-09-08 09:28:53"
	hash = "324D52A4175722A7850D8D44B559F98D"
	version = "1.0"
   	report = "The Silence Trojan - attack on financial organizations"
   	distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:
	$a1 = "S:\\SILENCE\\bnk\\ScreenMonitorServies\\ScreenMonitorService\\Release\\smmsrv.pdb" fullword ascii
	$a2 = "\\\\.\\pipe\\{73F7975A-A4A2-4AB6-9121-AECAE68AABBB}" fullword ascii
	$a3 = "ServiceMain: CreateEvent returned error" fullword ascii
	$a4 = "C:\\Windows\\temp\\Adobe Device.exe" fullword ascii
	$a10 = "\\mss.txt" fullword ascii

condition:
	uint16(0) == 0x5A4D and
	filesize < 5000000 and
	2 of them
}

rule apt_ZZ_Silence_strings2 {
meta:
	copyright = "Kaspersky Lab"
	description = "Rule to detect Unknown samples"
	last_modified = "2017-09-08 09:28:53"
	hash = "6A246FA30BC8CD092DE3806AE3D7FC49"
	version = "1.0"
   	report = "The Silence Trojan - attack on financial organizations"
   	distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:
	$a2 = "C:\\Users\\admin\\Desktop\\CnMgSrc\\Release Service\\srv_cons.pdb" fullword ascii
	$a3 = "Error WinHttpSendRequest with code %u: \"%s\"" fullword ascii
	$a10 = "Upsss. Process exit code %u" fullword wide
	$a12 = "Start %s site %s url %s" fullword ascii

condition:
	uint16(0) == 0x5A4D and
	filesize < 5000000 and
	2 of them
}
