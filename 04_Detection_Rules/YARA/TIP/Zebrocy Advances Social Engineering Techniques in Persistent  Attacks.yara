import "pe"

rule apt_RU_Zebrocy_embarcadero_delphi_implants {
meta:
	
	description = "Rule to detect Zebrocy Embarcadero delphi dropper and first stage validator"
	author = "Kaspersky Lab"
 	copyright = "Kaspersky Lab"
  	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "20-02-14"
	hash = "2fa37cef3c93daf2fad84903af065ad4"
	hash = "d9e48eacfe2147293ac233626dc77125"

strings:  	 
	
	$s1 = "\\VBApplication.log" ascii
	$s2 = "\\libkernel.exe" wide
	$s3 = "5C6C69626B65726E656C2E657865" ascii /* hex encoded string '\libkernel.exe' */
	$s4 = "TDefaultLoginCredentials.LoginEvent" ascii
    $s5 = "Embarcadero RAD Studio - Copyright 2015 Embarcadero Technologies, Inc." fullword ascii 
    $s6 = "Word cannot open the file, because the file format or file extension is not valid. Verify that the file has not been corrupted and that the file extension matches the format of the file." fullword ascii
    $s7 = "schtasks /create /sc minute /mo " wide
    $s8 = "Invalid time Offset string: %s=Error decoding URL style (%%XX) encoded string at position %d1Invalid URL encoded character (%s)" wide
    $s9 = "53747275637475726564536368656D612E62696E" ascii /* hex encoded 'StructuredSchema.bin' */
    $s10 = "68747470733A2F2F" ascii /* hex encoded string 'https://' */
    $s11 = "7363687461736B73202F637265617465202F7363206D696E757465202F6D6F20" ascii /* hex encoded string 'schtasks /create /sc minute /mo*/
    $s12 = "Worker Thread - %s #%d ThreadPool - %p" wide 
    $s13 = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.140 Safari/537.36 Edge/17.17134" fullword ascii

	$a1 = "loike=" fullword ascii
	$a2 = "nhghn=" fullword ascii
	$a3 = "rtybdf=" fullword ascii
	$a4 = "edf=" fullword ascii
	$a5 = "vsffd=" fullword ascii
	$a6 = "vgjhk=" fullword ascii
	$a7 = "rtfv=" fullword ascii
	$a8 = "Igbnmj=" fullword ascii


    $x1 = {8b 15 ac 4b 40 00 e8 59 ac d7 ff 83 c4 04 8b 45}
    $x2 = {80 c7 05 f0 5d 6a 00 ff ff ff ff c7 05 f4 5d 6a}
    $x3 = {83 2d b0 60 6a 00 01 73 39 33 c9 b2 01 a1 98 73}



condition:
	uint16(0) == 0x5A4D and
	filesize > 2MB and
	filesize < 8MB and
	#s4 >= 5 and 
	5 of ($s*) or 4 of ($a*) or (3 of ($s*) and all of ($x*))
}

rule apt_RU_Zebrocy_dotnet_backdoor {
meta:
	
	description = "Rule to detect Zebrocy .NET second stage backdoor"
	author = "Kaspersky Lab"
 	copyright = "Kaspersky Lab"
  	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "20-02-14"
	hash = "ca45cfd4d4450ed7a7f5141e2f246f8c"


strings:  	 

	$s1 = "key=" fullword wide
	$s2 = "retIP" fullword 
	$s3 = "AlwaysGoodCertificate" fullword 
	$s4 = "var=" fullword wide
	$s5 = "application/x-www-form-urlencoded" fullword wide
	$s6 = "ScreenShot" fullword ascii
	$s7 = "ListDir" fullword ascii
	$s8 = "UploadFile" fullword ascii
	$s9 = "ProcessStart" fullword ascii
	$s10 = "GarantDelivery" fullword ascii
	$s11 = "Somewhere" fullword ascii
	$s12 = "preparation" fullword ascii

	
	$pdb = "C:\\Users\\User\\source\\repos\\libsrc\\libsrc\\obj\\Release\\libsrc4.pdb" fullword ascii 



condition:
	uint16(0) == 0x5A4D and
	filesize < 100KB and 
	all of them or
	(pe.timestamp > 2524654861 and /* compilation timestamp after 2050 */ 6 of them )
	
}


