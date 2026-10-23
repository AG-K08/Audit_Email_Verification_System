import "pe" 
rule apt_Dropbox_uploader_2022 {
  meta:
    description = "Rule to detect the implant used for upload files to Dropbox"
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.0"
    last_modified = "2022-12-20"
    hash = "F8553382DE7E1E349D8E91EDB7C57953"
  
  strings:
    $a1 = "%s\\*.*" wide fullword
    $a2 = "CreateProcess success" fullword
    $a3 ="CreateProcess failed" fullword
    $a4 = {0F B6 91 ?? ?? ?? 00 0F B6 92 ?? ?? ?? 00 88 91 ?? ?? ?? 00 0F B6 91 ?? ?? ?? 00 0F B6 92 ?? ?? ?? 00 88 91 ?? ?? ?? 00 0F B6 91 ?? ?? ?? 00 0F B6 92 ?? ?? ?? 00 88 91}

  condition:
    uint16(0) == 0x5A4D and filesize < 1MB
    and (all of ($a*)) and
    (pe.number_of_signatures > 0) and
    for any i in (0..pe.number_of_signatures):
      (pe.signatures[i].serial == "12:f0:27:7e:0f:23:3b:39:f9:41:9b:06:e8:cd:e3:52")
}

rule apt_Dropbox_uploader_payload_injection_2022 {
   meta:
     description = "Rule to detect a payload injection of the implant used for upload files to Dropbox"
     author = "Kaspersky"
     copyright = "Kaspersky"
     distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
     version = "1.0"
     last_modified = "2022-12-20"
     hash = "5137C61734E2096018CEE99149DAC009"

  strings:
    $code = {89 5C 24 1C C6 44 24 ?? 6D C6 44 24 ?? 73 C6 44 24 ?? 69 C6 44 24 ?? 63 C6 44 24 ?? 2E 88 5C 24 7B C7 44 24 2C 44 00 00 00 C7 44 24 58 01 00 00 00 66 89 44 24 5C FF D6}

  condition:
    uint16(0) == 0x5A4D and filesize < 200000 and (all of them)
    and (for any i in (0..pe.number_of_signatures):
      (pe.signatures[i].serial == "12:f0:27:7e:0f:23:3b:39:f9:41:9b:06:e8:cd:e3:52"))
}

rule apt_YandexDisk_uploader_2022 {
  meta:
    description = "Rule to detect the implant used for upload files to YandexDisk "
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.0"
    last_modified = "2022-12-20"
    hash = "5C3A88073824A1BCE4359A7B69ED0A8D"
    
  strings:
    $string1 = "content-length" fullword
    $string2 = "hoxnox/yadisk-upload" fullword
    $string3 = "Cost Time:"
    $string4 = "Finished..." 

  condition:
    uint16(0) == 0x5A4D and filesize < 3MB and all of them
}

rule apt_Generic_file_uploader_2022 {
  meta:
    description = "Rule to detect Go Uploader transfer.exe"
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.0"
    last_modified = "2022-12-20"
    hash = "8BA9EE9FD6BD4B9304F7FB868CE975D8"
    
  strings:
    $string1 = "UPX0" fullword
    $string2 = "UPX1" fullword
    $build_id = "Go build ID: \"wP-5jseiV-i0EY7-"
    $string3 = "TWRClJZE5dfjmS/xxeXeuGdoU0GF6" 
    
  condition:
    uint16(0) == 0x5A4D and filesize < 3MB and all of them
}

rule apt_FourteenHi_loader_2022 {
  meta:
    description = "Rule to detect DllHijacking mpsvc.dll 2022"
    author = "Kaspersky"
    copyright = "Kaspersky"
    distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version = "1.0"
    last_modified = "2022-12-20"
    hash = "7332710D10B26A5970C5A1DDF7C83FBA"
    
  strings:
    $doc = ".doc" fullword 

  condition:
    uint16(0) == 0x5A4D and pe.DLL and filesize < 500000 
    and pe.exports("ServiceCrtMain") and all of them 
}
