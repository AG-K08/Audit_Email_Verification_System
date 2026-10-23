rule adware_Ketin_macOS {
    meta:
        description = "Rule to detect Ketin macOS AdWare samples, ciphered with substitution. Including installer, dylib and launchers."
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2022-11-14"
    strings:
		$s1 = "CCCrypt"
        $regex = /(\d{1,3}[\$\^\*\(\)\-\+\.\?\"!&=%#@_;:,]){16}/
    condition:
        (uint16(0) == 0xFACF or uint16(0) == 0xFECA) and
        filesize < 1MB and
        $regex and $s1
}

rule adware_Ketin_Installer_macOS {
     meta:
        description = "Rule to detect Ketin macOS AdWare installers and dylibs."
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2022-11-14"
    strings:
        $s1 = "CCCrypt"
        $s2 = "UUIDString"
        $s3 = "operatingSystemVersion"
        $s4 = "IOPlatformUUID"
        $s5 = ":url:completionHandler:"
        $s6 = "regularExpressionWithPattern"

        $enc1 = "affiliate_id" xor
        $enc2 = "DEBUG" xor

    condition:
        (uint16(0) == 0xFACF or uint16(0) == 0xFECA) and
        filesize < 2MB and
        3 of ($s*) and all of ($enc*)
}

rule adware_Ketin_Launcher_macOS {
    meta:
        description = "Rule to detect Ketin macOS AdWare launchers."
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2022-11-14"
    strings:
        $enc1 = "{HOME}/Library/Application Support" xor
        $enc2 = "NSCore" xor
    condition:
        (uint16(0) == 0xFACF or uint16(0) == 0xFECA) and
        filesize < 150KB and
        all of ($enc*)
}

rule adware_Ketin_CompanyUpdater_macOS {
    meta:
        description = "Rule to detect Ketin macOS AdWare samples named CompanyUpdater."
        author = "Kaspersky"
        copyright = "Kaspersky"
        distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
        version = "1.0"
        last_modified = "2022-11-14"    
    strings:
        $s1 = "CCCrypt"
        $regex = /([^\x00]\x00{7}[^\x00]\x00{7})/
    condition:
        (uint16(0) == 0xFACF or uint16(0) == 0xFECA) and
        (filesize < 2MB and #regex > 100 and $s1)
}


