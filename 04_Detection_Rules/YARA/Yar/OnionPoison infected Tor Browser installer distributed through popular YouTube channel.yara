rule crimeware_OnionPoison_freebl3 {
meta:
	description = "Rule to detect the infected Tor Browser"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-08-11"
	hash = "87E33DF76D70103A660783C02AAC44AC"
strings:
    $s1 = "rtlDecompress %d %d %d" ascii
    $s2 = "D65CB35A-58CB-4456-A7B7-E1B218770A9E" ascii
    $s3 = "Authorization: SIGN %s:%s"
condition:
    uint16(0) == 0x5A4D
    and all of them
}

rule crimeware_OnionPoison_cloud {
meta:
	description = "Rule to detect final payload of OnionPoison campaign"
	author = "Kaspersky"
	copyright = "Kaspersky"
	distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
	version = "1.0"
	last_modified = "2022-08-11"
	hash = "34c43c9b23b40d9d70b4530de781f88a"
strings:
	$a1 = "Softwares"
	$a2 = "Processes"
	$a3 = "Wifis"
	$a4 = "Socials"
	$a5 = "Histories"
	$a6 = "Chromes"

	$b1 = "TorBrowser\\Data\\Browser\\profile.default\\places.sqlite"
	$b2 = "\\Google\\Chrome\\User Data\\Default\\History"
	$b3 = "\\Microsoft\\Edge\\User Data\\Default\\History"

// RSA public key
	$c1 = "kmy94XUrUqWg75zMnW3R2gnwUo4p6GTZDn/befSmQ/Hcyz/YgNx+z18tpU4GbggQ" 
	$c2 = "0cxzdvAqYcf3nXZk9GJmi5p3sctSB9ynpHAMHIp0jagjynPJMWuS7MhwB6mvz90j"

condition:
	uint16(0) == 0x5A4D
	and (
    		(4 of ($a*) and any of ($b*))
    		or all of ($c*)
	)

}
