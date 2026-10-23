import "pe"

rule APT_ZZ_CobaltStrike_Cometer {
meta:
	copyright = "Kaspersky Lab"
	description = "Attack through Central Bank of Chile fake web-sites"
	last_modified = "2017-10-18"
	author = "Kaspersky Lab"
	hash = "0344EEEBFD183AA48E049BB3A8101CCE"
	hash = "5890917A52314280E0FC6D999104491B"
	hash = "AE8CFD1A33F604FEE0A48CA0B51CC538"
	hash = "ef6f128eb6f4167a494ac6c085cdf4e4"
	version = "1.0"

strings:
	$a1 = {69 60 69 6A 69 E9 24 06 13 00 05 05 08 46 5? 47 59 49 41 0A 06 04 19 08 1D 00 0B 05 0C 52 49 24 3A 20 2C 49}

condition:
	uint16(0) == 0x5A4D and
	filesize < 1000000 and
	1 of them and
	(pe.exports ("SystemUpdater") or pe.exports ("_SystemUpdater"))
}
