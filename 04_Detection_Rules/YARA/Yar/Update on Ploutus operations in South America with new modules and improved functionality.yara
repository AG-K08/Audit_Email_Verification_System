rule crimeware_latam_Ploutus_V3_CPP {

    meta:
        description = "Ploutus ATM malware, version written in VC++"
        filetype = "Win32"
        author = "Kaspersky Lab"
        date = "2017-03-07"
        version = "1.0"

strings:
    $code1 = "CDMInit" ascii
    $code2 = "DBD_AdvFuncDisp" ascii
    $code3 = "CDM-WFSOpen" ascii
    $code4 = "WFS_INF_CDM_CASH_UNIT_INFO" ascii
    $code5 = "CDM-WFS_CMD_CDM_DISPENSE" ascii

    $str1 = "No Cassette Selected" ascii
    $str2 = "Command:" ascii
    $str3 = "Key:" ascii
    $str4 = "Event:" ascii
    $str5 = "Selected Cassete:" ascii

condition:
    uint16(0) == 0x5A4D and
    all of them and
    filesize < 50000

}

rule crimeware_latam_Ploutus_V3_ConnectionTool {

    meta:
        description = "Ploutus ATM malware, remote administration and configuration utility"
        filetype = "MSIL"
        author = "Kaspersky Lab"
        date = "2017-03-07"
        version = "1.0"

strings:
    $diebold = "DieboldP" ascii
    $code1 = "StartLoopTV" ascii
    $code2 = "WifiStatus" ascii
    $code3 = "Disconnect" ascii
    $code4 = "set_Username" ascii
    $code5 = "set_Password" ascii
    $code6 = "get_MachineID" ascii
    $code7 = "get_C1" ascii
    $code8 = "get_C7" ascii
    $code9 = "C5" ascii
    $code10 = "C6" ascii
	
condition:
    uint16(0) == 0x5A4D and
    $diebold and
    4 of ($code*) and
    filesize < 260000

}


rule crimeware_latam_Ploutus_V3 {

    meta:
        description = "Ploutus ATM malware, third version with modifications"
        filetype = "MSIL"
        author = "Kaspersky Lab"
        date = "2017-03-07"
        version = "1.0"

strings:
    $xfs1 = "CASHDISPENSER3Lib" ascii
    $xfs2 = "ICDMDenomination" ascii
    $xfs3 = "ICDMCashUnit" ascii
    $xfs4 = "get_CurrencyID" ascii
    $xfs5 = "PINPAD3Lib" ascii
    $xfs6 = "PINFDKeys" ascii
    $xfs7 = "IPINReadData" ascii
    $xfs8 = "add_DispenseStarted" ascii
    $xfs9 = "PINFDKeys" ascii

    $str1 = "SetWindowsHook" ascii
    $str2 = "CallNextHookEx" ascii
    $str3 = "Diebold" wide
    $str4 = "AgilisConfigurationUtility" wide

condition:
    uint16(0) == 0x5A4D and
    4 of ($xfs*) and
    3 of ($str*) and
    filesize < 320000

}
