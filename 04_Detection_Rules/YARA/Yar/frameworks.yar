import "pe"
import "dotnet"

///////////////////////// LANGUAGES




rule Nuitka {
    meta:
        name        = "Nuitka"
        category    = "language"
        description = "This is a python program compiled to C with Nuitka"
        author      = "malcat"
        created     = "2024-03-20"
        reliability = 90
        tlp         = "TLP:white"
        sample      = "94512e7024c3570ae8a9a3f4a70a9bb817241047ea8a08d951e3feca9b51d9cd"

    strings:
        $ = "NUITKA_PYTHONPATH" ascii fullword
        $ = "cell_contents cannot be used to delete values Nuitka" ascii fullword
        $ = "nuitka_types_patch" ascii fullword
        $ = "nuitka_module_loader" ascii fullword
        $ = "cr_code is not writable in Nuitka" ascii fullword
        $ = "NUITKA_ONEFILE_PARENT" ascii fullword
		$ = "NUITKA_ONEFILE_BINARY" ascii fullword
		$ = "{TEMP}\\onefile_{PID}_{TIME}" wide fullword

    condition:
        3 of them and 
		pe.section_index(".text") == 0 and
		for any i in (0..pe.number_of_resources - 1): (
			pe.resources[i].type == pe.RESOURCE_TYPE_RCDATA and (
				pe.resources[i].id == 27 or
				pe.resources[i].id == 3
			)
		) 
}

rule PureBasic {
    meta:
        category = "language"
        description = "PureBasic executable"
        reliability = 60
        author = "malcat"

    strings:
        $ = {68????0000680000000068??????00E8??????0083C40C6800000000E8??????00A3}
        $ = {837C24080175??8B442404A3????????E8}

    condition:
        pe.section_index(".code") == 0 and for any of them: (
            $ at pe.entry_point
        )
}


rule Delphi {
    meta:
        category = "language"
        description = "Delphi executable, detection based on several artifacts"
        reliability = 80
        author = "malcat"

    strings:
        $ = { 0307426F6F6C65616E }
        $ = "FastMM Borland Edition" ascii fullword
        $ = "SOFTWARE\\Borland\\Delphi" ascii wide
        $ = { 0A06737472696E67 }
        $ = { 06537472696E67 }

    condition:
        (
            pe.section_index("CODE") >= 0 or 
            pe.section_index(".itext") >= 0 or
            pe.characteristics & 0x8080 == 0x8080 or
            pe.timestamp == 0x2A425E19 or 
            TurboLinker
        ) and 
        (
            for any i in (0..pe.number_of_resources - 1): (
                pe.resources[i].name_string == "P\x00A\x00C\x00K\x00A\x00G\x00E\x00I\x00N\x00F\x00O\x00" or pe.resources[i].name_string == "D\x00V\x00C\x00L\x00A\x00L\x00"
            ) or
            for any of them: (
                $ in (pe.sections[0].raw_data_offset..pe.sections[0].raw_data_offset + 10000)
            )
        )
}


rule DotNet {
    meta:
        category = "language"
        description = "Dotnet executable"
        reliability = 100
        author = "malcat"

    condition:
        dotnet.number_of_streams > 0
}


rule VisualBasicDotNet {
    meta:
        category = "language"
        description = "VB.Net executable"
        reliability = 100
        author = "malcat"

    condition:
        DotNet and for any i in (1..dotnet.number_of_assembly_refs) : (
            dotnet.assembly_refs[i].name == "Microsoft.VisualBasic"
        )
}

rule VisualBasic {
    meta:
        category = "language"
        description = "VisualBasic executable (pcode or native)"
        reliability = 100
        author = "malcat"

    strings:
        $vb_dll_ep = {83C8FFC21000}

    condition:
        pe.is_32bit() and
            (pe.imports("msvbvm60.dll") or pe.imports("msvbvm50.dll") or pe.imports("vb40032.dll")) and 
            (
                uint8(pe.entry_point) == 0x68 and 
                uint8(pe.rva_to_offset(uint32(pe.entry_point + 1) - pe.image_base)) == 0x56 and
                uint8(pe.rva_to_offset(uint32(pe.entry_point + 1) - pe.image_base) + 1) == 0x42
            ) or
            (
                pe.is_dll() and $vb_dll_ep at pe.entry_point
            )
}

rule AutoIt {
    meta:
        category = "language"
        description = "AutoIt compiled program"
        reliability = 100
        author = "malcat"

    strings:
        $c1 = "Null Object assignment in FOR..IN loop" wide fullword
        $c3 = "This is a third-party compiled AutoIt script." ascii
        $c4 = "This is a compiled AutoIt script." ascii
        $sig = {A3484B}

    condition:
        pe.number_of_sections > 2 and any of ($c*) and (
            $sig at pe.overlay.offset or
            for any i in (0..pe.number_of_resources - 1): (
                $sig at pe.resources[i].offset
            )
        )
}

rule AutoHotKey {
    meta:
        category = "language"
        description = "AutoHotKey intepreter with an AutoHotKey resource"
        reliability = 90
        author = "malcat"

    strings:
        $c1 = "NOTE: To disable the key history shown below, add the line \"#KeyHistory 0\" anywhere in the script" wide fullword
        $c2 = "Nonexistent hotkey variant (IfWin)." wide fullword
        $c3 = "MouseMoveOff" wide fullword
        $c4 = "CoordModePixel" wide fullword
        $sig = "; <COMPILER: "

    condition:
        pe.number_of_sections > 2 and 3 of ($c*) and (
            $sig at pe.overlay.offset or
            for any i in (0..pe.number_of_resources - 1): (
                $sig at pe.resources[i].offset
            )
        )
}

///////////////////////// INSTALLERS

rule NsisInstaller {
    meta:
        category = "installer"
        description = "Nullsoft installer"
        reliability = 90
        author = "malcat"

    strings:
        $c1 = "verifying installer: %d%%" ascii wide
        $c2 = "NSIS Error" ascii wide
        $c3 = "Error launching installer" ascii wide
        $nsis = { EFBEADDE4E756C6C736F6674496E7374 }

    condition:
        pe.overlay.size > 64 and $nsis in (pe.overlay.offset..pe.overlay.offset+10000) and 2 of ($c*)
}

rule InnoInstaller {
    meta:
        category = "installer"
        description = "InnoSetup installer"
        reliability = 90
        author = "malcat"

    strings:
        $c1 = "The setup files are corrupted. Please obtain a new copy of the program." wide 
        $c2 = "Inno Setup Setup Data" ascii wide
        $inno = "zlb" ascii
        $setupcfg = "rDlPtS" ascii
    condition:
        Delphi and pe.overlay.size > 64 and $inno in (pe.overlay.offset..pe.overlay.offset+10000) and any of ($c*) and 
        for any i in (0..pe.number_of_resources - 1): (
            $setupcfg at pe.resources[i].offset
        )
}


rule PyInstaller {
    meta:
        category = "installer"
        description = "Pyinstaller"
        reliability = 90
        author = "malcat"

    strings:
        $c1 = "Cannot GetProcAddress for Py_FrozenFlag" ascii 
        $c2 = "Error detected starting Python VM." ascii 
        $c3 = "sys.path.append(r\"%s\")" ascii 
        $c4 = "Cannot GetProcAddress for PySys_SetObject" ascii 
        $c5 = "Failed to get address for Py_SetPythonHome" ascii 
        $c6 = "Error loading Python DLL '%s'." ascii 
        $c7 = "Failed to set python home path!"
        $c8 = "Failed to get address for PySys_SetObject"
        $magic = {4D45490C0B0A0B0E00}

    condition:
        pe.overlay.size > 64 and (
            $magic or uint16(pe.overlay.offset) == 0xda78
        ) and 2 of ($c*)
}

rule Py2exe {
    meta:
        category = "installer"
        description = "Py2exe"
        reliability = 90
        author = "malcat"

    strings:
        $magic = {12345678}
        $s1 = "PY2EXE_VERBOSE" ascii fullword
        $s2 = "PYTHONINSPECT" ascii fullword
        $s3 = "boot_common.py" ascii

    condition:
        for any i in (0 .. pe.number_of_resources - 1): (
            $magic at pe.resources[i].offset
        ) and 2 of ($s*)
}


rule JWrapper {
    meta:
        category = "installer"
        description = "From Java to Native App in Seconds"
        reliability = 90
        author = "malcat"

    strings:
        $ = "[Extractor] Latest GUversion is newer or same as our version so will just run\n"    // "[Extractor] Late..o will just run◙"
        $ = "[Extractor] The existing JWrapper install is broken. Instructing the wrapper to update.\n"    // "[Extractor] The ..pper to update.◙"
        $ = "JWrapper Proxy Detector/1.0" wide    // "JWrapper Proxy Detector/1.0"
        $ = "[HttpDownloader] Saving any detected proxy settings\n"    // "[HttpDownloader].. proxy settings◙"
        $ = "[Extractor] [SEVERE] Unable to load existing JW dll.\n"    // "[Extractor] [SEV..xisting JW dll.◙"

    condition:
        3 of them
}

///////////////////////// SELF-EXTRACTORS

rule WinrarSelfExtractor {
    meta:
        category = "sfx"
        description = "WINRAR self extractor"
        reliability = 100
        author = "malcat"

    strings:
        $c1 = "RarHtmlClassName" ascii wide
        $c2 = "GETPASSWORD1" wide
        $c3 = "RarSFX" ascii wide
		$c4 = "__tmp_rar_sfx_access_check_%u" ascii fullword
        $rar = { 526172211A07 }
        $zip = { 504B0304 }

    condition:
        pe.overlay.size > 64 and ($rar at pe.overlay.offset or $zip at pe.overlay.offset) and 3 of ($c*)
}


rule CabSelfExtractor  {
    meta:
        category = "sfx"
        description = "CAB self extractor"
        reliability = 100
        author = "malcat"

    strings:
        $c1 = "wextract" ascii wide fullword
        $c2 = "UPDFILE%lu" ascii fullword
        $c3 = "PACKINSTSPACE" ascii fullword
        $c4 = "POSTRUNPROGRAM" ascii fullword
        $sig = {4D534346}

    condition:
        pe.number_of_sections > 2 and 3 of ($c*) and (
            for any i in (0..pe.number_of_resources - 1): (
                $sig at pe.resources[i].offset
            )
        )
}

rule SevenZipSelfExtractor {
    meta:
        category = "sfx"
        description = "7z self extractor"
        reliability = 100
        author = "malcat"

    strings:
        $c1 = "SfxVarCmdLine1" wide fullword
        $c2 = "7ZSfx%03x.cmd" wide fullword
        $c3 = "setup.exe" wide fullword
        $c4 = "SfxVarSystemLanguage" wide fullword
        $c5 = "*.sfx.api" ascii fullword
        $c6 = "Can not create temp folder archive" wide fullword
        $c7 = "7-Zip" wide fullword
        $c8 = "ExecuteParameters" wide fullword
        $sig = ";!@Install@!UTF-8!"


    condition:
        pe.number_of_sections > 2 and 3 of ($c*) and $sig at pe.overlay.offset
}


rule ElectronApp {
    meta:
        name        = "ElectronApp"
        category    = "language"
        description = "The program is a packed electron app"
        author      = "malcat"
        reliability = 90
        tlp         = "TLP:white"

    strings:
        $ = "V8.GC_SCAVENGER_SCAVENGE_ROOTS"
        $ = "V8.GC_MC_INCREMENTAL_EXTERNAL_EPILOGUE"
        $ = "V8.GC_MINOR_MC_MARK_CLOSURE_PARALLEL"
        $ = "electron_debug.log" wide
        $ = "Electron_PowerMonitorHostWindow" wide

    condition:
        3 of them and pe.section_index("CPADinfo") >= 0
}



