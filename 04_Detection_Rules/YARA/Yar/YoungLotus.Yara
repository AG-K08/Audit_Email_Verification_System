rule win32_younglotus {
    meta:
        author = "And"
        description = "Rule for detecting YoungLotus malware"
        reference_1 = "https://malpedia.caad.fkie.fraunhofer.de/details/win.younglotus"
        reference_2 = "https://habr.com/ru/articles/827184/"
        version = "1"
    strings:
        $string_0 = "%s:%d:%s"
        $string_1 = "SYSTEM\\CurrentControlSet\\Services\\"
        $string_2 = "WinSta0\\Default"
        $string_3 = "%4d-%.2d-%.2d %.2d:%.2d"
        $string_4 = "%d*%sMHz"
        $string_5 = "Win7"
        $string_6 = "Shellex"
        $string_7 = "%s%s%s%s%s%s"
        $string_8 = "AVtype_info"
    condition:
        uint16(0) == 0x5A4D and 6 of them and filesize < 300KB
}