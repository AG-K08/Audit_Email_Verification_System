rule ThemidaPacked_SectionName {
    meta:
        description = "Detects files packed with Themida based on section name"
        author = "Threat Analyst"
        date = "2025-07-23"
    strings:
        $section = ".themida" ascii wide
    condition:
        uint16(0) == 0x5A4D and $section in (0..1024)
}
