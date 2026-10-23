rule ValuableFileExtensions : suspect {
    meta:
        category = "destruction"
        description = "embeds a list of file extensions often targeted by ransomware, with malicious context"
        author = "malcat"
        reliability = 40

    strings:
        // Популярные расширения файлов, часто используемые ransomware
        $ext1 = "csv" ascii wide fullword
        $ext2 = "ps1" ascii wide fullword
        $ext3 = "backup" ascii wide fullword
        $ext4 = "pdf" ascii wide fullword
        $ext5 = "docx" ascii wide fullword
        $ext6 = "xlsx" ascii wide fullword
        $ext7 = "jpg" ascii wide fullword
        $ext8 = "zip" ascii wide fullword
        $ext9 = "sql" ascii wide fullword
        $ext10 = "vmdk" ascii wide fullword

        // Контекст, указывающий на ransomware
        $ransom1 = "encrypted" ascii wide fullword
        $ransom2 = "decrypt" ascii wide fullword
        $ransom3 = "ransomware" ascii wide fullword
        $ransom4 = "pay" ascii wide fullword
        $ransom5 = ".onion" ascii wide

    condition:
        5 of ($ext*) and 1 of ($ransom*)
}