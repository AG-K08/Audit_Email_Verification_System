rule SuspiciousPowershellScript {
    meta:
        category = "suspicious activity"
        description = "Detects suspicious PowerShell script execution"
        author = "example"
        created = "2024-09-16"
        reliability = 80

    strings:
        $powershell = "powershell.exe" ascii wide fullword
        $encodedCommand = "-EncodedCommand" ascii wide fullword
        $bypass = "-ExecutionPolicy Bypass" ascii wide fullword
        $hidden = "-WindowStyle Hidden" ascii wide fullword
        $downloadString = "IEX(New-Object Net.WebClient).DownloadString" ascii wide
        $base64 = "Base64" ascii wide fullword
        $base64cmd = "base64" ascii wide fullword
        $encodedString = /[A-Za-z0-9+/=]{20,}/ ascii fullword // Common pattern for Base64 encoded strings
        $base64encode = "System.Text.Encoding::UTF8.GetString([System.Convert]::FromBase64String(" ascii wide fullword

    condition:
        $powershell and (1 of ($encodedCommand, $bypass, $hidden, $downloadString)) or
        (2 of ($base64, $base64cmd, $encodedString, $base64encode))
}
