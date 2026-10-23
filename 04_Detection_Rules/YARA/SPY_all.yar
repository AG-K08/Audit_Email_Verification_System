rule Spyware_DataCollection
{
    meta:
        description = "Detects spyware collecting personal data"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $userInfo = "username" ascii wide
        $age = "age" ascii wide
        $gender = "gender" ascii wide
        $location = "geolocation" ascii wide
        $interests = "interests" ascii wide
        $habits = "habits" ascii wide

    condition:
        uint16(0) == 0x5A4D and (3 of ($userInfo, $age, $gender, $location, $interests, $habits))
}

rule Spyware_CredentialTheft
{
    meta:
        description = "Detects spyware stealing credentials"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $password1 = "password" ascii wide
        $password2 = "credentials" ascii wide
        $login = "login" ascii wide
        $banking = "bankaccount" ascii wide

    condition:
        uint16(0) == 0x5A4D and (2 of ($password1, $password2, $login, $banking))
}

rule Spyware_FileTheft
{
    meta:
        description = "Detects spyware copying personal files"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $copyDocs = "CopyFile" ascii wide
        $docs = "document" ascii wide
        $photos = "photo" ascii wide
        $videos = "video" ascii wide

    condition:
        uint16(0) == 0x5A4D and (2 of ($copyDocs, $docs, $photos, $videos))
}

rule Spyware_Keylogger
{
    meta:
        description = "Detects keylogger activity"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $hook = "SetWindowsHookEx" ascii wide
        $getKeys = "GetAsyncKeyState" ascii wide
        $keylogger = "keylogger" ascii wide

    condition:
        uint16(0) == 0x5A4D and (2 of ($hook, $getKeys, $keylogger))
}

rule Spyware_ScreenshotCapture
{
    meta:
        description = "Detects spyware taking screenshots"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $screenshot1 = "BitBlt" ascii wide
        $screenshot2 = "GetDC" ascii wide
        $screenshot3 = "CreateCompatibleDC" ascii wide

    condition:
        uint16(0) == 0x5A4D and (2 of ($screenshot1, $screenshot2, $screenshot3))
}

rule Spyware_Persistence
{
    meta:
        description = "Detects spyware persistence mechanisms"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $runRegistry = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $runServices = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide
        $startup = "Startup\\Programs" ascii wide
        $taskScheduler = "TaskScheduler" ascii wide
        $autoRun = "autorun.inf" ascii wide
        $setAutoStart = "SetAutoStart" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($runRegistry, $runServices, $startup, $taskScheduler, $autoRun, $setAutoStart))
}

rule Spyware_DataTransmission
{
    meta:
        description = "Detects spyware transmitting stolen data"
        author = "And"
        category = "spyware"
        created = "2024-09-17"

    strings:
        $sendData = "send data to server" ascii wide
        $spam = "send spam" ascii wide
        $spamServer = "email spam server" ascii wide

    condition:
        uint16(0) == 0x5A4D and (any of ($sendData, $spam, $spamServer))
}
