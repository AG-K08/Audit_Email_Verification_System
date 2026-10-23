rule SpywareAdvancedDetection
{
    meta:
        description = "Detects advanced spyware behaviors with file checks"
        author = "And"
        category = "spyware"
        created = "2024-09-17"
        reliability = 90

    strings:
        $userInfo = "username" ascii wide
        $age = "age" ascii wide
        $gender = "gender" ascii wide
        $location = /geoloc(ation)?/ ascii wide
        $interests = "interests" ascii wide
        $habits = "habits" ascii wide
        $password = /passw(or)?d|credentials/i ascii wide
        $login = "login" ascii wide
        $banking = "bankaccount" ascii wide
        $copyDocs = "CopyFile" ascii wide
        $docs = "document" ascii wide
        $photos = "photo" ascii wide
        $videos = "video" ascii wide
        $hook = "SetWindowsHookEx" ascii wide
        $getKeys = "GetAsyncKeyState" ascii wide
        $keylogger = "keylogger" ascii wide
        $screenshot1 = "BitBlt" ascii wide
        $screenshot2 = "GetDC" ascii wide
        $screenshot3 = "CreateCompatibleDC" ascii wide
        $runRegistry = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $runServices = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide
        $startup = "Startup\\Programs" ascii wide
        $taskScheduler = "TaskScheduler" ascii wide
        $autoRun = "autorun.inf" ascii wide
        $setAutoStart = "SetAutoStart" ascii wide
        $sendData = /send (data|spam) to server|email spam server/i ascii wide

    condition:
        uint16(0) == 0x5A4D and filesize < 1MB and (
            3 of ($userInfo, $age, $gender, $location, $interests, $habits) or
            2 of ($password, $login, $banking) or
            ($copyDocs and (2 of ($docs, $photos, $videos) or $sendData)) or
            2 of ($hook, $getKeys, $keylogger) or
            2 of ($screenshot1, $screenshot2, $screenshot3) or
            any of ($runRegistry, $runServices, $startup, $taskScheduler, $autoRun, $setAutoStart) or
            $sendData
        )
}