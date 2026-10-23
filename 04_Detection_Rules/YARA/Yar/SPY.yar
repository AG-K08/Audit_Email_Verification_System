rule SpywareAdvancedDetection
{
    meta:
        description = "Detects advanced spyware behaviors including personal data collection, keylogging, screenshots, credential theft, and persistence mechanisms"
        author = "And"
        category = "spyware"
        created = "2024-09-17"
        reliability = 85

    strings:
        // Перехват личных данных
        $userInfo = "username" ascii wide
        $age = "age" ascii wide
        $gender = "gender" ascii wide
        $location = "geolocation" ascii wide
        $interests = "interests" ascii wide
        $habits = "habits" ascii wide

        // Перехват логинов и паролей
        $password1 = "password" ascii wide
        $password2 = "credentials" ascii wide
        $login = "login" ascii wide
        $banking = "bankaccount" ascii wide

        // Копирование файлов
        $copyDocs = "CopyFile" ascii wide
        $docs = "document" ascii wide
        $photos = "photo" ascii wide
        $videos = "video" ascii wide

        // Keylogger
        $hook = "SetWindowsHookEx" ascii wide
        $getKeys = "GetAsyncKeyState" ascii wide
        $keylogger = "keylogger" ascii wide

        // Отслеживание активности
        $browserHistory = "browser history" ascii wide
        $installedApps = "installed applications" ascii wide
        $trackWebsites = "track websites" ascii wide

        // Снятие скриншотов
        $screenshot1 = "BitBlt" ascii wide
        $screenshot2 = "GetDC" ascii wide
        $screenshot3 = "CreateCompatibleDC" ascii wide

        // Поиск по ключевым словам
        $searchKeywords = "search for keywords" ascii wide
        $keyword1 = "password" ascii wide
        $keyword2 = "account" ascii wide
        $keyword3 = "login" ascii wide
        $keyword4 = "email" ascii wide

        // Управление устройством
        $camera = "StartCamera" ascii wide
        $microphone = "StartMicrophone" ascii wide
        $sms = "SendSMS" ascii wide
        $call = "MakeCall" ascii wide
        $installMalware = "InstallMalware" ascii wide

        // Передача данных
        $sendData = "send data to server" ascii wide
        $spam = "send spam" ascii wide
        $spamServer = "email spam server" ascii wide

        // Способы закрепления (Persistence)
        $runRegistry = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii wide
        $runServices = "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunServices" ascii wide
        $startup = "Startup\\Programs" ascii wide
        $taskScheduler = "TaskScheduler" ascii wide
        $autoRun = "autorun.inf" ascii wide
        $setAutoStart = "SetAutoStart" ascii wide

    condition:
        uint16(0) == 0x5A4D and (3 of ($userInfo, $age, $gender, $location, $interests, $habits) or
        2 of ($password1, $password2, $login, $banking) or
        2 of ($copyDocs, $docs, $photos, $videos) or
        3 of ($hook, $getKeys, $keylogger) or
        2 of ($browserHistory, $installedApps, $trackWebsites) or
        2 of ($screenshot1, $screenshot2, $screenshot3) or
        2 of ($searchKeywords, $keyword1, $keyword2, $keyword3, $keyword4) or
        2 of ($camera, $microphone, $sms, $call, $installMalware) or
        2 of ($sendData, $spam, $spamServer) or
        any of ($runRegistry, $runServices, $startup, $taskScheduler, $autoRun, $setAutoStart))
}
