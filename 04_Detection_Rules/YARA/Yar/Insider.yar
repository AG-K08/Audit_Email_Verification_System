rule Insider_Threat_Detection
{
    meta:
        description = "Detects potential insider threat activities, including data leakage, unusual admin actions, large file transfers, and suspicious network connections."
        author = "And"
        category = "insider threat"
        created = "2024-09-17"

    strings:
        // Действия по передаче данных
        $usb = "USBSTOR\\Disk" ascii wide
        $phone = "MTP" ascii wide
        $sdcard = "SD CARD" ascii wide
        $fileCopy = "copy" ascii wide
        $ftp = "ftp" ascii wide
        $sftp = "sftp" ascii wide
        $scp = "scp" ascii wide
        $rsync = "rsync" ascii wide
        $emailAttach = /attach.*\.(jpg|png|pdf|docx?)\b/ ascii wide
        $cloud = "cloud storage" ascii wide
        $archive = "zip" ascii wide
        $sendFiles = "send" ascii wide
        $rename = "rename" ascii wide
        $archiveBeforeCopy = "zip" ascii wide

        // Мессенджеры и приложения
        $messengers = "Allo|AltSuite|amo|amoCRM|BlackBerry Messenger|Bleep|CA Flowdock|Chanty|Chat2Desk|Cisco Spark|dialog|Discord|Duo|Facebook|Facebook Messenger|FireChat|Fleep|Flock|Gitter|Google Allo|Google Chat|Google Talk|GroupMe|Hangouts|Hangouts Google|Hipolink|ICQ|iMessage|Instagram|Instaplus.pro|Intranetus|iSendSMS|KakaoTalk|Lark|Line|LiveTex|Mail.Ru|Mail.Ru Агент|MDC|Messenger|Microsoft Teams|OK|ooVoo|Outlook|Pamela|Pibox Music|Pidgin|Pinngle|QARM|QIP|QQ mobile|RaidCall|Sameroom|Signal Messenger|Skype|Slack|Smarty CRM|SMMBOT.net|Smooch|Snapchat|Staply|tada.team|talkSpirit|TamTam|TeamSpeak|Teamwork Chat|Telegram|Teletype|Threema|TikTok|tlk.io|Trillian|Twist|Twitter|Typetalk|Veon|Viber|VIPole|WeChat|WhatsApp|Yamichat|Zoho Cliq|Zoom|ДругВокруг|МойОфис Логос|Одноклассники|Сибрус|ТамТам|Яндекс.Мессенджер|WinMail.exe|Windows Mail" ascii wide

        // Программы для удаленного подключения
        $remoteConnect = "TeamViewer|AnyDesk|AeroAdmin" ascii wide

        // Браузеры
        $browsers = "1st Browser|360 Extreme Explorer|Airfox|Alienforce|Amigo|AOL Desktop|Arora|Aurora Browser|Avant Browser|Avira Scout|Brave|Browser Select|Chromium|CLIQZ|Columbus Web Bro...|CoolNovo|CyberDragon|Cyberfox|Globus Privacy Bro...|IceCat|Internet Explorer|Iridium Browser|K-Browser|Lunascape|Maelstrom|Maxthon MX6|Microsoft Edge|Mozilla Firefox|Neuron|OhHai Browser|Opera|Orbitum|Oxy Browser|Pampa Browser|PirateSnoop|qutebrowser|Safari|Sandcat|Secure Browser|Superbird|Titan Browser|Tor Browser|UR Browser|YRC Weblink|ZipZap|амблер-Браузер|Гогуль|Рамблер-Браузер|Яндекс Браузер" ascii wide

        // Необычные действия администратора
        $privEsc = "SeDebugPrivilege" ascii wide
        $userAdd = "net user" ascii wide
        $taskSchedule = "schtasks" ascii wide
        $remoteControl = "remote desktop" ascii wide

        // Большие файлы и сетевые ресурсы
        $httpPost = "POST /upload" ascii wide
        $cloudStorage = "cloud storage" ascii wide

        // Подозрительные сетевые подключения
        $externalIP = "connect to external IP" ascii wide
        $vpn = "VPN" ascii wide
        $tor = "Tor" ascii wide
        $proxy = "proxy" ascii wide

        // Действия по сохранению данных
        $saveAs = "Save As" ascii wide
        $save = "Save" ascii wide
        $dialogSave = "save dialog" ascii wide

        // Исключения для Kaspersky
        $kaspersky = "Kaspersky|kav|kaspersky antivirus|kaspersky internet security|Kaspersky Security Cloud" ascii wide

    condition:
        any of ($usb, $phone, $sdcard, $fileCopy, $ftp, $sftp, $scp, $rsync, $emailAttach, $cloud, $archive, $sendFiles, $rename, $archiveBeforeCopy, $messengers, $remoteConnect, $browsers, $privEsc, $userAdd, $taskSchedule, $remoteControl, $httpPost, $cloudStorage, $externalIP, $vpn, $tor, $proxy, $saveAs, $save, $dialogSave) and
        not any of ($kaspersky)
}
