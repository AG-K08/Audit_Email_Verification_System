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
        $storage = "MTP|SD CARD|cloud storage|zip|copy|send|rename" ascii wide
        $fileTransfer = "ftp|sftp|scp|rsync|POST /upload" ascii wide
        $emailAttach = /attach.*\.(jpg|png|pdf|docx?)\b/ ascii wide

        // Мессенджеры и приложения
        $messengers = "Telegram|WhatsApp|Skype|Viber|Zoom|Slack|Signal Messenger|Discord|Facebook Messenger|Microsoft Teams" ascii wide

        // Программы для удаленного подключения и браузеры
        $remoteConnect = "TeamViewer|AnyDesk|AeroAdmin|Tor Browser|Mozilla Firefox|Chrome|Edge|Opera|Safari" ascii wide

        // Необычные действия администратора
        $adminActions = "SeDebugPrivilege|net user|schtasks|remote desktop" ascii wide

        // Подозрительные сетевые подключения
        $network = "VPN|Tor|proxy|connect to external IP" ascii wide

        // Действия по сохранению данных
        $saveActions = "Save As|Save|save dialog" ascii wide

        // Исключения для Kaspersky
        $kaspersky = "Kaspersky|kav|kaspersky antivirus|kaspersky internet security|Kaspersky Security Cloud" ascii wide

    condition:
        any of ($usb, $storage, $fileTransfer, $emailAttach, $messengers, $remoteConnect, $adminActions, $network, $saveActions) and
        not any of ($kaspersky)
}
