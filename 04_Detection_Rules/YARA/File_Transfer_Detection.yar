rule File_Transfer_Detection
{
    meta:
        description = "Detects files that might have been transferred via messengers, copied to USB devices, or transferred through various methods such as FTP or cloud storage."
        author = "And"
        category = "file transfer"
        created = "2024-09-17"

    strings:
        // Действия по передаче данных через мессенджеры
        $messengerTransfer = "Telegram|WhatsApp|Skype|Viber|Zoom|Slack|Signal Messenger|Discord|Facebook Messenger|Microsoft Teams" ascii wide

        // Действия по копированию данных на USB
        $usbCopy = "USBSTOR\\Disk|copy to USB|removable storage" ascii wide

        // Передача файлов через другие методы
        $fileTransferMethods = "ftp|sftp|scp|rsync|upload to cloud|cloud storage" ascii wide
        $cloudServices = "Dropbox|Google Drive|OneDrive|Yandex Disk|Box" ascii wide

        // Форматы передаваемых файлов
        $fileFormats = /\.(jpg|jpeg|png|gif|pdf|doc|docx|xls|xlsx|ppt|pptx|zip|rar|7z|tar|gz|mp3|mp4|avi|mkv)\b/ ascii wide

    condition:
        any of ($messengerTransfer, $usbCopy, $fileTransferMethods, $cloudServices) and
        $fileFormats
}
