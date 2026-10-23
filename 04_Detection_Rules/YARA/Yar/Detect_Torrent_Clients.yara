rule Detect_Torrent_Clients
{
    meta:
        description = "Detect common torrent clients based on filenames and paths"
        author = "AND"
        date = "2025-01-11"
        version = "1.0"

    strings:
        // Common torrent client executable names
        $media_get = "MediaGet.exe"
        $transmission = "transmission-qt.exe"
        $torrex_lite = "TorrexLite.exe"
        $soulseek = "SoulseekQt.exe"
        $emule = "emule.exe"
        $torrent_swapper = "TorrentSwapper.exe"
        $free_torrent = "FreeTorrent.exe"
        $shareaza = "Shareaza.exe"
        $ares_galaxy = "Ares.exe"
        $qbittorrent = "qbittorrent.exe"
        $bit_che = "BitChe.exe"
        $vuze = "Vuze.exe"
        $torrent_opener = "TorrentOpener.exe"
        $bittorrent = "bittorrent.exe"
        $utorrent = "utorrent.exe"
        $utorrent_alt = "µTorrent.exe"

        // Paths commonly used by torrent clients
        $path_media_get = "C:\\Program Files\\MediaGet\\"
        $path_qbittorrent = "C:\\Program Files\\qBittorrent\\"
        $path_utorrent = "C:\\Users\\%USERNAME%\\AppData\\Roaming\\uTorrent\\"
        $path_vuze = "C:\\Program Files\\Vuze\\"
        $path_shareaza = "C:\\Program Files\\Shareaza\\"
        $path_ares_galaxy = "C:\\Program Files\\Ares\\"

    condition:
        any of ($media_get, $transmission, $torrex_lite, $soulseek, $emule, $torrent_swapper, 
                $free_torrent, $shareaza, $ares_galaxy, $qbittorrent, $bit_che, $vuze, 
                $torrent_opener, $bittorrent, $utorrent, $utorrent_alt) or 
        any of ($path_media_get, $path_qbittorrent, $path_utorrent, $path_vuze, $path_shareaza, $path_ares_galaxy)
}
