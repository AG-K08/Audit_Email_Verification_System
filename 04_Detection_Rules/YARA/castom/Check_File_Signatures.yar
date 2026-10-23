rule Check_File_Signatures {
    meta:
        description = "Проверка корректности сигнатур файлов разных форматов"
        author = "Ваше имя"
        date = "2024-10-16"
        version = "1.2"

    strings:
        // Документы и офисные файлы
        $docx_xlsx_pptx = { 50 4B 03 04 }           // DOCX, XLSX, PPTX (ZIP-based)
        $doc_old = { D0 CF 11 E0 A1 B1 1A E1 }      // DOC, XLS, PPT (старый формат)
        $pdf = { 25 50 44 46 2D }                   // PDF
        $rtf = { 7B 5C 72 74 66 }                   // RTF
        $oxps = { 4F 58 50 53 }                     // OXPS
        $txt_utf8 = { EF BB BF }                    // UTF-8 BOM (TXT)

        // Архивы
        $zip = { 50 4B 03 04 }                      // ZIP
        $rar = { 52 61 72 21 1A 07 00 }             // RAR
        $gzip = { 1F 8B }                           // GZIP
        $tar = { 75 73 74 61 72 }                   // TAR (ustar)
        $bz2 = { 42 5A 68 }                         // BZ2
        $cab = { 4D 53 43 46 }                      // CAB
        $arj = { 60 EA }                            // ARJ
        $bkp = { 42 4B 50 }                         // BKP
        $7z = { 37 7A BC AF 27 1C }                 // 7z

        // Изображения
        $jpeg = { FF D8 FF }                        // JPEG
        $png = { 89 50 4E 47 0D 0A 1A 0A }          // PNG
        $bmp = { 42 4D }                            // BMP
        $gif = { 47 49 46 38 }                      // GIF
        $tiff = { 49 49 2A 00 } or { 4D 4D 00 2A }  // TIFF
        $ico = { 00 00 01 00 }                      // ICO
        $psd = { 38 42 50 53 }                      // PSD
        $webp = { 52 49 46 46 ?? ?? ?? ?? 57 45 42 50 } // WebP
        $heic = { 00 00 00 ?? 66 74 79 70 68 65 69 63 } // HEIC
        $heif = { 00 00 00 ?? 66 74 79 70 68 65 69 66 } // HEIF
        $avif = { 00 00 00 ?? 66 74 79 70 61 76 69 66 } // AVIF

        // Аудио/видео файлы
        $mp3 = { 49 44 33 }                         // MP3
        $mp4 = { 66 74 79 70 69 73 6F 6D } or { 66 74 79 70 6D 70 34 32 } // MP4
        $avi = { 52 49 46 46 ?? ?? ?? ?? 41 56 49 20 } // AVI
        $wav = { 52 49 46 46 ?? ?? ?? ?? 57 41 56 45 } // WAV
        $flac = { 66 4C 61 43 }                     // FLAC
        $webm = { 1A 45 DF A3 }                     // WebM
        $mov = { 00 00 00 14 66 74 79 70 71 74 }    // MOV
        $mkv = { 1A 45 DF A3 }                      // MKV

        // Почта и базы данных
        $pst = { 21 42 44 4E }                      // PST/OST
        $dbf = { 03 }                               // DBF
        $eml = { 46 72 6F 6D }                      // EML
        $msg = { D0 CF 11 E0 }                      // MSG
        $idx = { 00 01 00 00 }                      // IDX

        // Исполняемые файлы и библиотеки
        $exe_dll = { 4D 5A }                        // EXE, DLL (Windows)
        $elf = { 7F 45 4C 46 }                      // ELF (Linux)
        $macho = { FE ED FA CE } or { CE FA ED FE } // Mach-O (macOS)

        // Текстовые форматы
        $xml = { 3C 3F 78 6D 6C }                   // XML
        $html = { 3C 68 74 6D 6C }                  // HTML
        $json = { 7B 22 }                           // JSON
        $yaml = { 23 79 61 6D 6C }                  // YAML
        $csv = { 2C }                               // CSV
        $sql = { 44 52 4F 50 }                      // SQL
        $php = { 3C 3F 70 68 70 }                   // PHP
        $python = { 23 21 2F 75 73 72 2F 62 69 6E 2F 70 79 74 68 6F 6E } // Python
        $javascript = { 2F 2A 2A }                  // JavaScript
        $css = { 40 69 6D 70 6F 72 74 }             // CSS

        // Шрифты
        $ttf = { 00 01 00 00 00 }                   // TTF
        $otf = { 4F 54 54 4F }                      // OTF
        $woff = { 77 4F 46 46 }                     // WOFF
        $woff2 = { 77 4F 46 32 }                    // WOFF2
        $eot = { 4C 50 }                            // EOT

    condition:
        any of them
}