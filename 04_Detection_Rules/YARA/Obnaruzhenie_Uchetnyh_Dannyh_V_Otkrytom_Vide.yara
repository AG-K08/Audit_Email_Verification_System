rule HEUR_Credential_Scanner_Generic
{
    meta:
        author      = "And"
        type        = "Heuristic"
        description = "Обнаруживает потенциальные учетные данные (имена пользователей, пароли, ключи API) в открытом виде, включая обфусцированные (Base64, XOR)."
        date        = "2025-07-24"
        version     = "1.2"
        reference   = "Адаптировано на основе предоставленного пользователем правила"
        tactic      = "Credential Access"
        technique   = "T1552: Unsecured Credentials"

    strings:
        // --- 1. Ключевые слова, связанные с идентификацией пользователя ---
        $user_kw1 = "username" fullword ascii wide nocase
        $user_kw2 = "user" fullword ascii wide nocase
        $user_kw3 = "login" fullword ascii wide nocase
        $user_kw4 = "account" fullword ascii wide nocase
        $user_kw5 = "userid" fullword ascii wide nocase

        // --- 2. Ключевые слова, связанные с паролями и секретами ---
        $pass_kw1 = "password" fullword ascii wide nocase
        $pass_kw2 = "pass" fullword ascii wide nocase
        $pass_kw3 = "pwd" fullword ascii wide nocase
        $pass_kw4 = "secret" fullword ascii wide nocase
        $pass_kw5 = "token" fullword ascii wide nocase
        $pass_kw6 = "api_key" fullword ascii wide nocase
        $pass_kw7 = "passwd" fullword ascii wide nocase

        // --- 3. Регулярное выражение для пар ключ=значение (Высокая достоверность) ---
        $re_credential_pair = /(password|pass|pwd|secret|token|api_key|passwd)\s*[:=]\s*["']?([A-Za-z0-9\._\-%+@!#$^&*()]{6,})["']?/ nocase wide ascii

        // --- 4. Обнаружение закодированных учетных данных (Высокая достоверность) ---
        $b64_pass = "password" base64 wide
        $b64_secret = "secret" base64 wide
        $xor_pass = "password" xor(0x01-0xff) wide

    condition:
        // Ограничение по размеру файла для производительности
        filesize < 10MB and
        (
            // --- Сценарий 1: Высокая достоверность ---
            // Срабатывание на явные пары ключ=значение или закодированные строки
            $re_credential_pair or
            1 of ($b64*) or
            $xor_pass
            or
            // --- Сценарий 2: Средняя достоверность ---
            // Срабатывание, если найдено несколько ключевых слов для пользователя и пароля.
            // Это более производительная альтернатива проверке близости.
            (2 of ($user_kw*) and 2 of ($pass_kw*))
        )
}