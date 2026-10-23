rule BrowserExtension_Mining {
    meta:
        description = "Detects browser extensions potentially used for cryptocurrency mining"
        author = "Your Name"
        date = "2023-10-01"
        reference = "https://example.com/reference"

    strings:
        $miner_js = /.*(coinhive|cryptonight|xmrig|monero).*/ nocase
        $miner_url = /.*(coinhive\.com|cryptonight\.net|xmrig\.com|monero\.org).*/ nocase
        $miner_api = /.*(startMining|stopMining|getHashesPerSecond).*/ nocase
        $miner_config = /.*(miner\.start|miner\.stop|miner\.config).*/ nocase
        $miner_strings = { "miner", "cryptonight", "coinhive", "xmrig", "monero" }

    condition:
        filesize < 1MB and
        (
            $miner_js or
            $miner_url or
            $miner_api or
            $miner_config or
            any of ($miner_strings)
        )
}