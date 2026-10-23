rule VPN_Proxy_SoftwareDetection
{
    meta:
        author = "Assistant"
        description = "Detects VPN and proxy software based on file signatures"
        date = "2025-01-11"

    strings:
        // OpenVPN
        $openvpn_sig = { 4F 70 65 6E 56 50 4E 20 76 65 72 73 69 6F 6E }

        // WireGuard
        $wireguard_sig = { 57 69 72 65 47 75 61 72 64 20 56 50 4E }

        // Shadowsocks
        $shadowsocks_sig = { 73 68 61 64 6F 77 73 6F 63 6B 73 }

        // Proxychains
        $proxychains_sig = { 70 72 6F 78 79 63 68 61 69 6E 73 }

        // SOCKS proxy
        $socks_proxy_sig = { 53 4F 43 4B 53 35 }

        // L2TP/IPsec VPN
        $l2tp_ipsec_sig = { 4C 32 54 50 20 49 50 53 65 63 }

        // PPTP VPN
        $pptp_sig = { 50 50 54 50 20 56 50 4E }

        // Common VPN software
        $nordvpn_sig = { 4E 6F 72 64 56 50 4E }
        $expressvpn_sig = { 45 78 70 72 65 73 73 56 50 4E }
        $cyberghost_sig = { 43 79 62 65 72 47 68 6F 73 74 }
        $surfshark_sig = { 53 75 72 66 73 68 61 72 6B }

        // Additional VPN software
        $vpn_unlimited_sig = { 56 50 4E 20 55 6E 6C 69 6D 69 74 65 64 }
        $private_internet_access_sig = { 50 72 69 76 61 74 65 20 49 6E 74 65 72 6E 65 74 20 41 63 63 65 73 73 }
        $protonvpn_sig = { 50 72 6F 74 6F 6E 56 50 4E }
        $hotspot_shield_sig = { 48 6F 74 73 70 6F 74 20 53 68 69 65 6C 64 }
        $hidemyass_sig = { 48 69 64 65 4D 79 41 73 73 }
        $ivacyvpn_sig = { 49 76 61 63 79 20 56 50 4E }
        $purevpn_sig = { 50 75 72 65 56 50 4E }
        $strongvpn_sig = { 53 74 72 6F 6E 67 56 50 4E }
        $vpn_gate_sig = { 56 50 4E 20 47 61 74 65 }
        $torguard_sig = { 54 6F 72 47 75 61 72 64 }

        // Additional Proxy software
        $proxifier_sig = { 50 72 6F 78 69 66 69 65 72 }
        $ultrasurf_sig = { 55 6C 74 72 61 53 75 72 66 }
        $kproxy_sig = { 4B 50 72 6F 78 79 }
        $zenmate_sig = { 5A 65 6E 4D 61 74 65 }

        // Additional VPN services
        $windscribe_sig = { 57 69 6E 64 53 63 72 69 62 65 }
        $mullvad_sig = { 4D 75 6C 6C 76 61 64 }
        $vyprvpn_sig = { 56 79 70 72 56 50 4E }
        $ipvanish_sig = { 49 50 56 61 6E 69 73 68 }
        $tunnelbear_sig = { 54 75 6E 6E 65 6C 42 65 61 72 }
        $betternet_sig = { 42 65 74 74 65 72 6E 65 74 }
        $psiphon_sig = { 50 73 69 70 68 6F 6E }
        $lantern_sig = { 4C 61 6E 74 65 72 6E }
        $freedome_sig = { 46 72 65 65 64 6F 6D 65 }
        $opera_vpn_sig = { 4F 70 65 72 61 20 56 50 4E }

        // Additional Proxy services
        $tor_browser_sig = { 54 6F 72 20 42 72 6F 77 73 65 72 }
        $privoxy_sig = { 50 72 69 76 6F 78 79 }
        $squid_proxy_sig = { 53 71 75 69 64 20 50 72 6F 78 79 }
        $ccproxy_sig = { 43 43 50 72 6F 78 79 }
        $3proxy_sig = { 33 50 72 6F 78 79 }

    condition:
        any of ($openvpn_sig, $wireguard_sig, $shadowsocks_sig, $proxychains_sig, $socks_proxy_sig, 
                $l2tp_ipsec_sig, $pptp_sig, $nordvpn_sig, $expressvpn_sig, $cyberghost_sig, $surfshark_sig,
                $vpn_unlimited_sig, $private_internet_access_sig, $protonvpn_sig, $hotspot_shield_sig, 
                $hidemyass_sig, $ivacyvpn_sig, $purevpn_sig, $strongvpn_sig, $vpn_gate_sig, $torguard_sig,
                $proxifier_sig, $ultrasurf_sig, $kproxy_sig, $zenmate_sig, $windscribe_sig, $mullvad_sig,
                $vyprvpn_sig, $ipvanish_sig, $tunnelbear_sig, $betternet_sig, $psiphon_sig, $lantern_sig,
                $freedome_sig, $opera_vpn_sig, $tor_browser_sig, $privoxy_sig, $squid_proxy_sig, $ccproxy_sig,
                $3proxy_sig)
}