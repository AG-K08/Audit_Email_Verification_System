rule Backdoored_ssh: CrouchingYeti
{
meta:

    report        = "CrouchingYeti server-side activity analysis"
    description   = "Rule to detect backdoored ssh"
    hash          = "9f08509f2f6a989a2cf19ce1d38f61ec"
    hash          = "864bf4389f1a049784b22b889a9daba9"
    author        = "Kaspersky Lab"
    copyright     = "Kaspersky Lab"
    distribution  = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
    version       = "1.0"
    date          = "2017-12-15"
    last_modified = "2017-12-15"

strings:

    $a1 = "OpenSSH" 
    $a2 = "usage: ssh"
    $a3 = "HISTFILE"
    
    $b1 = "sEIkbT307kB/Z6AwFLuuc0" 
    $b2 = "/var/tmp/.pipe.sock"
    $b3 = {43 AC 12 99 5F 9B 23 09 67 FA 13 06 B3 D8 E3 FF 10 21 C9 E1 EE 92 F3 0C}

condition:

    uint32(0) == 0x464c457f and filesize<1000000 and (all of ($a*) or any of ($b*))
}



