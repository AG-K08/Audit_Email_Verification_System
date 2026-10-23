rule malware_ua_ITARMY_ddos
{
meta:
    hash = "1ECAFBCC7187740E037462B312181319"
    hash = "E88DAC291E0442AFAAF474B352D9028C"
    hash = "DFD9BBC24F46EE0E1F69623308126CAD"
    author = "Kaspersky ICS CERT"
    copyright = "Kaspersky"
    description = "Rule to detect DDoS shell scripts from IT ARMY of Ukraine"
    version = "1.0"
    last_modified = "2022-11-01"

strings:
    $a1 = "CONST_ONE=1"
    $a2 = "line_no=0"
    $a3 = /wget -T [0-9]+.[0-9]+ -t [0-9]+ \$LINE/

    $b = "for (( c=$TIMER; c>0; c-- ))"
    
    $c1 = "./dosilka.sh < list"
    $c2 = "www.notwar.ho.ua"
    $c3 = "playforukraine.live"
    $c4 = "tours.testforstudio.com"
    $c5 = "russianwarshipgofuckyourself.club"

condition:
    (all of ($a*)) or ($b and (any of ($c*)))
}
