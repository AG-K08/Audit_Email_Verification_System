rule Crimeware_RU_ATMProxy {
meta:
   copyright = "Kaspersky Lab"
   description = "Rule to detect atmproxy samples"
   last_modified = "2017-06-29 10:29:00"
   hash = "DB3EA092ED1803018DFA2D830923DC91"
   version = "1.0"
   report = "ATMProxy - A new way to rob ATMs"
   distribution ="DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"

strings:
   $a1 = "NCR.APTRA.VPITCPIP.DLL" ascii    
   $a5 = "c:\\Program Files\\NCR APTRA\\Advance NDC\\Config\\TCPIPCommunicationsServiceConfig.xml" fullword wide
   $a6 = "Dispensed %d success. casseteIndex - %d, listNumber - %d, Amount - %d" fullword ascii
   $a7 = "Dispense failed - 0x%x. Index - %d, listNumber - %d, Amount - %d" fullword ascii
   $a8 = "c:\\Program Files\\NCR APTRA\\Advance NDC\\Debug\\MESSAGEIN0.log" fullword wide
   $a9 = "c:\\Program Files\\NCR APTRA\\Advance NDC\\Debug\\MESSAGEIN.log" fullword wide
   $a10 = "Dispense: casseteIndex - %d, listNumber - %d, Amount - %d" fullword ascii
   $a11 = "c:\\Program Files\\NCR APTRA\\SSS Runtime Core\\ulnmpr.exe" fullword wide
   $a12 = "c:\\Program Files\\NCR APTRA\\SSS Runtime Core\\ulnmin.exe" fullword wide
   $a13 = "c:\\Program Files\\NCR APTRA\\SSS Runtime Core\\ulnmin.log" fullword wide
   $a14 = "c:\\Program Files\\NCR APTRA\\SSS Runtime Core\\ulnmpr.log" fullword wide
  $a46 = "CurrencyDispenser1" fullword ascii  
   $a52 = "CurrencyID - %s" fullword ascii
   $a53 = "Item value - %d" fullword ascii
   $a54 = "Start WfsTest3" fullword ascii
   $a55 = "Packet patched" fullword ascii
   $a61 = "host2atm" fullword ascii
   $a62 = "atm2host" fullword ascii
   $a65 = "ndcterm" fullword wide
   $a66 = "ulnmpr" fullword wide

condition:
   uint16(0) == 0x5A4D and
   filesize < 5000000 and
   2 of them
}
