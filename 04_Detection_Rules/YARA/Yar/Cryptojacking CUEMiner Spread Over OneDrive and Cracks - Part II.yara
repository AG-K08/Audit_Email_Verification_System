rule Cryptojacking_CUEMinerCpp {
meta:
  description = "Rule to detect v3.x CUEMiner"
  author = "Kaspersky"
  copyright = "Kaspersky"
  distribution = "DISTRIBUTION IS FORBIDDEN. DO NOT UPLOAD TO ANY MULTISCANNER OR SHARE ON ANY THREAT INTEL PLATFORM"
  version = "1.0"
  last_modified = "2023-02-13"

strings:
  $exitRet = { 48 83 ec 28 e8 ?? ?? 00 00 48 85 c0 0f 94 c0 0f b6 c0 f7 d8 48 83 c4 28 c3 }
  $minGW = "GCC: (x86_64-win32-seh-rev0, Built by MinGW-W64 project) 12.2.0"
  $ntdl_compare = { 41 81 f8 6e 74 64 6c }

condition:
  uint16(0) == 0x5a4d and uint32(uint32(0x3c)) == 0x00004550 and
  filesize < 4000000 and 
  filesize > 250000 and 
  all of them
}
