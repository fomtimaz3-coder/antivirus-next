/* GPL-2.0. Selected unchanged rules from Yara-Rules/rules malware/RANSOM_MS17-010_Wannacrypt.yar.
Selection by Anti-wiew, 2026-09-14. Original authors and references retained below. */

rule WannaCry_Ransomware {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (with the help of binar.ly)"
      reference = "https://goo.gl/HG2j5T"
      date = "2017-05-12"
      hash1 = "ed01ebfbc9eb5bbea545af4d01bf5f1071661840480439c6e5babe8e080e41aa"
   strings:
      $x1 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii
      $x2 = "taskdl.exe" fullword ascii
      $x3 = "tasksche.exe" fullword ascii
      $x4 = "Global\\MsWinZonesCacheCounterMutexA" fullword ascii
      $x5 = "WNcry@2ol7" fullword ascii
      $x6 = "www.iuqerfsodp9ifjaposdfjhgosurijfaewrwergwea.com" ascii
      $x7 = "mssecsvc.exe" fullword ascii
      $x8 = "C:\\%s\\qeriuwjhrf" fullword ascii
      $x9 = "icacls . /grant Everyone:F /T /C /Q" fullword ascii

      $s1 = "C:\\%s\\%s" fullword ascii
      $s2 = "<!-- Windows 10 --> " fullword ascii
      $s3 = "cmd.exe /c \"%s\"" fullword ascii
      $s4 = "msg/m_portuguese.wnry" fullword ascii
      $s5 = "\\\\192.168.56.20\\IPC$" fullword wide
      $s6 = "\\\\172.16.99.5\\IPC$" fullword wide

      $op1 = { 10 ac 72 0d 3d ff ff 1f ac 77 06 b8 01 00 00 00 }
      $op2 = { 44 24 64 8a c6 44 24 65 0e c6 44 24 66 80 c6 44 }
      $op3 = { 18 df 6c 24 14 dc 64 24 2c dc 6c 24 5c dc 15 88 }
      $op4 = { 09 ff 76 30 50 ff 56 2c 59 59 47 3b 7e 0c 7c }
      $op5 = { c1 ea 1d c1 ee 1e 83 e2 01 83 e6 01 8d 14 56 }
      $op6 = { 8d 48 ff f7 d1 8d 44 10 ff 23 f1 23 c1 }
   condition:
      uint16(0) == 0x5a4d and filesize < 10000KB and ( 1 of ($x*) and 1 of ($s*) or 3 of ($op*) )
}

rule WannaCry_Ransomware_Gen {
   meta:
      description = "Detects WannaCry Ransomware"
      author = "Florian Roth (based on rule by US CERT)"
      reference = "https://www.us-cert.gov/ncas/alerts/TA17-132A"
      date = "2017-05-12"
      hash1 = "9fe91d542952e145f2244572f314632d93eb1e8657621087b2ca7f7df2b0cb05"
      hash2 = "8e5b5841a3fe81cade259ce2a678ccb4451725bba71f6662d0cc1f08148da8df"
      hash3 = "4384bf4530fb2e35449a8e01c7e0ad94e3a25811ba94f7847c1e6612bbb45359"
   strings:
      $s1 = "__TREEID__PLACEHOLDER__" fullword ascii
      $s2 = "__USERID__PLACEHOLDER__" fullword ascii
      $s3 = "Windows for Workgroups 3.1a" fullword ascii
      $s4 = "PC NETWORK PROGRAM 1.0" fullword ascii
      $s5 = "LANMAN1.0" fullword ascii
   condition:
      uint16(0) == 0x5a4d and filesize < 5000KB and all of them
}

 rule wannacry_static_ransom : wannacry_static_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$mutex01 = "Global\\MsWinZonesCacheCounterMutexA" ascii

$lang01 = "m_bulgarian.wnr" ascii

$lang02 = "m_vietnamese.wnry" ascii

$startarg01 = "StartTask" ascii

$startarg02 = "TaskStart" ascii

$startarg03 = "StartSchedule" ascii

$wcry01 = "WanaCrypt0r" ascii wide

$wcry02 = "WANACRY" ascii

$wcry03 = "WANNACRY" ascii

$wcry04 = "WNCRYT" ascii wide

$forig01 = ".wnry\x00" ascii

$fvar01 = ".wry\x00" ascii

condition:

($mutex01 or any of ($lang*)) and ( $forig01 or all of ($fvar*) ) and any of ($wcry*) and any of ($startarg*)

}

rule wannacry_memory_ransom : wannacry_memory_ransom {

meta:

description = "Detects WannaCryptor spreaded during 2017-May-12th campaign and variants in memory"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "%08X.eky"

$s02 = "%08X.pky"

$s03 = "%08X.res"

$s04 = "%08X.dky"

$s05 = "@WanaDecryptor@.exe"

condition:

all of them

}

rule worm_ms17_010 : worm_ms17_010 {

meta:

description = "Detects Worm used during 2017-May-12th WannaCry campaign, which is based on ETERNALBLUE"

author = "Blueliv"

reference = "https://blueliv.com/research/wannacrypt-malware-analysis/"

date = "2017-05-15"

strings:

$s01 = "__TREEID__PLACEHOLDER__" ascii

$s02 = "__USERID__PLACEHOLDER__@" ascii

$s03 = "SMB3"

$s05 = "SMBu"

$s06 = "SMBs"

$s07 = "SMBr"

$s08 = "%s -m security" ascii

$s09 = "%d.%d.%d.%d"

$payloadwin2000_2195 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x32\x00\x31\x00\x39\x00\x35\x00\x00\x00"

$payload2000_50 =

"\x57\x00\x69\x00\x6e\x00\x64\x00\x6f\x00\x77\x00\x73\x00\x20\x00\x32\x00\x30\x00\x30\x00\x30\x00\x20\x00\x35\x00\x2e\x00\x30\x00\x00\x00"

condition:

all of them

}