import "pe"

rule MAL_HERMETIC_WIPER {
    meta:
      desc = "Hermetic Wiper - broad hunting rule"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "02.23.2022"
      hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
    strings:
        $string1 = "DRV_XP_X64" wide ascii nocase
        $string2 = "EPMNTDRV\\%u" wide ascii nocase
        $string3 = "PhysicalDrive%u" wide ascii nocase
        $cert1 = "Hermetica Digital Ltd" wide ascii nocase
    condition:
      uint16(0) == 0x5A4D and
      all of them
}

rule MAL_PARTY_TICKET {
    meta:
      desc = "PartyTicket / HermeticRansom Golang Ransomware - associated with HermeticWiper campaign"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "02.24.2022"
      hash = "4dc13bb83a16d4ff9865a51b3e4d24112327c526c1392e14d56f20d6f4eaf382"
      reference = "https://twitter.com/juanandres_gs/status/1496930731351805953"
    strings:
        $string1 = "/403forBiden/" wide ascii nocase
        $string2 = "/wHiteHousE/" wide ascii 
        $string3 = "vote_result." wide ascii
        $string4 = "partyTicket." wide ascii
        $buildid1 = "Go build ID: \"qb0H7AdWAYDzfMA1J80B/nJ9FF8fupJl4qnE4WvA5/PWkwEJfKUrRbYN59_Jba/2o0VIyvqINFbLsDsFyL2\"" wide ascii
        $project1 = "C:/projects/403forBiden/wHiteHousE/" wide ascii
    condition:
      uint16(0) == 0x5A4D and
      (2 of ($string*) or 
        any of ($buildid*) or 
        any of ($project*))
}

rule MAL_COMPROMISED_HERMETICA_CERT  {
    meta:
      desc = "Hermetica Cert - broad hunting rule based on the certificate used in HermeticWiper and HermeticWizard"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "03.01.2022"
      hash = "1bc44eef75779e3ca1eefb8ff5a64807dbc942b1e4a2672d77b9f6928d292591"
      reference = "https://www.sentinelone.com/labs/hermetic-wiper-ukraine-under-attack/"
    condition:
      uint16(0) == 0x5a4d and
      for any i in (0 .. pe.number_of_signatures) : (
         pe.signatures[i].issuer contains "DigiCert EV Code Signing CA" and
         pe.signatures[i].serial == "0c:48:73:28:73:ac:8c:ce:ba:f8:f0:e1:e8:32:9c:ec"
      )
}

rule MAL_ISSAC_WIPER {
    meta:
      desc = "Issac Wiper - broad hunting rule"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "03.01.2022"
      hash = "13037b749aa4b1eda538fda26d6ac41c8f7b1d02d83f47b0d187dd645154e033"
      reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
    strings:
        $name1 = "Cleaner.dll" wide ascii
        $name2 = "cl.exe" wide ascii nocase
        $name3 = "cl64.dll" wide ascii nocase
        $name4 = "cld.dll" wide ascii nocase
        $name5 = "cll.dll" wide ascii nocase
        $name6 = "Cleaner.exe" wide ascii
        $export = "_Start@4" wide ascii
    condition:
      uint16(0) == 0x5A4D and
      (any of ($name*) and $export)
}

rule MAL_HERMETIC_WIZARD {
    meta:
      desc = "HermeticWizard hunting rule"
      author = "Hegel @ SentinelLabs"
      version = "1.0"
      last_modified = "03.01.2022"
      reference = "https://www.welivesecurity.com/2022/03/01/isaacwiper-hermeticwizard-wiper-worm-targeting-ukraine/"
    strings:
        $name1 = "Wizard.dll" wide ascii
        $name2 = "romance.dll" wide ascii
        $name3 = "exec_32.dll" wide ascii
        $function1 = "DNSGetCacheDataTable" wide ascii
        $function2 = "GetIpNetTable" wide ascii
        $function3 = "WNetOpenEnumW" wide ascii
        $function4 = "NetServerEnum" wide ascii
        $function5 = "GetTcpTable" wide ascii
        $function6 = "GetAdaptersAddresses" wide ascii
        $function7 = "GetEnvironmentStrings" wide ascii
        $ip_anchor1 = "192.168.255.255" wide ascii
    condition:
      uint16(0) == 0x5A4D and
      (any of ($function*) and any of ($name*) and $ip_anchor1)
}
