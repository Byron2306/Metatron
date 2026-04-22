/*
   YARA Rules - Network Threat Signatures
   Seraph AI Security Platform
*/

rule C2_Cobalt_Strike_Beacon
{
    meta:
        description = "Detects Cobalt Strike beacon configuration patterns"
        author = "Seraph AI"
        severity = "critical"
        technique = "T1071"
    strings:
        $cs1 = { 00 01 00 00 00 ?? 00 00 00 }
        $cs2 = "beacon.dll" nocase
        $cs3 = "cobaltstrike" nocase
        $cs4 = "sleeptime" nocase
        $cs5 = "%s (admin)" nocase
        $cfg = { FC E8 8? 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
    condition:
        any of them
}

rule Metasploit_Meterpreter
{
    meta:
        description = "Detects Metasploit Meterpreter shellcode patterns"
        author = "Seraph AI"
        severity = "critical"
        technique = "T1059"
    strings:
        $m1 = "meterpreter" nocase
        $m2 = "metasploit" nocase
        $m3 = "msf" nocase
        $m4 = { FC E8 89 00 00 00 60 89 E5 31 D2 64 8B 52 30 }
        $m5 = "upload" nocase
        $m6 = "download" nocase
        $m7 = "getsystem" nocase
    condition:
        ($m1 or $m2) or ($m4 and any of ($m5, $m6, $m7))
}

rule DNS_Tunneling_Indicators
{
    meta:
        description = "Detects DNS tunneling tool indicators"
        author = "Seraph AI"
        severity = "high"
        technique = "T1071.004"
    strings:
        $d1 = "dnscat" nocase
        $d2 = "dns2tcp" nocase
        $d3 = "iodine" nocase
        $d4 = "dnscrypt" nocase
        $d5 = "dns-shell" nocase
    condition:
        any of them
}

rule Suspicious_TOR_Client
{
    meta:
        description = "Detects TOR client configuration indicators"
        author = "Seraph AI"
        severity = "medium"
        technique = "T1090.003"
    strings:
        $t1 = "SocksPort" nocase
        $t2 = "HiddenServiceDir" nocase
        $t3 = ".onion" nocase
        $t4 = "ExitPolicy reject *:*" nocase
        $t5 = "ControlPort" nocase
    condition:
        2 of them
}

rule Empire_PowerShell_Agent
{
    meta:
        description = "Detects Empire PowerShell agent patterns"
        author = "Seraph AI"
        severity = "critical"
        technique = "T1059.001"
    strings:
        $e1 = "empire" nocase
        $e2 = "Get-JobState" nocase
        $e3 = "Invoke-Empire" nocase
        $e4 = "System.Net.WebClient" nocase
        $e5 = "HKCU:Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
    condition:
        $e1 or ($e4 and any of ($e2, $e3, $e5))
}
