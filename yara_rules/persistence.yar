/*
   YARA Rules - Persistence Mechanism Detection
   Seraph AI Security Platform
*/

rule Linux_Cron_Persistence
{
    meta:
        description = "Detects suspicious cron job entries used for persistence"
        author = "Seraph AI"
        severity = "high"
        technique = "T1053.003"
    strings:
        $c1 = "* * * * *" nocase
        $c2 = "curl " nocase
        $c3 = "wget " nocase
        $c4 = "/tmp/" nocase
        $c5 = "bash -c" nocase
        $c6 = "/dev/shm" nocase
    condition:
        $c1 and ($c4 or $c6) and ($c2 or $c3 or $c5)
}

rule Systemd_Service_Persistence
{
    meta:
        description = "Detects suspicious systemd service files used for persistence"
        author = "Seraph AI"
        severity = "high"
        technique = "T1543.002"
    strings:
        $s1 = "[Service]"
        $s2 = "ExecStart="
        $s3 = "/tmp/" nocase
        $s4 = "/dev/shm" nocase
        $s5 = "bash -i" nocase
        $s6 = "python3 -c" nocase
        $s7 = "perl -e" nocase
    condition:
        $s1 and $s2 and any of ($s3, $s4, $s5, $s6, $s7)
}

rule SSH_Authorized_Keys_Injection
{
    meta:
        description = "Detects SSH key injection pattern in scripts"
        author = "Seraph AI"
        severity = "high"
        technique = "T1098.004"
    strings:
        $a1 = "authorized_keys" nocase
        $a2 = "ssh-rsa " nocase
        $a3 = "ssh-ed25519 " nocase
        $a4 = "echo " nocase
        $a5 = ">>" nocase
    condition:
        $a1 and ($a2 or $a3) and ($a4 or $a5)
}

rule LD_PRELOAD_Hijacking
{
    meta:
        description = "Detects LD_PRELOAD hijacking for persistence"
        author = "Seraph AI"
        severity = "high"
        technique = "T1574.006"
    strings:
        $l1 = "LD_PRELOAD" nocase
        $l2 = "ld.so.preload" nocase
        $l3 = "/etc/ld.so.preload" nocase
    condition:
        any of them
}

rule SUID_SGID_Abuse
{
    meta:
        description = "Detects SUID/SGID bit manipulation for privilege escalation"
        author = "Seraph AI"
        severity = "high"
        technique = "T1548.001"
    strings:
        $s1 = "chmod +s" nocase
        $s2 = "chmod 4755" nocase
        $s3 = "chmod 6755" nocase
        $s4 = "find.*-perm.*-4000" nocase
        $s5 = "find.*-perm.*-2000" nocase
    condition:
        any of them
}

rule Kernel_Module_Loading
{
    meta:
        description = "Detects suspicious kernel module loading"
        author = "Seraph AI"
        severity = "critical"
        technique = "T1547.006"
    strings:
        $k1 = "insmod " nocase
        $k2 = "modprobe " nocase
        $k3 = "init_module" nocase
        $k4 = "/lib/modules" nocase
        $k5 = ".ko" nocase
    condition:
        any of ($k1, $k2, $k3) and ($k4 or $k5)
}
