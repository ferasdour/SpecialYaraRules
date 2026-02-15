rule Trojan.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Trojan.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "3"
        first_sha256 = "3377608db7b40c70b91214a2523bf548fd07938507cae85813f4524bcedd0790"
        first_seen = "2026-02-15T01:05:50+00:00"
        threat_score = "100"

    strings:
        $h0 = "106.52.51.128"
        $h1 = "172.67.190.135"
        $h2 = "104.21.19.248"
        $fn0 = "conhost.exe"
        $fn1 = "3377608db7b40c70b91214a2523bf548fd07938507cae85813f4524bcedd0790.bin.exe"
        $fn2 = "rhproxy64.sys"
        $fn3 = "620542472f3f77da7b60e6d33cc4c6c2c7af90e1cddfb392e2149c07a521de01.bin.exe"
        $fn4 = "acpipagr64.sys"
        $fn5 = "SystemSettings.exe"
        $fn6 = "powershell.exe.log"
        $fn7 = "StartupProfileData-Interactive"

    condition:
        8 of them
}
