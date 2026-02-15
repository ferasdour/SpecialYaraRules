rule IL_Trojan.MSILZilla_family
{
    meta:
        description = "Auto-generated YARA rule for IL_Trojan.MSILZilla"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "6461d2ad0b8db4ed71681326b7c6f1aa23b783d4b2736decb3ec3a9bf4eae460"
        first_seen = "2026-02-15T01:32:18+00:00"
        threat_score = "100"
        mitre_techniques = "Native API, Component Object Model, Windows Management Instrumentation, Scheduled Task, Shared Modules"
        target_url = "none"

    strings:
        $d0 = "larenxzose-39663.portmap.host"
        $h0 = "193.161.193.99"
        $fn0 = "xdwdAvast Antivirus Upgrade.exe"
        $fn1 = "xdwdAvast Antivirus Upgrade.exe.bin"

    condition:
        3 of them
}
