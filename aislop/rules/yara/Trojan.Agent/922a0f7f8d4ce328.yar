rule Trojan.Agent_family
{
    meta:
        description = "Auto-generated YARA rule for Trojan.Agent"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "3"
        first_sha256 = "922a0f7f8d4ce328408bcb135d98a9ea33eb1a05bdfbb1fd4df89ff935899301"
        first_seen = "2026-02-15T01:01:46+00:00"
        threat_score = "100"

    strings:
        $d0 = "batyatj6.beget.tech"
        $fn0 = "RCX3262.tmp"
        $fn1 = "RCX332E.tmp"
        $fn2 = "SystemSettings.exe"
        $fn3 = "RCX30BA.tmp"
        $fn4 = "RCX3119.tmp"
        $fn5 = "RCX3767.tmp"
        $fn6 = "RCX3C3B.tmp"
        $fn7 = "msdtc.exe"

    condition:
        7 of them
}
