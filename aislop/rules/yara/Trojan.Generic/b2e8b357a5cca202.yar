rule Trojan.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Trojan.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "b2e8b357a5cca202397371039a7e73fcb05ac61648a46426021a12cd4e30c572"
        first_seen = "2026-02-15T01:33:08+00:00"
        threat_score = "100"
        mitre_techniques = "Native API, Windows Command Shell, Windows Management Instrumentation, Component Object Model, Service Execution"
        target_url = "none"

    strings:
        $d0 = "de5b.northstar.api.socdn.com"
        $fn0 = "s54.exe.log"
        $fn1 = "s54.exe"

    condition:
        2 of them
}
