rule Lazy.Generic_family
{
    meta:
        description = "Auto-generated YARA rule for Lazy.Generic"
        author = "aislop v6"
        source = "Hybrid Analysis"
        sample_count = "1"
        first_sha256 = "39b76c1fab5e60ba3e18759dce03a1f44167e1e0d9121a8647d18d1b967c43bb"
        first_seen = "2026-02-15T01:31:17+00:00"
        threat_score = "100"
        mitre_techniques = "Phishing, Native API, Shared Modules, Modify Registry, Kernel Modules and Extensions"
        target_url = "none"

    strings:
        $d0 = "pee-files.nl"
        $h0 = "104.21.84.179"

    condition:
        any of them
}
