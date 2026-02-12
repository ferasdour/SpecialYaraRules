rule proximity_665fac4b
{
    meta:
        sha256 = "665fac4bd7bea7412f009e6e2f31466404451e1ab4048dff5e4964a2dc5047ad"
        family = "proximity"
        threat_score = "80"
        first_seen = "2026-02-12T01:49:16+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/665fac4bd7bea7412f009e6e2f31466404451e1ab4048dff5e4964a2dc5047ad"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 6d 6f 6e 65 7a 6f 6e 2e 63 6f 6d 2f }

    condition:
        1 of ($*)
}
