rule proximity_efc7d9c8
{
    meta:
        sha256 = "efc7d9c8980a6d99806676e3eb24ab0906d05cc674928c4d2648837c7170a4bc"
        family = "proximity"
        threat_score = "75"
        first_seen = "2026-02-12T02:53:16+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/efc7d9c8980a6d99806676e3eb24ab0906d05cc674928c4d2648837c7170a4bc"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 63 6f 6e 63 72 65 74 65 2e 63 6f 2e 6a 70 2f 69 6e 64 65 78 2e 70 68 70 }

    condition:
        1 of ($*)
}
