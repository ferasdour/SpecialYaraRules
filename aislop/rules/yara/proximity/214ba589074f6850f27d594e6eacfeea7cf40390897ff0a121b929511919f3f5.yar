rule proximity_214ba589
{
    meta:
        sha256 = "214ba589074f6850f27d594e6eacfeea7cf40390897ff0a121b929511919f3f5"
        family = "proximity"
        threat_score = "78"
        first_seen = "2026-02-12T00:32:35+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/214ba589074f6850f27d594e6eacfeea7cf40390897ff0a121b929511919f3f5"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 32 52 5c 29 7c }
        $s1 = { 5c 5d 7b 50 66 }

    condition:
        1 of ($*)
}
