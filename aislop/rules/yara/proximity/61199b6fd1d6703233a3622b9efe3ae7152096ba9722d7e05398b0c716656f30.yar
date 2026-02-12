rule proximity_61199b6f
{
    meta:
        sha256 = "61199b6fd1d6703233a3622b9efe3ae7152096ba9722d7e05398b0c716656f30"
        family = "proximity"
        threat_score = "75"
        first_seen = "2026-02-12T01:54:18+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/61199b6fd1d6703233a3622b9efe3ae7152096ba9722d7e05398b0c716656f30"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 2c 5c 66 67 51 72 30 }
        $s1 = { 67 5c 6c 61 65 55 }
        $s2 = { 4f 72 69 67 69 6e 3a 20 68 74 74 70 73 3a 2f 2f 65 6e 67 61 67 65 2e 77 69 78 61 70 70 73 2e 6e 65 74 }
        $s3 = { 6e 7c 5c 6e 47 21 }
        $s4 = { 73 59 5c 7d 68 6c 4c }
        $s5 = { 59 5c 2e 3e 67 2d 6b }

    condition:
        4 of ($*)
}
