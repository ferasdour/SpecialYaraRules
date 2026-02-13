rule proximity_cb933e53
{
    meta:
        sha256 = "cb933e536853cd6dd9c1cb08aca45baeb9913a832d94ccaf97c214ae3cbc9e97"
        family = "proximity"
        threat_score = "85"
        first_seen = "2026-02-12T02:48:38+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/cb933e536853cd6dd9c1cb08aca45baeb9913a832d94ccaf97c214ae3cbc9e97"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 2a 5c 43 53 72 2d 41 64 5d 69 }
        $s1 = { 34 7b 5c 52 41 74 54 }
        $s2 = { 36 5c 3e 51 74 }
        $s3 = { 3f 36 60 3f 7b 5c 2e }
        $s4 = { 5c 65 38 52 5b }
        $s5 = { 5c 7c 2f 4f 36 }
        $s6 = { 5d 2a 21 5c 2c 3e }
        $s7 = { 44 5c 62 57 4b 6c 7b }
        $s8 = { 44 5c 7c 40 6f 4d 74 }
        $s9 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 61 64 64 69 64 61 73 2e 63 61 2f }
        $s10 = { 4f 72 69 67 69 6e 3a 20 68 74 74 70 73 3a 2f 2f 73 74 72 69 70 63 68 61 74 2e 63 6f 6d }
        $s11 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 3a 2f 2f 66 69 6c 74 65 72 2e 6c 65 6f 79 61 72 64 2e 63 6f 6d 2f 66 69 6c 74 65 72 3f 71 3d 26 69 3d 67 54 63 38 74 53 63 6b 41 49 34 5f 30 26 63 69 3d 2d 34 30 38 32 33 38 35 31 30 30 39 36 38 37 36 33 32 37 32 26 74 3d 31 35 34 39 34 33 34 37 36 35 26 68 3d 31 32 }
        $s12 = { 52 65 66 65 72 65 72 3a 20 68 74 74 70 73 3a 2f 2f 73 74 72 69 70 63 68 61 74 2e 63 6f 6d 2f }
        $s13 = { 6a 20 50 72 5c }
        $s14 = { 6c 5c 40 5a 23 5a }
        $s15 = { 6c 79 5c 39 21 }
        $s16 = { 51 45 7b 5c 66 }
        $s17 = { 71 56 3a 38 5c 49 }
        $s18 = { 51 7d 5c 27 62 38 39 }

    condition:
        15 of ($*)
}
