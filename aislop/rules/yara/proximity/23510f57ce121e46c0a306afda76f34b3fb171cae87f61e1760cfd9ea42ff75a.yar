rule proximity_23510f57
{
    meta:
        sha256 = "23510f57ce121e46c0a306afda76f34b3fb171cae87f61e1760cfd9ea42ff75a"
        family = "proximity"
        threat_score = "80"
        first_seen = "2026-02-12T00:53:45+00:00"
        sample_url = "https://www.hybrid-analysis.com/sample/23510f57ce121e46c0a306afda76f34b3fb171cae87f61e1760cfd9ea42ff75a"
        description = "Auto-generated YARA rule (file-based)"
        author = "Feemco pipeline"
        source = "Hybrid Analysis"

    strings:
        $s0 = { 3a 5c 73 73 7c 35 }
        $s1 = { 5b 3a 7a 5f 4b 5c }
        $s2 = { 5c 56 34 6b 72 }
        $s3 = { 46 3d 7c 5c 59 }
        $s4 = { 4f 72 69 67 69 6e 3a 20 68 74 74 70 73 3a 2f 2f 77 77 77 2e 72 65 61 64 61 62 69 6c 69 74 2e 63 6f 6d }
        $s5 = { 70 57 38 5c 25 }
        $s6 = { 7e 72 59 5c 69 4d 28 }

    condition:
        5 of ($*)
}
